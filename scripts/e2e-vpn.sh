#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
bin="${OPENTUN_BIN:-$repo_root/target/release/opentun}"
host_ip="${OPENTUN_E2E_HOST_IP:-192.168.248.1}"
peer_a_ip="${OPENTUN_E2E_PEER_A_IP:-192.168.248.2}"
peer_b_ip="${OPENTUN_E2E_PEER_B_IP:-192.168.248.3}"
relay_port="${OPENTUN_E2E_RELAY_PORT:-19443}"
coord_port="${OPENTUN_E2E_COORD_PORT:-18443}"
tun_name="${OPENTUN_E2E_TUN:-tun0}"
direct_mode="${OPENTUN_E2E_DIRECT:-0}"
tunnel_a="10.88.0.1"
tunnel_b="10.88.0.2"
underlay_cidr="${OPENTUN_E2E_UNDERLAY_CIDR:-24}"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This E2E test requires Linux network namespaces." >&2
    exit 1
fi

for command in cargo ip ping sudo timeout; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Missing required command: $command" >&2
        exit 1
    fi
done

if [[ "${OPENTUN_E2E_BUILT:-0}" != "1" ]]; then
    cargo build --release --manifest-path "$repo_root/Cargo.toml"
fi

if [[ $EUID -ne 0 ]]; then
    exec sudo \
        OPENTUN_E2E_BUILT=1 \
        OPENTUN_BIN="$bin" \
        OPENTUN_E2E_HOST_IP="$host_ip" \
        OPENTUN_E2E_PEER_A_IP="$peer_a_ip" \
        OPENTUN_E2E_PEER_B_IP="$peer_b_ip" \
        OPENTUN_E2E_RELAY_PORT="$relay_port" \
        OPENTUN_E2E_COORD_PORT="$coord_port" \
        OPENTUN_E2E_TUN="$tun_name" \
        OPENTUN_E2E_DIRECT="$direct_mode" \
        OPENTUN_E2E_UNDERLAY_CIDR="$underlay_cidr" \
        OPENTUN_E2E_KEEP_LOGS="${OPENTUN_E2E_KEEP_LOGS:-0}" \
        "$0" "$@"
fi

if [[ ! -x "$bin" ]]; then
    echo "Binary not found or not executable: $bin" >&2
    exit 1
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/opentun-e2e.XXXXXX")"
suffix="$(printf "%04x" "$$" | tail -c 5)"
ns_a="otun-a-$suffix"
ns_b="otun-b-$suffix"
bridge="otbr$suffix"
veth_a_host="otah$suffix"
veth_a_ns="otan$suffix"
veth_b_host="otbh$suffix"
veth_b_ns="otbn$suffix"
server_pid=""
peer_a_pid=""
peer_b_pid=""

print_logs() {
    for log in "$workdir"/server.log "$workdir"/peer-a.log "$workdir"/peer-b.log; do
        if [[ -s "$log" ]]; then
            echo
            echo "==> $log" >&2
            tail -n 80 "$log" >&2 || true
        fi
    done
}

cleanup() {
    local status=$?
    set +e

    for pid in "$peer_a_pid" "$peer_b_pid" "$server_pid"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            wait "$pid" 2>/dev/null
        fi
    done

    ip netns del "$ns_a" 2>/dev/null
    ip netns del "$ns_b" 2>/dev/null
    ip link del "$bridge" 2>/dev/null

    if [[ $status -ne 0 ]]; then
        print_logs
        echo
        echo "E2E test failed; logs kept in $workdir" >&2
    elif [[ "${OPENTUN_E2E_KEEP_LOGS:-0}" == "1" ]]; then
        echo "E2E test passed; logs kept in $workdir"
    else
        rm -rf "$workdir"
    fi

    exit "$status"
}
trap cleanup EXIT INT TERM

wait_for_tcp() {
    local host=$1
    local port=$2

    for _ in $(seq 1 100); do
        if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done

    echo "Timed out waiting for $host:$port" >&2
    return 1
}

wait_for_tun() {
    local namespace=$1

    for _ in $(seq 1 100); do
        if ip -n "$namespace" link show "$tun_name" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done

    echo "Timed out waiting for $tun_name in $namespace" >&2
    return 1
}

make_pubkey() {
    local secret=$1
    printf '%s\n' "$secret" | "$bin" pubkey | tail -n 1
}

write_peer_config() {
    local path=$1
    local tunnel_ip=$2
    local listen_port=$3
    local secret=$4
    local pubkey=$5
    local remote_tunnel_ip=$6
    local remote_underlay_ip=$7
    local remote_pubkey=$8

    cat > "$path/config.yaml" <<YAML
name: $tun_name
address: $tunnel_ip
port: $listen_port
mtu: 1280
secret: $secret
pubkey: $pubkey
node_roles:
  - peer
stun_servers: []
coordination_url: ws://$host_ip:$coord_port
relay_urls:
  - ws://$host_ip:$relay_port
relay_listen_addr: null
coord_listen_addr: null
coord_auth_token: null
peers:
  $remote_tunnel_ip:
    sock_addr: $remote_underlay_ip:$listen_port
    pub_key: $remote_pubkey
YAML
}

mkdir -p "$workdir/server" "$workdir/peer-a" "$workdir/peer-b"

if [[ "$direct_mode" == "1" ]]; then
    peer_a_endpoint_ip="$peer_a_ip"
    peer_b_endpoint_ip="$peer_b_ip"
else
    # Keep static direct endpoints reachable enough for UDP send_to, but unroutable by peers.
    peer_a_endpoint_ip="192.168.248.253"
    peer_b_endpoint_ip="192.168.248.254"
fi

secret_a="$("$bin" genkey)"
secret_b="$("$bin" genkey)"
pubkey_a="$(make_pubkey "$secret_a")"
pubkey_b="$(make_pubkey "$secret_b")"

write_peer_config "$workdir/peer-a" "$tunnel_a" 1194 "$secret_a" "$pubkey_a" \
    "$tunnel_b" "$peer_b_endpoint_ip" "$pubkey_b"
write_peer_config "$workdir/peer-b" "$tunnel_b" 1194 "$secret_b" "$pubkey_b" \
    "$tunnel_a" "$peer_a_endpoint_ip" "$pubkey_a"

ip netns add "$ns_a"
ip netns add "$ns_b"
ip link set lo up
ip link add "$bridge" type bridge
ip addr add "$host_ip/$underlay_cidr" dev "$bridge"
ip link set "$bridge" up

ip link add "$veth_a_host" type veth peer name "$veth_a_ns"
ip link add "$veth_b_host" type veth peer name "$veth_b_ns"
ip link set "$veth_a_host" master "$bridge"
ip link set "$veth_b_host" master "$bridge"
ip link set "$veth_a_host" up
ip link set "$veth_b_host" up
ip link set "$veth_a_ns" netns "$ns_a"
ip link set "$veth_b_ns" netns "$ns_b"

ip -n "$ns_a" link set lo up
ip -n "$ns_b" link set lo up
ip -n "$ns_a" addr add "$peer_a_ip/$underlay_cidr" dev "$veth_a_ns"
ip -n "$ns_b" addr add "$peer_b_ip/$underlay_cidr" dev "$veth_b_ns"
ip -n "$ns_a" link set "$veth_a_ns" up
ip -n "$ns_b" link set "$veth_b_ns" up

(
    cd "$workdir/server"
    "$bin" --relay --coord \
        --relay-listen "$host_ip:$relay_port" \
        --coord-listen "$host_ip:$coord_port"
) > "$workdir/server.log" 2>&1 &
server_pid=$!
wait_for_tcp "$host_ip" "$relay_port"
wait_for_tcp "$host_ip" "$coord_port"

(
    cd "$workdir/peer-a"
    ip netns exec "$ns_a" "$bin" --peer
) > "$workdir/peer-a.log" 2>&1 &
peer_a_pid=$!

(
    cd "$workdir/peer-b"
    ip netns exec "$ns_b" "$bin" --peer
) > "$workdir/peer-b.log" 2>&1 &
peer_b_pid=$!

wait_for_tun "$ns_a"
wait_for_tun "$ns_b"
ip -n "$ns_a" route replace 10.88.0.0/24 dev "$tun_name"
ip -n "$ns_b" route replace 10.88.0.0/24 dev "$tun_name"

timeout 20 ip netns exec "$ns_a" ping -c 3 -W 2 "$tunnel_b"
timeout 20 ip netns exec "$ns_b" ping -c 3 -W 2 "$tunnel_a"

echo "E2E VPN test passed: $tunnel_a <-> $tunnel_b over $tun_name"
