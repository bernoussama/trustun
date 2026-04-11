#!/usr/bin/env bash
set -euo pipefail

bin="${OPENTUN_BIN:-target/release/opentun}"
tun_name="${OPENTUN_TUN:-utun0}"
route_cidr="${OPENTUN_ROUTE:-10.0.0.0/8}"

cargo build --release
sudo setcap cap_net_admin=eip "$bin"

if ! command -v ip >/dev/null 2>&1; then
    echo "run.sh requires the ip command from iproute2 to add the tunnel route." >&2
    exit 1
fi

"$bin" "$@" &
pid=$!

cleanup() {
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        wait "$pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

for _ in {1..50}; do
    if ip link show "$tun_name" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        set +e
        wait "$pid"
        status=$?
        set -e
        exit "$status"
    fi
    sleep 0.1
done

if ! ip link show "$tun_name" >/dev/null 2>&1; then
    echo "TUN interface $tun_name did not appear before route setup." >&2
    exit 1
fi

sudo ip route replace "$route_cidr" dev "$tun_name"

wait "$pid"
