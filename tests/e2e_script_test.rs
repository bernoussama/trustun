#[test]
fn e2e_vpn_script_exercises_tun_to_tun_ping() {
    let script = std::fs::read_to_string("scripts/e2e-vpn.sh")
        .expect("scripts/e2e-vpn.sh should exist");

    assert!(script.contains("ip netns add"));
    assert!(script.contains("config.yaml"));
    assert!(script.contains("ping -c"));
    assert!(script.contains("OPENTUN_E2E_DIRECT"));
    assert!(script.contains("10.88.0.2"));
    assert!(script.contains("10.88.0.1"));
}
