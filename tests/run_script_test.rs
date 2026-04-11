#[test]
fn run_script_uses_current_release_binary() {
    let script = include_str!("../run.sh");
    let manifest = include_str!("../Cargo.toml");

    assert!(manifest.contains("name = \"opentun\""));
    assert!(
        script.contains("target/release/opentun"),
        "run.sh should launch the current package binary"
    );
    assert!(
        !script.contains("target/release/ipou"),
        "run.sh should not reference the old ipou binary name"
    );
}

#[test]
fn run_script_forwards_all_cli_arguments() {
    let script = include_str!("../run.sh");

    assert!(
        script.contains("\"$@\""),
        "run.sh should forward all arguments to opentun"
    );
}

#[test]
fn run_script_cleans_up_child_on_script_exit() {
    let script = include_str!("../run.sh");

    assert!(
        script.contains("trap cleanup EXIT"),
        "run.sh should clean up the opentun child if setup fails"
    );
}

#[test]
fn run_script_stops_if_opentun_exits_before_tun_is_ready() {
    let script = include_str!("../run.sh");

    assert!(
        script.contains("if ! kill -0 \"$pid\""),
        "run.sh should stop instead of adding a route after opentun exits early"
    );
}
