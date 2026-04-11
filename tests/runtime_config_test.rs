use opentun::cli::Cli;
use opentun::config::Config;

fn blank_cli() -> Cli {
    Cli {
        peer: false,
        relay: false,
        coord: false,
        relay_listen: None,
        coord_listen: None,
        relay_url: None,
        coord_url: None,
        name: None,
        address: None,
        port: None,
        command: None,
    }
}

#[test]
fn config_backfills_new_fields_for_legacy_yaml() {
    let yaml = r#"
name: utun0
address: 10.0.0.1
port: 1194
secret: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
pubkey: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
peers: {}
"#;

    let config: Config = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.mtu, 1280);
    assert_eq!(config.node_roles, vec!["peer"]);
    assert_eq!(config.stun_servers, vec!["stun.l.google.com:19302"]);
    assert!(config.relay_urls.is_empty());
    assert!(config.coordination_url.is_empty());
}

#[test]
fn cli_role_flags_override_config_roles() {
    let config = Config::default();
    let mut cli = blank_cli();
    cli.relay = true;
    cli.coord = true;

    let roles = config.resolve_roles(&cli).unwrap();

    assert!(!roles.peer);
    assert!(roles.relay);
    assert!(roles.coord);
}

#[test]
fn peer_role_validation_requires_coord_and_relay_endpoints() {
    let config = Config::default();
    let roles = config.resolve_roles(&blank_cli()).unwrap();

    let error = config.validate_runtime(roles).unwrap_err().to_string();

    assert!(error.contains("coordination_url") || error.contains("relay_urls"));
}

#[test]
fn peer_role_validation_requires_configured_peers() {
    let mut config = Config::default();
    config.coordination_url = "ws://127.0.0.1:8443".to_string();
    config.relay_urls = vec!["ws://127.0.0.1:9443".to_string()];
    let roles = config.resolve_roles(&blank_cli()).unwrap();

    let error = config.validate_runtime(roles).unwrap_err().to_string();

    assert!(error.contains("peers"));
}

#[test]
fn relay_and_coord_roles_require_listen_addresses() {
    let mut config = Config::default();
    config.node_roles = vec!["relay".to_string(), "coord".to_string()];

    let roles = config.resolve_roles(&blank_cli()).unwrap();
    let error = config.validate_runtime(roles).unwrap_err().to_string();

    assert!(error.contains("relay_listen_addr") || error.contains("coord_listen_addr"));
}
