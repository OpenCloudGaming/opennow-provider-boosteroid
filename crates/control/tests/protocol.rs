use opennow_plugin_api::PluginId;
use opennow_plugin_api::provider::*;
use std::io::{BufRead, BufReader, Write};
use std::num::NonZeroU64;
use std::process::{Command, Stdio};

fn request(id: &str, request: ProviderRequest) -> HostMessageV2 {
    HostMessageV2::Request(Box::new(HostRequestV2 {
        v: Version2,
        epoch: NonZeroU64::new(37).unwrap(),
        id: Text::new(id).unwrap(),
        timeout_ms: 5000,
        request,
    }))
}

#[test]
fn executable_uses_real_ndjson_and_does_not_claim_signed_in_or_playback() {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_boosteroid-control"))
        .env_clear()
        .env("OPENNOW_PLUGIN_DATA_DIR", directory.path().join("private"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let hello = ProviderRequest::Hello(ProviderHello {
        plugin_id: PluginId::new(boosteroid_common::PLUGIN_ID).unwrap(),
        version: Text::new(boosteroid_common::VERSION).unwrap(),
        capabilities: List::new(boosteroid_control::capabilities()).unwrap(),
    });
    for (id, operation) in [
        ("hello", hello),
        ("auth", ProviderRequest::AuthStatus(Empty {})),
        ("stop", ProviderRequest::Shutdown(Empty {})),
    ] {
        let request = request(id, operation);
        serde_json::to_writer(&mut input, &request).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let PluginMessageV2::Response(response) = serde_json::from_str(&line).unwrap();
        assert_eq!(response.id.as_str(), id);
        assert_eq!(response.epoch.get(), 37);
        if id == "auth" {
            assert!(
                matches!(response.outcome,ProviderOutcome::Success { reply } if matches!(*reply,ProviderReply::AuthStatus(AuthState::SignedOut)))
            );
        }
    }
    drop(input);
    assert!(child.wait().unwrap().success());
    let mut extra = String::new();
    assert_eq!(output.read_line(&mut extra).unwrap(), 0);
}
