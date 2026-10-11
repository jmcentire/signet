//! Process-level MCP contract: no vault initialization and no stdout banner.
use std::io::Write;
use std::process::{Command, Stdio};

fn run(input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_signet"))
        .arg("preview-serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start preview");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn stdio_emits_only_responses_and_never_authority() {
    let output = run(concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"preview_rule_change\",\"arguments\":{\"operation\":\"remove\",\"rule_id\":\"amazon-limit\",\"expected_version\":\"v1\"}}}\n"
    ));
    assert!(output.status.success());
    let responses: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout must be JSON-RPC"))
        .collect();
    assert_eq!(
        responses.len(),
        3,
        "notifications must not produce responses"
    );
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 2);
    assert_eq!(
        responses[2]["result"]["structuredContent"]["authorizes_execution"],
        false
    );
}

#[test]
fn oversized_input_stops_without_processing() {
    let output = run(&"x".repeat(65537));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr).unwrap().contains("64 KiB"));
}
