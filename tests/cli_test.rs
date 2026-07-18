use std::process::Command;

use dockerfile_roast::rules::all_rules;

#[test]
fn list_rules_json_matches_registered_rules() {
    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args(["--list-rules", "--format", "json"])
        .output()
        .expect("droast should run");

    assert!(
        output.status.success(),
        "droast failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let listed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("rule metadata should be valid JSON");
    let listed = listed.as_array().expect("rule metadata should be an array");
    let registered = all_rules();

    assert_eq!(listed.len(), registered.len());
    for (actual, expected) in listed.iter().zip(registered) {
        assert_eq!(actual["id"], expected.id);
        assert_eq!(actual["severity"], expected.severity.to_string());
        assert_eq!(actual["description"], expected.description);
    }
}
