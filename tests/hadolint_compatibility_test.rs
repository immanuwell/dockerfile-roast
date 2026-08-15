use std::process::Command;

fn policy_fixture(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("droast-hadolint-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn hadolint_compatibility_discovers_yaml_and_preserves_equivalent_dl_ids() {
    let root = policy_fixture("hadolint-auto-config");
    std::fs::write(
        root.join("Dockerfile"),
        "FROM ubuntu:latest\nUSER root\nRUN cd /tmp && echo ok\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".hadolint.yaml"),
        "ignored: [DL3002]\noverride:\n  error: [DL3003]\nformat: json\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(&root)
        .env("HOME", &root)
        .env("XDG_CONFIG_HOME", root.join("xdg"))
        .args(["--hadolint-compatible", "--no-fail", "Dockerfile"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = findings.as_array().unwrap();
    assert!(findings.iter().any(|finding| finding["code"] == "DL3007"));
    assert!(findings
        .iter()
        .any(|finding| finding["code"] == "DL3003" && finding["level"] == "error"));
    assert!(!findings.iter().any(|finding| finding["code"] == "DL3002"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn hadolint_compatibility_honors_cli_env_thresholds_and_pragmas() {
    let root = policy_fixture("hadolint-precedence");
    let dockerfile = root.join("Dockerfile");
    let config = root.join("empty.yaml");
    std::fs::write(&config, "{}\n").unwrap();
    std::fs::write(
        &dockerfile,
        "# hadolint ignore=DL3007\nFROM ubuntu:latest\nUSER root\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .env("HADOLINT_IGNORE", "DL3007")
        .env("HADOLINT_OVERRIDE_ERROR", "DL3002")
        .args([
            "--hadolint-compatible",
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
            "--failure-threshold",
            "error",
            dockerfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(findings.as_array().unwrap().len(), 1);
    assert_eq!(findings[0]["code"], "DL3002");
    assert_eq!(findings[0]["level"], "error");

    let disabled = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            "--hadolint-compatible",
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
            "--disable-ignore-pragma",
            "--no-fail",
            dockerfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let findings: serde_json::Value = serde_json::from_slice(&disabled.stdout).unwrap();
    assert!(findings
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["code"] == "DL3007"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn hadolint_compatibility_emits_supported_machine_formats_and_mapping_warnings() {
    let root = policy_fixture("hadolint-formats");
    let dockerfile = root.join("Dockerfile");
    let config = root.join("hadolint.yaml");
    std::fs::write(&dockerfile, "FROM ubuntu:latest\n").unwrap();
    std::fs::write(&config, "ignored: [DL9999, DL3033]\n").unwrap();

    for (format, marker) in [
        ("checkstyle", "<checkstyle version=\"4.3\">"),
        ("codeclimate", "\"check_name\":\"DL3007\""),
        ("gitlab_codeclimate", "\"fingerprint\":"),
        ("junit", "<testsuites"),
        ("codacy", "\"patternId\":\"DL3007\""),
        ("sonarqube", "\"engineId\":\"Hadolint\""),
        ("sarif", "\"version\": \"2.1.0\""),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_droast"))
            .args([
                "--hadolint-compatible",
                "--config",
                config.to_str().unwrap(),
                "--format",
                format,
                "--no-fail",
                dockerfile.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(marker),
            "{format}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("unmatched Hadolint rule DL9999"));
        assert!(stderr.contains("behaviorally different"));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn hadolint_compatibility_reports_parse_errors_as_dl1000_and_scopes_report_paths() {
    let root = policy_fixture("hadolint-parse-error");
    let dockerfile = root.join("Dockerfile");
    let config = root.join("empty.yaml");
    std::fs::write(&dockerfile, "WAT nope\n").unwrap();
    std::fs::write(&config, "{}\n").unwrap();

    let json = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            "--hadolint-compatible",
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
            "--file-path-in-report",
            "reported/Dockerfile",
            "--no-fail",
            dockerfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let findings: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(findings.as_array().unwrap().len(), 1);
    assert_eq!(findings[0]["code"], "DL1000");
    assert_eq!(findings[0]["file"], dockerfile.to_str().unwrap());

    let checkstyle = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            "--hadolint-compatible",
            "--config",
            config.to_str().unwrap(),
            "--format",
            "checkstyle",
            "--file-path-in-report",
            "reported/Dockerfile",
            "--no-fail",
            dockerfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&checkstyle.stdout).contains("<file name=\"reported/Dockerfile\">")
    );
    std::fs::remove_dir_all(root).unwrap();
}
