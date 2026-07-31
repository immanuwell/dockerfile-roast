use std::io::Write;
use std::process::{Command, Stdio};

use dockerfile_roast::rules::all_rules;
use dockerfile_roast::repository;

fn repository_fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/repository-awareness")
}

fn run_sarif(args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args(args)
        .output()
        .expect("droast should run");

    assert!(
        output.status.success(),
        "droast failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("output should be valid SARIF")
}

fn policy_fixture(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("droast-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn fail_on_controls_the_exit_status_from_cli_and_config() {
    let root = policy_fixture("fail-on");
    let dockerfile = root.join("Dockerfile");
    let config = root.join("droast.toml");
    std::fs::write(&dockerfile, "FROM alpine:latest\n").unwrap();
    std::fs::write(&config, "fail-on = \"warning\"\n").unwrap();

    let config_failure = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--only",
            "DF001",
            "--no-roast",
            "--check-dockerignore=false",
            dockerfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        config_failure.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&config_failure.stdout)
    );

    let cli_failure = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            "--fail-on",
            "info",
            "--only",
            "DF001",
            "--no-roast",
            "--check-dockerignore=false",
            dockerfile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(cli_failure.status.code(), Some(1));
}

#[test]
fn root_long_help_starts_with_the_banner_but_subcommand_help_does_not() {
    let root_help = Command::new(env!("CARGO_BIN_EXE_droast"))
        .arg("--help")
        .output()
        .expect("droast --help should run");
    assert!(root_help.status.success());
    let root_help = String::from_utf8_lossy(&root_help.stdout);
    assert!(root_help.starts_with("\x1b[1;31m\n\n"));
    let banner = root_help.find("██████╗ ██████╗").unwrap();
    let description = root_help
        .find("A Dockerfile linter that catches bad practices")
        .unwrap();
    assert!(banner < description);
    assert!(root_help.contains("Dockerfile linter with personality"));

    let subcommand_help = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args(["messages", "--help"])
        .output()
        .expect("droast messages --help should run");
    assert!(subcommand_help.status.success());
    assert!(!String::from_utf8_lossy(&subcommand_help.stdout).contains("██████╗ ██████╗"));
}

#[test]
fn message_overrides_are_layered_for_terminal_output_and_not_json() {
    let root = policy_fixture("message-overrides");
    let user_config = root.join("user-config");
    let project_messages = root.join(".droast/messages.yaml");
    let explicit_messages = root.join("team.yaml");
    let dockerfile = root.join("Dockerfile");
    std::fs::create_dir_all(project_messages.parent().unwrap()).unwrap();
    std::fs::create_dir_all(user_config.join("droast")).unwrap();
    std::fs::write(&dockerfile, "FROM alpine:3.20\nUSER root\n").unwrap();
    std::fs::write(
        user_config.join("droast/messages.yaml"),
        "version: 1\nrules:\n  DF002:\n    message: user message\n",
    )
    .unwrap();
    std::fs::write(
        &project_messages,
        "version: 1\nrules:\n  DF002:\n    message: project message\n",
    )
    .unwrap();
    std::fs::write(
        &explicit_messages,
        "version: 1\nrules:\n  DF002:\n    message: explicit {rule} at {file}:{line}\n",
    )
    .unwrap();

    let terminal = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(&root)
        .env("XDG_CONFIG_HOME", &user_config)
        .args([
            dockerfile.to_str().unwrap(),
            "--messages",
            explicit_messages.to_str().unwrap(),
            "--only",
            "DF002",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(terminal.status.success(), "{}", String::from_utf8_lossy(&terminal.stderr));
    let terminal = String::from_utf8_lossy(&terminal.stdout);
    assert!(terminal.contains("explicit DF002 at"));
    assert!(!terminal.contains("project message"));
    assert!(!terminal.contains("user message"));
    assert!(!terminal.contains("██████╗ ██████╗"));

    let json = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(&root)
        .env("XDG_CONFIG_HOME", &user_config)
        .args([
            dockerfile.to_str().unwrap(),
            "--messages",
            explicit_messages.to_str().unwrap(),
            "--only",
            "DF002",
            "--format",
            "json",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(json.status.success(), "{}", String::from_utf8_lossy(&json.stderr));
    assert!(!String::from_utf8_lossy(&json.stdout).contains("explicit DF002"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn messages_commands_create_validate_dump_and_complete() {
    let root = policy_fixture("messages-commands");
    let init = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(&root)
        .args(["messages", "init", "--project", "--preset", "friendly"])
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", String::from_utf8_lossy(&init.stderr));
    let path = root.join(".droast/messages.yaml");
    assert!(path.exists());

    let validate = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args(["messages", "validate", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(validate.status.success(), "{}", String::from_utf8_lossy(&validate.stderr));

    let dump = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args(["messages", "dump", "--all"])
        .output()
        .unwrap();
    assert!(dump.status.success(), "{}", String::from_utf8_lossy(&dump.stderr));
    assert!(String::from_utf8_lossy(&dump.stdout).contains("DF013"));

    let completion = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(completion.status.success());
    let completion = String::from_utf8_lossy(&completion.stdout);
    assert!(completion.contains("messages"));
    assert!(completion.contains("validate"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn stdin_lint_uses_the_process_working_directory_for_the_ignorefile() {
    let root = policy_fixture("stdin-ignorefile");
    std::fs::write(root.join(".dockerignore"), ".git\n").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(&root)
        .args(["--only", "DF033", "--format", "json", "--no-fail", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("droast should run");
    child
        .stdin
        .take()
        .expect("stdin should be available")
        .write_all(b"FROM alpine:3.20\n")
        .unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["findings"].as_array().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

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
        assert_eq!(
            actual["categories"],
            serde_json::json!(expected.categories())
        );
    }
}

#[test]
fn cli_applies_severity_overrides_from_config() {
    let root = policy_fixture("severity");
    let dockerfile = root.join("Dockerfile");
    let config = root.join("droast.toml");
    std::fs::write(&dockerfile, "FROM alpine:3.20\nUSER root\n").unwrap();
    std::fs::write(
        &config,
        "[severity-overrides]\nDF002 = \"info\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
            "--only",
            "DF002",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["findings"][0]["severity"], "INFO");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn baseline_fingerprints_are_emitted_and_suppress_existing_errors() {
    let root = policy_fixture("baseline");
    let dockerfile = root.join("Dockerfile");
    let baseline = root.join("droast-baseline.json");
    std::fs::write(&dockerfile, "FROM alpine:3.20\nUSER root\n").unwrap();

    let write = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only", "DF002",
            "--baseline", baseline.to_str().unwrap(),
            "--write-baseline",
            "--format", "json",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(write.status.success(), "{}", String::from_utf8_lossy(&write.stderr));
    let json: serde_json::Value = serde_json::from_slice(&write.stdout).unwrap();
    assert!(json["findings"][0]["fingerprint"].as_str().unwrap().starts_with("sha256:"));

    let check = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only", "DF002",
            "--baseline", baseline.to_str().unwrap(),
            "--format", "sarif",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
    let sarif: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert!(sarif["runs"][0]["results"][0]["partialFingerprints"]["droast/v1"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let terminal_only_new = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only", "DF002",
            "--baseline", baseline.to_str().unwrap(),
            "--only-new",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(terminal_only_new.status.success(), "{}", String::from_utf8_lossy(&terminal_only_new.stderr));
    assert!(String::from_utf8_lossy(&terminal_only_new.stdout).contains("no new findings since the baseline"));

    std::fs::write(
        &dockerfile,
        "FROM alpine:3.20\nUSER root\nRUN chmod 777 /tmp/cache\n",
    )
    .unwrap();
    let only_new = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only",
            "DF002,DF034",
            "--baseline",
            baseline.to_str().unwrap(),
            "--only-new",
            "--format",
            "json",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(
        only_new.status.success(),
        "{}",
        String::from_utf8_lossy(&only_new.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&only_new.stdout).unwrap();
    assert_eq!(json["total"], 1);
    assert_eq!(json["findings"][0]["rule"], "DF034");

    let only_new_sarif = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only", "DF002,DF034",
            "--baseline", baseline.to_str().unwrap(),
            "--only-new",
            "--format", "sarif",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(only_new_sarif.status.success(), "{}", String::from_utf8_lossy(&only_new_sarif.stderr));
    let sarif: serde_json::Value = serde_json::from_slice(&only_new_sarif.stdout).unwrap();
    assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
    assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "DF034");

    let only_new_fails_for_new_errors = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only",
            "DF002,DF034",
            "--baseline",
            baseline.to_str().unwrap(),
            "--only-new",
            "--format",
            "compact",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(!only_new_fails_for_new_errors.status.success());
    let compact = String::from_utf8_lossy(&only_new_fails_for_new_errors.stdout);
    assert!(compact.contains("[DF034]"));
    assert!(!compact.contains("[DF002]"));

    let missing_baseline = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([dockerfile.to_str().unwrap(), "--only-new"])
        .output()
        .unwrap();
    assert!(!missing_baseline.status.success());
    assert!(String::from_utf8_lossy(&missing_baseline.stderr).contains("--baseline"));

    let write_and_filter = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--baseline", baseline.to_str().unwrap(),
            "--write-baseline",
            "--only-new",
        ])
        .output()
        .unwrap();
    assert!(!write_and_filter.status.success());
    assert!(String::from_utf8_lossy(&write_and_filter.stderr).contains("cannot be used with"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn copy_ignored_file_uses_the_effective_build_context_ignore_file() {
    let root = policy_fixture("copy-ignored");
    let dockerfile = root.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\nCOPY secret.txt /app/\n").unwrap();
    std::fs::write(root.join(".dockerignore"), "secret.txt\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only", "DF077",
            "--format", "json",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["findings"][0]["rule"], "DF077");
    assert_eq!(result["findings"][0]["line"], 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn copy_from_stage_is_not_checked_against_the_build_context_ignore_file() {
    let root = policy_fixture("copy-from-stage");
    let dockerfile = root.join("Dockerfile");
    std::fs::write(
        &dockerfile,
        "FROM alpine:3.20 AS source\nRUN touch /tool\nFROM scratch\nCOPY --from=source /tool /tool\n",
    )
    .unwrap();
    std::fs::write(root.join(".dockerignore"), "**/*\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only", "DF077",
            "--format", "json",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["findings"].as_array().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn copy_all_acknowledges_common_effective_ignore_patterns() {
    let root = policy_fixture("copy-all-ignore");
    let dockerfile = root.join("Dockerfile");
    std::fs::write(&dockerfile, "FROM alpine:3.20\nCOPY . .\n").unwrap();
    std::fs::write(root.join(".dockerignore"), ".git\nnode_modules\n.env\ndist\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--only", "DF007",
            "--format", "json",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["findings"][0]["rule"], "DF007");
    assert!(result["findings"][0]["message"].as_str().unwrap().contains("protected build context"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_applies_path_specific_configuration() {
    let root = policy_fixture("path-override");
    let service = root.join("services/api");
    std::fs::create_dir_all(&service).unwrap();
    let dockerfile = service.join("Dockerfile");
    let config = root.join("droast.toml");
    std::fs::write(&dockerfile, "FROM alpine:latest\n").unwrap();
    std::fs::write(
        &config,
        r#"
[[overrides]]
paths = ["services/**/Dockerfile"]
skip = ["DF001"]
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--format",
            "json",
            "--only",
            "DF001",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["total"], 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_rejects_invalid_team_policy_instead_of_ignoring_it() {
    let root = policy_fixture("invalid-policy");
    let dockerfile = root.join("Dockerfile");
    let config = root.join("droast.toml");
    std::fs::write(&dockerfile, "FROM alpine:3.20\n").unwrap();
    std::fs::write(&config, "skip = [\"DF999\"]\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown rule ID"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn init_generates_a_valid_complete_policy_template() {
    let root = policy_fixture("init");
    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(&root)
        .arg("init")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let config = std::fs::read_to_string(root.join("droast.toml")).unwrap();
    for setting in [
        "extends",
        "preset",
        "severity-overrides",
        "require-suppression-reason",
        "approved-registries",
        "approved-base-images",
        "required-labels",
        "overrides",
    ] {
        assert!(config.contains(setting), "template is missing {setting}");
    }
    dockerfile_roast::config::DroastConfig::load_from(&root.join("droast.toml")).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn init_imports_compatible_hadolint_configuration() {
    let root = policy_fixture("hadolint-import");
    std::fs::write(
        root.join(".hadolint.yaml"),
        "ignored: [DL3003, DL3025, SC2086]\ntrustedRegistries: [docker.io]\noverride:\n  error: [DL3002]\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(&root)
        .args(["init", "--from-hadolint"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = root.join("droast.toml");
    let content = std::fs::read_to_string(&config).unwrap();
    assert!(content.contains("skip = [\"DF008\", \"DF018\", \"DF025\"]"));
    assert!(content.contains("DF002 = \"error\""));
    assert!(String::from_utf8_lossy(&output.stderr).contains("SC2086"));
    dockerfile_roast::config::DroastConfig::load_from(&config).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_presets_select_their_rule_categories() {
    let root = policy_fixture("presets");
    let dockerfile = root.join("Dockerfile");
    std::fs::write(
        &dockerfile,
        "FROM alpine:3.20\nUSER root\nRUN echo 1\nRUN echo 2\nRUN echo 3\nRUN echo 4\n",
    )
    .unwrap();

    let run = |preset: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_droast"))
            .args([
                dockerfile.to_str().unwrap(),
                "--preset",
                preset,
                "--format",
                "json",
                "--no-fail",
                "--check-dockerignore=false",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    let security = run("security");
    let security_rules = security["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["rule"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(security_rules.contains(&"DF002"));
    assert!(!security_rules.contains(&"DF003"));

    let performance = run("performance");
    let performance_rules = performance["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["rule"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(performance_rules.contains(&"DF003"));
    assert!(!performance_rules.contains(&"DF002"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn directory_input_recursively_discovers_dockerfiles_compose_and_bake_targets() {
    let fixture = repository_fixture();
    let sarif = run_sarif(&[
        fixture.to_str().unwrap(),
        "--format",
        "sarif",
        "--only",
        "DF071",
        "--no-fail",
        "--check-dockerignore=false",
    ]);
    let mut files = sarif["runs"][0]["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|artifact| artifact["location"]["uri"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    files.sort();

    assert_eq!(files.len(), 13);
    for suffix in [
        "Dockerfile",
        "Dockerfile.dev",
        "worker.Dockerfile",
        "Containerfile",
        "Containerfile.release",
        "nested/Dockerfile.test",
        "contexts/worker/Dockerfile",
        "docker/api.build",
        "docker/bake.build",
        "docker/json.build",
        "docker/specific.build",
        "docker/override.build",
        ".devcontainer/Dockerfile",
    ] {
        assert!(
            files.iter().any(|file| file.ends_with(suffix)),
            "missing {suffix}: {files:?}"
        );
    }
}

#[test]
fn directory_json_output_is_one_valid_document() {
    let fixture = repository_fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            fixture.to_str().unwrap(),
            "--format",
            "json",
            "--only",
            "DF071",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .expect("droast should run");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(document.as_array().unwrap().len(), 13);
}

#[test]
fn directory_discovery_skips_dockerfile_specific_ignore_files() {
    let root = policy_fixture("dockerfile-specific-ignore-discovery");
    std::fs::write(root.join("Dockerfile"), "FROM alpine:3.20\nCMD [\"true\"]\n").unwrap();
    std::fs::write(root.join("Dockerfile.dockerignore"), ".git\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            root.to_str().unwrap(),
            "--only",
            "DF071",
            "--format",
            "json",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(document["file"].as_str().unwrap().ends_with("Dockerfile"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn single_file_json_output_remains_an_object() {
    let dockerfile = repository_fixture().join("Dockerfile");
    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            dockerfile.to_str().unwrap(),
            "--format",
            "json",
            "--only",
            "DF071",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .expect("droast should run");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert!(document.is_object());
    assert!(document["file"].as_str().unwrap().ends_with("Dockerfile"));
}

#[test]
fn no_arguments_discovers_the_current_repository() {
    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .current_dir(repository_fixture())
        .args([
            "--format",
            "sarif",
            "--only",
            "DF071",
            "--no-fail",
            "--check-dockerignore=false",
        ])
        .output()
        .expect("droast should run");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert_eq!(sarif["runs"][0]["artifacts"].as_array().unwrap().len(), 13);
}

#[test]
fn discovery_preserves_hidden_project_directories_and_ignores_excluded_trees() {
    let fixture = repository_fixture();
    let discovery = repository::discover(
        std::slice::from_ref(&fixture),
        repository::ContainerEngine::Docker,
    );

    assert!(discovery
        .inputs
        .iter()
        .any(|input| input.dockerfile.ends_with(".devcontainer/Dockerfile")));
    assert!(!discovery
        .inputs
        .iter()
        .any(|input| input.dockerfile.ends_with("ignored/Dockerfile")));
}

#[test]
fn declared_contexts_override_repository_context_inference() {
    let fixture = repository_fixture();
    let discovery = repository::discover(
        std::slice::from_ref(&fixture),
        repository::ContainerEngine::Docker,
    );
    let api = discovery
        .inputs
        .iter()
        .find(|input| input.dockerfile.ends_with("docker/api.build"))
        .unwrap();
    let nested = discovery
        .inputs
        .iter()
        .find(|input| input.dockerfile.ends_with("nested/Dockerfile.test"))
        .unwrap();

    assert_eq!(api.context, fixture.join("contexts/api").canonicalize().unwrap());
    assert_eq!(nested.context, fixture.canonicalize().unwrap());
}

#[test]
fn compose_and_bake_contexts_select_the_context_root_dockerignore() {
    let fixture = repository_fixture();
    let sarif = run_sarif(&[
        fixture.to_str().unwrap(),
        "--format",
        "sarif",
        "--only",
        "DF033",
        "--no-fail",
    ]);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    for suffix in ["docker/api.build", "docker/bake.build", "docker/json.build"] {
        assert!(
            !results.iter().any(|result| result["locations"][0]
                ["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .ends_with(suffix)),
            "{suffix} should use its build context's .dockerignore"
        );
    }
}

#[test]
fn dockerfile_specific_empty_ignore_overrides_context_ignore() {
    let fixture = repository_fixture();
    let sarif = run_sarif(&[
        fixture.to_str().unwrap(),
        "--format",
        "sarif",
        "--only",
        "DF033",
        "--no-fail",
    ]);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert!(results.iter().any(|result| {
        result["ruleId"] == "DF033"
            && result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .ends_with("docker/specific.build")
            && result["message"]["text"]
                .as_str()
                .unwrap()
                .contains("no exclusion patterns")
    }));
}

#[test]
fn missing_context_root_ignore_is_reported() {
    let fixture = repository_fixture();
    let sarif = run_sarif(&[
        fixture.to_str().unwrap(),
        "--format",
        "sarif",
        "--only",
        "DF033",
        "--no-fail",
    ]);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert!(results.iter().any(|result| {
        result["ruleId"] == "DF033"
            && result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .ends_with("repository-awareness/Dockerfile")
            && result["message"]["text"]
                .as_str()
                .unwrap()
                .contains("No effective build-context ignore file")
    }));
}

#[test]
fn podman_prefers_containerignore_over_dockerignore() {
    let root = std::env::temp_dir().join(format!("droast-podman-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("Containerfile"), "FROM alpine:3.20\n").unwrap();
    std::fs::write(root.join(".dockerignore"), "target\n").unwrap();
    std::fs::write(root.join(".containerignore"), "# comments do not exclude files\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            root.to_str().unwrap(),
            "--engine",
            "podman",
            "--format",
            "json",
            "--only",
            "DF033",
            "--no-fail",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["findings"][0]["rule"], "DF033");
    assert!(document["findings"][0]["message"]
        .as_str()
        .unwrap()
        .contains(".containerignore"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn podman_discovers_quadlet_and_kube_local_builds() {
    let root = std::env::temp_dir().join(format!("droast-quadlet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("quadlet-context")).unwrap();
    std::fs::create_dir_all(root.join("kube-app")).unwrap();
    std::fs::write(root.join("quadlet-context/Containerfile"), "FROM alpine:3.20\n").unwrap();
    std::fs::write(root.join("kube-app/Containerfile"), "FROM alpine:3.20\n").unwrap();
    std::fs::write(
        root.join("app.build"),
        "[Build]\nFile=quadlet-context/Containerfile\nSetWorkingDirectory=unit\n",
    )
    .unwrap();
    std::fs::write(
        root.join("pod.kube"),
        "[Kube]\nYaml=pod.yaml\n",
    )
    .unwrap();
    std::fs::write(
        root.join("pod.yaml"),
        "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      image: kube-app\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            root.to_str().unwrap(),
            "--engine",
            "podman",
            "--format",
            "sarif",
            "--only",
            "DF071",
            "--no-fail",
            "--check-ignorefile=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let artifacts = document["runs"][0]["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts.iter().any(|artifact| artifact["location"]["uri"]
        .as_str()
        .unwrap()
        .ends_with("quadlet-context/Containerfile")));
    assert!(artifacts.iter().any(|artifact| artifact["location"]["uri"]
        .as_str()
        .unwrap()
        .ends_with("kube-app/Containerfile")));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn podman_reports_cpp_preprocessed_containerfiles() {
    let root = std::env::temp_dir().join(format!("droast-containerfile-in-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("Containerfile.in");
    std::fs::write(&file, "#define BASE alpine:3.20\nFROM BASE\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_droast"))
        .args([
            file.to_str().unwrap(),
            "--engine",
            "podman",
            "--format",
            "json",
            "--only",
            "DF075",
            "--no-fail",
            "--check-ignorefile=false",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["findings"][0]["rule"], "DF075");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn dockerfile_specific_ignore_works_without_a_context_root_ignore() {
    let fixture = repository_fixture();
    let sarif = run_sarif(&[
        fixture.to_str().unwrap(),
        "--format",
        "sarif",
        "--only",
        "DF033",
        "--no-fail",
    ]);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert!(!results.iter().any(|result| {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .ends_with("docker/override.build")
    }));
}
