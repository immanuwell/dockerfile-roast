use std::process::Command;

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
