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
    let discovery = repository::discover(std::slice::from_ref(&fixture));

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
    let discovery = repository::discover(std::slice::from_ref(&fixture));
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
                .contains("No effective .dockerignore")
    }));
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
