use std::collections::HashSet;

use dockerfile_roast::rules::all_rules;

#[test]
fn docker_build_check_matrix_is_complete_and_references_known_rules() {
    let matrix: serde_json::Value = serde_json::from_str(include_str!("../compatibility/docker-build-checks.json"))
        .expect("compatibility matrix must be valid JSON");
    assert_eq!(matrix["schema_version"], 1);
    let checks = matrix["checks"].as_array().expect("checks must be an array");
    assert_eq!(checks.len(), 21, "matrix must cover every Docker build check");

    let known_rules = all_rules()
        .into_iter()
        .map(|rule| rule.id)
        .collect::<HashSet<_>>();
    let mut names = HashSet::new();
    for check in checks {
        let name = check["docker_check"].as_str().expect("check name must be a string");
        assert!(names.insert(name), "duplicate Docker check {name}");
        assert!(matches!(
            check["status"].as_str(),
            Some("supported" | "partial" | "planned")
        ));
        for rule in check["droast_rules"].as_array().expect("rules must be an array") {
            let rule = rule.as_str().expect("rule ID must be a string");
            assert!(known_rules.contains(rule), "unknown Droast rule {rule}");
        }
    }
}
