//! Configurable organization policy checks and governed inline suppressions.

use glob::Pattern;
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use time::{Date, Duration, Month, OffsetDateTime};

use crate::linter::{rule_id_enabled, LintOptions};
use crate::parser::{parse_document, Instruction};
use crate::rules::{all_rules, Finding, Severity};

pub fn configured_findings(instructions: &[Instruction], opts: &LintOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    if opts.approved_registries.is_some() && rule_id_enabled(opts, "DF065") {
        findings.extend(registry_findings(instructions, opts));
    }
    if opts.approved_base_images.is_some() && rule_id_enabled(opts, "DF073") {
        findings.extend(base_image_findings(instructions, opts));
    }
    if (!opts.required_labels.is_empty() || opts.strict_labels) && rule_id_enabled(opts, "DF074") {
        findings.extend(label_findings(instructions, opts));
    }
    findings
}

fn registry_findings(instructions: &[Instruction], opts: &LintOptions) -> Vec<Finding> {
    let approved = opts.approved_registries.as_deref().unwrap_or_default();
    external_images(instructions)
        .into_iter()
        .filter_map(|(instruction, image)| {
            let registry = image_registry(image);
            (!matches_any(registry, approved)).then(|| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
                rule: "DF065".into(),
                severity: Severity::Warning,
                line: instruction.line,
                message: format!(
                    "FROM registry '{}' is not in approved-registries",
                    registry
                ),
                roast: format!(
                    "The registry '{}' is outside the approved supply chain. Add it only after review.",
                    registry
                ),
            })
        })
        .collect()
}

fn base_image_findings(instructions: &[Instruction], opts: &LintOptions) -> Vec<Finding> {
    let approved = opts.approved_base_images.as_deref().unwrap_or_default();
    external_images(instructions)
        .into_iter()
        .filter(|(_, image)| !matches_any(image, approved))
        .map(|(instruction, image)| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF073".into(),
            severity: Severity::Error,
            line: instruction.line,
            message: format!("External image '{}' is not approved", image),
            roast: "That external image is not on the approved menu. Use a reviewed image or update the policy with a reason.".to_string(),
        })
        .collect()
}

fn external_images(instructions: &[Instruction]) -> Vec<(&Instruction, &str)> {
    let mut aliases = HashSet::new();
    let mut images = Vec::new();
    for instruction in instructions {
        if instruction.instruction == "FROM" {
            let mut tokens = instruction
                .arguments
                .split_whitespace()
                .filter(|token| !token.starts_with("--"));
            let Some(image) = tokens.next() else {
                continue;
            };
            if !image.eq_ignore_ascii_case("scratch")
                && !aliases.contains(&image.to_ascii_lowercase())
            {
                images.push((instruction, image));
            }
            if tokens
                .next()
                .is_some_and(|token| token.eq_ignore_ascii_case("as"))
            {
                if let Some(alias) = tokens.next() {
                    aliases.insert(alias.to_ascii_lowercase());
                }
            }
        } else if instruction.instruction == "COPY" {
            let Some(image) = instruction
                .flags
                .iter()
                .find(|flag| flag.name.eq_ignore_ascii_case("from"))
                .and_then(|flag| flag.value.as_deref())
            else {
                continue;
            };
            if image.parse::<usize>().is_err() && !aliases.contains(&image.to_ascii_lowercase()) {
                images.push((instruction, image));
            }
        }
    }
    images
}

fn image_registry(image: &str) -> &str {
    let first = image
        .split('@')
        .next()
        .unwrap_or(image)
        .split('/')
        .next()
        .unwrap_or(image);
    if image.contains('/')
        && (first.contains('.') || first.contains(':') || first.eq_ignore_ascii_case("localhost"))
    {
        first
    } else {
        "docker.io"
    }
}

fn matches_any(value: &str, patterns: &[String]) -> bool {
    let value = value.to_ascii_lowercase();
    patterns.iter().any(|pattern| {
        Pattern::new(&pattern.to_ascii_lowercase())
            .map(|pattern| pattern.matches(&value))
            .unwrap_or(false)
    })
}

fn label_findings(instructions: &[Instruction], opts: &LintOptions) -> Vec<Finding> {
    let (labels, line) = final_stage_labels(instructions);
    let mut findings = Vec::new();

    for (name, format) in &opts.required_labels {
        match labels.get(name) {
            None => findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
                rule: "DF074".into(),
                severity: Severity::Error,
                line,
                message: format!("Required image label '{}' is missing", name),
                roast: "The image arrived without the metadata needed to identify, trace, or govern it.".to_string(),
            }),
            Some((value, label_line)) if !label_value_matches(value, format) => findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
                rule: "DF074".into(),
                severity: Severity::Error,
                line: *label_line,
                message: format!(
                    "Image label '{}' value '{}' does not match format '{}'",
                    name, value, format
                ),
                roast: "A required label exists, but its value is decorative rather than machine-usable.".to_string(),
            }),
            Some(_) => {}
        }
    }

    if opts.strict_labels {
        for (name, (_, label_line)) in &labels {
            if !opts.required_labels.contains_key(name) {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF074".into(),
                    severity: Severity::Error,
                    line: *label_line,
                    message: format!("Image label '{}' is not allowed by the strict schema", name),
                    roast:
                        "Strict labels means the schema is the guest list. This label is not on it."
                            .to_string(),
                });
            }
        }
    }

    findings
}

fn final_stage_labels(instructions: &[Instruction]) -> (BTreeMap<String, (String, usize)>, usize) {
    let mut labels = BTreeMap::new();
    let mut stage_line = 0;
    for instruction in instructions {
        if instruction.instruction == "FROM" {
            labels.clear();
            stage_line = instruction.line;
        } else if instruction.instruction == "LABEL" {
            let words = &instruction.words;
            if words.len() >= 2 && !words[0].value.contains('=') {
                labels.insert(
                    words[0].value.clone(),
                    (words[1].value.clone(), instruction.line),
                );
                continue;
            }
            for word in words {
                if let Some((name, value)) = word.value.split_once('=') {
                    labels.insert(name.to_string(), (value.to_string(), instruction.line));
                }
            }
        }
    }
    (labels, stage_line)
}

fn label_value_matches(value: &str, format: &str) -> bool {
    if value.contains('$') && !format.eq_ignore_ascii_case("text") {
        return false;
    }
    match format.to_ascii_lowercase().as_str() {
        "text" => !value.trim().is_empty(),
        "url" => Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://[^\s]+$")
            .unwrap()
            .is_match(value),
        "semver" => semver::Version::parse(value.trim_start_matches('v')).is_ok(),
        "hash" => Regex::new(r"^[0-9a-fA-F]{7,64}$").unwrap().is_match(value),
        "rfc3339" => {
            OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).is_ok()
        }
        "spdx" => spdx::Expression::parse(value).is_ok(),
        "email" => Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
            .unwrap()
            .is_match(value),
        _ => format
            .strip_prefix("regex:")
            .and_then(|pattern| Regex::new(pattern).ok())
            .is_some_and(|pattern| pattern.is_match(value)),
    }
}

#[derive(Debug)]
struct Suppression {
    rules: Vec<String>,
    line: usize,
    target: Option<(usize, usize)>,
    global: bool,
    used: bool,
}

pub fn apply_inline_suppressions(content: &str, findings: &mut Vec<Finding>, opts: &LintOptions) {
    if !content.contains("droast") || !content.contains('#') {
        return;
    }
    let (mut suppressions, mut policy_findings) = parse_suppressions(content, opts);
    if !opts.inline_suppressions {
        if rule_id_enabled(opts, "DF072") {
            findings.append(&mut policy_findings);
        }
        return;
    }

    findings.retain(|finding| {
        if finding.rule == "DF072" {
            return true;
        }
        let mut suppressed = false;
        for suppression in &mut suppressions {
            let matches_rule = suppression
                .rules
                .iter()
                .any(|rule| rule.eq_ignore_ascii_case(&finding.rule));
            let matches_location = suppression.global
                || suppression.target.is_some_and(|(start, end)| {
                    finding.line > 0 && finding.line >= start && finding.line <= end
                });
            if matches_rule && matches_location {
                suppression.used = true;
                suppressed = true;
            }
        }
        !suppressed
    });

    if opts.report_unused_suppressions && rule_id_enabled(opts, "DF072") {
        for suppression in suppressions.iter().filter(|item| !item.used) {
            policy_findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
                rule: "DF072".into(),
                severity: Severity::Warning,
                line: suppression.line,
                message: format!(
                    "Unused suppression for {}",
                    suppression.rules.join(",")
                ),
                roast: "This exception no longer hides a finding. Remove it before it becomes permanent policy archaeology.".to_string(),
            });
        }
    }
    if rule_id_enabled(opts, "DF072") {
        findings.append(&mut policy_findings);
    }
}

fn parse_suppressions(content: &str, opts: &LintOptions) -> (Vec<Suppression>, Vec<Finding>) {
    let document = parse_document(content);
    let known_rules = all_rules()
        .into_iter()
        .map(|rule| rule.id.to_string())
        .collect::<HashSet<_>>();
    let first_instruction_line = document.instructions.first().map(|item| item.line);
    let today = OffsetDateTime::now_utc().date();
    let directive =
        Regex::new(r"^\s*#\s*droast\s+(?:(global)\s+)?ignore=([^\s]+)(?:\s+(.*))?$").unwrap();
    let mut suppressions = Vec::new();
    let mut findings = Vec::new();

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        let Some(captures) = directive.captures(line) else {
            continue;
        };
        if document.instructions.iter().any(|instruction| {
            line_number >= instruction.span.start.line && line_number <= instruction.span.end.line
        }) {
            continue;
        }

        if !opts.inline_suppressions {
            findings.push(suppression_finding(
                line_number,
                "Inline suppressions are disabled by policy".into(),
            ));
            continue;
        }

        let global = captures.get(1).is_some();
        if global && first_instruction_line.is_some_and(|first| line_number > first) {
            findings.push(suppression_finding(
                line_number,
                "Global suppressions must appear before the first Dockerfile instruction".into(),
            ));
            continue;
        }
        let rules = captures[2]
            .split(',')
            .map(|rule| rule.trim().to_ascii_uppercase())
            .filter(|rule| !rule.is_empty())
            .collect::<Vec<_>>();
        if rules.is_empty() || rules.iter().any(|rule| !known_rules.contains(rule)) {
            findings.push(suppression_finding(
                line_number,
                format!(
                    "Suppression contains an unknown rule ID: {}",
                    captures[2].trim()
                ),
            ));
            continue;
        }
        if rules.iter().any(|rule| rule == "DF072") {
            findings.push(suppression_finding(
                line_number,
                "DF072 suppression-policy findings cannot be suppressed".into(),
            ));
            continue;
        }

        let attributes =
            match parse_attributes(captures.get(3).map(|item| item.as_str()).unwrap_or("")) {
                Ok(attributes) => attributes,
                Err(message) => {
                    findings.push(suppression_finding(line_number, message));
                    continue;
                }
            };
        if attributes
            .keys()
            .any(|key| key != "reason" && key != "expires")
        {
            findings.push(suppression_finding(
                line_number,
                "Suppression supports only reason and expires attributes".into(),
            ));
            continue;
        }
        let reason = attributes
            .get("reason")
            .map(|value| value.trim())
            .unwrap_or("");
        if opts.require_suppression_reason && reason.is_empty() {
            findings.push(suppression_finding(
                line_number,
                "Suppression reason is required by policy".into(),
            ));
            continue;
        }
        if let Some(pattern) = &opts.suppression_reason_pattern {
            if !Regex::new(pattern)
                .expect("configuration validates suppression reason patterns")
                .is_match(reason)
            {
                findings.push(suppression_finding(
                    line_number,
                    "Suppression reason does not match suppression-reason-pattern".into(),
                ));
                continue;
            }
        }

        let expires = match attributes.get("expires") {
            Some(value) => match parse_date(value) {
                Ok(date) => Some(date),
                Err(message) => {
                    findings.push(suppression_finding(line_number, message));
                    continue;
                }
            },
            None => None,
        };
        if (opts.require_suppression_expiration || opts.max_suppression_days.is_some())
            && expires.is_none()
        {
            findings.push(suppression_finding(
                line_number,
                "Suppression expiration is required by policy".into(),
            ));
            continue;
        }
        if expires.is_some_and(|date| date < today) {
            findings.push(suppression_finding(
                line_number,
                format!("Suppression expired on {}", attributes["expires"]),
            ));
            continue;
        }
        if let (Some(date), Some(max_days)) = (expires, opts.max_suppression_days) {
            if date > today + Duration::days(max_days.min(i64::MAX as u64) as i64) {
                findings.push(suppression_finding(
                    line_number,
                    format!("Suppression expiration exceeds the {max_days}-day policy limit"),
                ));
                continue;
            }
        }

        let target = (!global)
            .then(|| next_instruction_range(content, line_number, &document.instructions))
            .flatten();
        if !global && target.is_none() {
            findings.push(suppression_finding(
                line_number,
                "Suppression has no following Dockerfile instruction".into(),
            ));
            continue;
        }
        suppressions.push(Suppression {
            rules,
            line: line_number,
            target,
            global,
            used: false,
        });
    }
    (suppressions, findings)
}

fn next_instruction_range(
    content: &str,
    directive_line: usize,
    instructions: &[Instruction],
) -> Option<(usize, usize)> {
    if let Some(instruction) = instructions.iter().find(|item| item.line > directive_line) {
        return Some((instruction.span.start.line, instruction.span.end.line));
    }
    content
        .lines()
        .enumerate()
        .skip(directive_line)
        .find(|(_, line)| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .map(|(index, _)| (index + 1, index + 1))
}

fn parse_attributes(input: &str) -> Result<HashMap<String, String>, String> {
    let mut attributes = HashMap::new();
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        let key_start = index;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'-')
        {
            index += 1;
        }
        if index == key_start || bytes.get(index) != Some(&b'=') {
            return Err("Malformed suppression attribute; expected key=value".into());
        }
        let key = input[key_start..index].to_ascii_lowercase();
        index += 1;
        let value = if matches!(bytes.get(index), Some(b'\"' | b'\'')) {
            let quote = bytes[index];
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            if index == bytes.len() {
                return Err(format!("Unterminated quoted value for {key}"));
            }
            let value = input[value_start..index].to_string();
            index += 1;
            value
        } else {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            input[value_start..index].to_string()
        };
        if attributes.insert(key.clone(), value).is_some() {
            return Err(format!("Duplicate suppression attribute '{key}'"));
        }
    }
    Ok(attributes)
}

fn parse_date(value: &str) -> Result<Date, String> {
    let parts = value
        .split('-')
        .map(str::parse::<i32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("Invalid suppression expiration '{value}'; expected YYYY-MM-DD"))?;
    if parts.len() != 3 {
        return Err(format!(
            "Invalid suppression expiration '{value}'; expected YYYY-MM-DD"
        ));
    }
    let month = u8::try_from(parts[1])
        .ok()
        .and_then(|month| Month::try_from(month).ok())
        .ok_or_else(|| format!("Invalid suppression expiration '{value}'"))?;
    let day =
        u8::try_from(parts[2]).map_err(|_| format!("Invalid suppression expiration '{value}'"))?;
    Date::from_calendar_date(parts[0], month, day)
        .map_err(|_| format!("Invalid suppression expiration '{value}'"))
}

fn suppression_finding(line: usize, message: String) -> Finding {
    Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
        rule: "DF072".into(),
        severity: Severity::Error,
        line,
        message,
        roast: "A suppression is a policy exception, not an invisibility spell. Make it explicit, valid, and temporary.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linter::{lint_content, LintOptions};

    fn options(only: &[&str]) -> LintOptions {
        LintOptions {
            only_rules: only.iter().map(|rule| rule.to_string()).collect(),
            check_dockerignore: false,
            ..LintOptions::default()
        }
    }

    fn rules(source: &str, options: &LintOptions) -> Vec<String> {
        lint_content(source, "Dockerfile", options)
            .findings
            .into_iter()
            .map(|finding| finding.rule)
            .collect()
    }

    #[test]
    fn parses_quoted_suppression_attributes() {
        let attributes = parse_attributes(r#"reason="legacy base" expires=2999-12-31"#).unwrap();
        assert_eq!(attributes["reason"], "legacy base");
        assert_eq!(attributes["expires"], "2999-12-31");
    }

    #[test]
    fn registry_detection_handles_docker_hub_and_ports() {
        assert_eq!(image_registry("alpine:3.20"), "docker.io");
        assert_eq!(image_registry("acme/app:1"), "docker.io");
        assert_eq!(
            image_registry("registry.example.com:5000/app:1"),
            "registry.example.com:5000"
        );
    }

    #[test]
    fn next_instruction_suppression_hides_only_the_selected_finding() {
        let source = r#"# droast ignore=DF001 reason="legacy base" expires=2999-12-31
FROM alpine:latest
USER root
"#;
        let options = options(&["DF001", "DF002", "DF072"]);

        assert_eq!(rules(source, &options), ["DF002"]);
    }

    #[test]
    fn global_suppression_applies_to_file_level_findings() {
        let source = r#"# droast global ignore=DF020 reason="runtime injection" expires=2999-12-31
FROM alpine:3.20
CMD ["true"]
"#;
        let options = options(&["DF020", "DF072"]);

        assert!(rules(source, &options).is_empty());
    }

    #[test]
    fn required_reason_and_expiration_are_enforced() {
        let source = "# droast ignore=DF001\nFROM alpine:latest\n";
        let mut options = options(&["DF001", "DF072"]);
        options.require_suppression_reason = true;
        options.require_suppression_expiration = true;

        assert_eq!(rules(source, &options), ["DF072", "DF001"]);
    }

    #[test]
    fn suppression_reason_pattern_is_enforced() {
        let source = r#"# droast ignore=DF001 reason="temporary" expires=2999-12-31
FROM alpine:latest
"#;
        let mut options = options(&["DF001", "DF072"]);
        options.suppression_reason_pattern = Some(r"^SEC-[0-9]+ .+$".into());

        assert_eq!(rules(source, &options), ["DF072", "DF001"]);
    }

    #[test]
    fn maximum_suppression_lifetime_is_enforced() {
        let source = r#"# droast ignore=DF001 reason="SEC-1 migration" expires=2999-12-31
FROM alpine:latest
"#;
        let mut options = options(&["DF001", "DF072"]);
        options.max_suppression_days = Some(90);

        assert_eq!(rules(source, &options), ["DF072", "DF001"]);
    }

    #[test]
    fn disabled_inline_suppressions_are_visible_and_ineffective() {
        let source = r#"# droast ignore=DF001 reason="SEC-1 migration" expires=2999-12-31
FROM alpine:latest
"#;
        let mut options = options(&["DF001", "DF072"]);
        options.inline_suppressions = false;

        assert_eq!(rules(source, &options), ["DF072", "DF001"]);
    }

    #[test]
    fn unused_suppressions_are_reported_when_requested() {
        let source = r#"# droast ignore=DF001 reason="SEC-1 migration" expires=2999-12-31
FROM alpine:3.20
"#;
        let mut options = options(&["DF001", "DF072"]);
        options.report_unused_suppressions = true;

        assert_eq!(rules(source, &options), ["DF072"]);
    }

    #[test]
    fn expired_suppression_does_not_hide_the_finding() {
        let source = r#"# droast ignore=DF001 reason="old exception" expires=2000-01-01
FROM alpine:latest
"#;
        let options = options(&["DF001", "DF072"]);

        assert_eq!(rules(source, &options), ["DF072", "DF001"]);
    }

    #[test]
    fn suppression_inside_heredoc_is_not_a_dockerfile_directive() {
        let source = r#"FROM ubuntu:24.04
RUN <<SCRIPT
# droast ignore=DF015
apt-get install curl
SCRIPT
"#;
        let options = options(&["DF015", "DF072"]);

        assert_eq!(rules(source, &options), ["DF015"]);
    }

    #[test]
    fn configured_registry_allowlist_replaces_default_registry_policy() {
        let source = "FROM ghcr.io/acme/runtime:1\n";
        let mut options = options(&["DF065"]);
        options.approved_registries = Some(vec!["registry.example.com".into()]);

        assert_eq!(rules(source, &options), ["DF065"]);
    }

    #[test]
    fn registry_policy_is_inactive_until_approved_registries_is_configured() {
        let source = "FROM registry.example.com/acme/runtime:1\n";
        let options = options(&["DF065"]);

        assert!(rules(source, &options).is_empty());
    }

    #[test]
    fn approved_base_images_support_globs_and_stage_aliases() {
        let source = "FROM rust:1.85 AS build\nFROM build AS packaged\n";
        let mut options = options(&["DF073"]);
        options.approved_base_images = Some(vec!["rust:1.*".into()]);

        assert!(rules(source, &options).is_empty());
    }

    #[test]
    fn approved_base_images_apply_to_external_copy_sources() {
        let source = "FROM alpine:3.20\nCOPY --from=ghcr.io/acme/tools:1 /tool /tool\n";
        let mut options = options(&["DF073"]);
        options.approved_base_images = Some(vec!["alpine:3.*".into()]);

        assert_eq!(rules(source, &options), ["DF073"]);

        options
            .approved_base_images
            .as_mut()
            .unwrap()
            .push("ghcr.io/acme/tools:*".into());
        assert!(rules(source, &options).is_empty());
    }

    #[test]
    fn required_labels_validate_formats_on_the_final_stage() {
        let source = r#"FROM alpine:3.20
LABEL org.opencontainers.image.source="https://github.com/acme/app" \
      org.opencontainers.image.version="1.2.3" \
      org.opencontainers.image.licenses="MIT"
"#;
        let mut options = options(&["DF074"]);
        options
            .required_labels
            .insert("org.opencontainers.image.source".into(), "url".into());
        options
            .required_labels
            .insert("org.opencontainers.image.version".into(), "semver".into());
        options
            .required_labels
            .insert("org.opencontainers.image.licenses".into(), "spdx".into());

        assert!(rules(source, &options).is_empty());
    }

    #[test]
    fn strict_labels_reject_undeclared_metadata() {
        let source = "FROM alpine:3.20\nLABEL custom.key=value\n";
        let mut options = options(&["DF074"]);
        options.strict_labels = true;

        assert_eq!(rules(source, &options), ["DF074"]);
    }

    #[test]
    fn label_policy_findings_use_the_label_line_for_scoped_suppression() {
        let source = r#"FROM alpine:3.20
# droast ignore=DF074 reason="PLAT-1 generated version" expires=2999-12-31
LABEL org.opencontainers.image.version="not-semver"
"#;
        let mut options = options(&["DF072", "DF074"]);
        options
            .required_labels
            .insert("org.opencontainers.image.version".into(), "semver".into());

        assert!(rules(source, &options).is_empty());
    }

    #[test]
    fn severity_overrides_are_applied_before_minimum_severity() {
        let source = "FROM alpine:3.20\nUSER root\n";
        let mut options = options(&["DF002"]);
        options
            .severity_overrides
            .insert("DF002".into(), Severity::Info);
        options.min_severity = Severity::Warning;

        assert!(rules(source, &options).is_empty());
    }

    #[test]
    fn categories_select_matching_rules() {
        let source = "FROM alpine:latest\nUSER root\nRUN echo one\nRUN echo two\nRUN echo three\nRUN echo four\n";
        let mut options = options(&[]);
        options.categories = vec!["security".into()];

        let found = rules(source, &options);
        assert!(found.iter().any(|rule| rule == "DF002"));
        assert!(!found.iter().any(|rule| rule == "DF003"));
    }
}
