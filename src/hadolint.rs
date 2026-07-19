//! Conversion of compatible Hadolint YAML settings to droast TOML.

use anyhow::{bail, Context};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct ImportResult {
    pub config: String,
    pub imported_rules: usize,
    pub unmapped_rules: Vec<String>,
    pub unmapped_settings: Vec<String>,
}

pub fn import_config(path: &Path) -> anyhow::Result<ImportResult> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Hadolint config '{}'", path.display()))?;
    let document: Value = serde_yaml::from_str(&source)
        .with_context(|| format!("Invalid Hadolint YAML config '{}'", path.display()))?;
    let settings = document.as_mapping().ok_or_else(|| {
        anyhow::anyhow!(
            "Hadolint config '{}' must be a YAML mapping",
            path.display()
        )
    })?;

    let mut skip = BTreeSet::new();
    let mut overrides = BTreeMap::new();
    let mut imported_rules = 0;
    let mut unmapped_rules = BTreeSet::new();
    let mut unmapped_settings = BTreeSet::new();
    for rule in strings(settings, "ignored")? {
        apply_rule(
            &rule,
            None,
            &mut skip,
            &mut overrides,
            &mut imported_rules,
            &mut unmapped_rules,
        );
    }
    if let Some(value) = get(settings, "override") {
        let value = value
            .as_mapping()
            .ok_or_else(|| anyhow::anyhow!("Hadolint 'override' must be a mapping"))?;
        for (hadolint_severity, droast_severity) in [
            ("error", "error"),
            ("warning", "warning"),
            ("info", "info"),
            ("style", "info"),
        ] {
            for rule in strings(value, hadolint_severity)? {
                apply_rule(
                    &rule,
                    Some(droast_severity),
                    &mut skip,
                    &mut overrides,
                    &mut imported_rules,
                    &mut unmapped_rules,
                );
            }
        }
    }

    let registries = strings(settings, "trustedRegistries")?;
    let labels = map(settings, "label-schema")?;
    let strict_labels = boolean(settings, "strict-labels")?;
    let mut no_fail = boolean(settings, "no-fail")?;
    let inline_suppressions = boolean(settings, "disable-ignore-pragma")?.map(|value| !value);
    let mut min_severity = get(settings, "failure-threshold")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    match min_severity.as_deref() {
        Some("style") | Some("ignore") => min_severity = Some("info".into()),
        Some("none") => {
            min_severity = None;
            no_fail = Some(true);
        }
        Some("error") | Some("warning") | Some("info") | None => {}
        Some(value) => {
            unmapped_settings.insert(format!("failure-threshold={value}"));
            min_severity = None;
        }
    }
    let format = get(settings, "format")
        .and_then(Value::as_str)
        .and_then(|value| match value {
            "tty" => Some("terminal"),
            "json" | "sarif" => Some(value),
            _ => {
                unmapped_settings.insert(format!("format={value}"));
                None
            }
        });
    for key in settings.keys().filter_map(Value::as_str) {
        if !matches!(
            key,
            "ignored"
                | "override"
                | "trustedRegistries"
                | "label-schema"
                | "strict-labels"
                | "no-fail"
                | "disable-ignore-pragma"
                | "failure-threshold"
                | "format"
        ) {
            unmapped_settings.insert(key.into());
        }
    }

    Ok(ImportResult {
        config: render(
            &skip,
            &overrides,
            &registries,
            &labels,
            strict_labels,
            no_fail,
            inline_suppressions,
            min_severity.as_deref(),
            format,
        ),
        imported_rules,
        unmapped_rules: unmapped_rules.into_iter().collect(),
        unmapped_settings: unmapped_settings.into_iter().collect(),
    })
}

fn apply_rule(
    rule: &str,
    severity: Option<&str>,
    skip: &mut BTreeSet<String>,
    overrides: &mut BTreeMap<String, String>,
    imported: &mut usize,
    unmapped: &mut BTreeSet<String>,
) {
    let Some(aliases) = aliases(rule) else {
        unmapped.insert(rule.to_ascii_uppercase());
        return;
    };
    *imported += 1;
    for alias in aliases {
        match severity {
            Some(severity) => {
                overrides.insert((*alias).into(), severity.into());
            }
            None => {
                skip.insert((*alias).into());
            }
        }
    }
}

/// Hadolint rules with equivalent droast checks. One Hadolint rule may map to multiple checks.
fn aliases(rule: &str) -> Option<&'static [&'static str]> {
    match rule.to_ascii_uppercase().as_str() {
        "DL3000" => Some(&["DF009"]),
        "DL3001" => Some(&["DF060"]),
        "DL3002" => Some(&["DF002"]),
        "DL3003" => Some(&["DF008"]),
        "DL3004" => Some(&["DF010"]),
        "DL3006" | "DL3007" => Some(&["DF001"]),
        "DL3008" | "DL3033" | "DL3037" | "DL3041" => Some(&["DF005"]),
        "DL3009" => Some(&["DF004"]),
        "DL3012" => Some(&["DF041"]),
        "DL3013" => Some(&["DF051"]),
        "DL3014" => Some(&["DF015"]),
        "DL3015" => Some(&["DF016"]),
        "DL3016" => Some(&["DF031"]),
        "DL3018" => Some(&["DF052"]),
        "DL3019" => Some(&["DF029"]),
        "DL3021" => Some(&["DF048"]),
        "DL3022" => Some(&["DF049"]),
        "DL3023" => Some(&["DF050"]),
        "DL3024" => Some(&["DF042"]),
        "DL3025" => Some(&["DF018", "DF025"]),
        "DL3026" => Some(&["DF065"]),
        "DL3028" => Some(&["DF053"]),
        "DL3029" => Some(&["DF061"]),
        "DL3030" => Some(&["DF027"]),
        "DL3032" => Some(&["DF047"]),
        "DL3034" => Some(&["DF043"]),
        "DL3035" => Some(&["DF044"]),
        "DL3036" => Some(&["DF045"]),
        "DL3040" => Some(&["DF046"]),
        "DL3042" => Some(&["DF030"]),
        "DL3043" => Some(&["DF068"]),
        "DL3044" => Some(&["DF062"]),
        "DL3045" => Some(&["DF063"]),
        "DL3046" => Some(&["DF064"]),
        "DL3047" => Some(&["DF056"]),
        "DL3059" => Some(&["DF003"]),
        "DL3060" => Some(&["DF055"]),
        "DL3061" => Some(&["DF037"]),
        "DL3062" => Some(&["DF054"]),
        "DL4000" => Some(&["DF019"]),
        "DL4001" => Some(&["DF058"]),
        "DL4003" => Some(&["DF038"]),
        "DL4004" => Some(&["DF039"]),
        "DL4006" => Some(&["DF057"]),
        _ => None,
    }
}

fn get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.into()))
}
fn strings(mapping: &Mapping, key: &str) -> anyhow::Result<Vec<String>> {
    let Some(value) = get(mapping, key) else {
        return Ok(Vec::new());
    };
    match value {
        Value::String(value) => Ok(vec![value.clone()]),
        Value::Sequence(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("Hadolint '{key}' must contain strings"))
            })
            .collect(),
        _ => bail!("Hadolint '{key}' must be a string or list of strings"),
    }
}
fn map(mapping: &Mapping, field: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let Some(value) = get(mapping, field) else {
        return Ok(BTreeMap::new());
    };
    value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("Hadolint '{field}' must be a mapping"))?
        .iter()
        .map(|(key, value)| {
            Ok((
                key.as_str()
                    .ok_or_else(|| anyhow::anyhow!("Hadolint '{field}' keys must be strings"))?
                    .into(),
                value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Hadolint '{field}' values must be strings"))?
                    .into(),
            ))
        })
        .collect()
}
fn boolean(mapping: &Mapping, key: &str) -> anyhow::Result<Option<bool>> {
    get(mapping, key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| anyhow::anyhow!("Hadolint '{key}' must be true or false"))
        })
        .transpose()
}

fn render(
    skip: &BTreeSet<String>,
    overrides: &BTreeMap<String, String>,
    registries: &[String],
    labels: &BTreeMap<String, String>,
    strict: Option<bool>,
    no_fail: Option<bool>,
    inline: Option<bool>,
    severity: Option<&str>,
    format: Option<&str>,
) -> String {
    let mut output = String::from(
        "# Generated from a Hadolint configuration. Review reported unmapped items.\n\n",
    );
    if !skip.is_empty() {
        output.push_str(&format!(
            "skip = {}\n",
            list(skip.iter().map(String::as_str))
        ));
    }
    if !registries.is_empty() {
        output.push_str(&format!(
            "approved-registries = {}\n",
            list(registries.iter().map(String::as_str))
        ));
    }
    for (key, value) in [
        ("strict-labels", strict.map(|value| value.to_string())),
        ("no-fail", no_fail.map(|value| value.to_string())),
        ("inline-suppressions", inline.map(|value| value.to_string())),
        ("min-severity", severity.map(quote)),
        ("format", format.map(quote)),
    ] {
        if let Some(value) = value {
            output.push_str(&format!("{key} = {value}\n"));
        }
    }
    if !overrides.is_empty() {
        output.push_str("\n[severity-overrides]\n");
        for (rule, value) in overrides {
            output.push_str(&format!("{rule} = {}\n", quote(value)));
        }
    }
    if !labels.is_empty() {
        output.push_str("\n[required-labels]\n");
        for (label, value) in labels {
            output.push_str(&format!("{} = {}\n", quote(label), quote(value)));
        }
    }
    output
}
fn list<'a>(values: impl Iterator<Item = &'a str>) -> String {
    format!("[{}]", values.map(quote).collect::<Vec<_>>().join(", "))
}
fn quote(value: &str) -> String {
    serde_json::to_string(value).expect("strings are serializable")
}

#[cfg(test)]
mod tests {
    use super::import_config;
    #[test]
    fn imports_supported_settings_and_reports_unmapped_items() {
        let root =
            std::env::temp_dir().join(format!("droast-hadolint-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join(".hadolint.yaml");
        std::fs::write(&source, "ignored: [DL3003, DL3025, SC2086]\ntrustedRegistries: [docker.io, registry.example.com]\nfailure-threshold: warning\nno-fail: true\ndisable-ignore-pragma: true\nstrict-labels: true\nlabel-schema:\n  org.opencontainers.image.version: semver\noverride:\n  error: [DL3002]\n  style: [DL3042]\nformat: sarif\nno-color: true\n").unwrap();
        let result = import_config(&source).unwrap();
        assert!(result
            .config
            .contains("skip = [\"DF008\", \"DF018\", \"DF025\"]"));
        assert!(result
            .config
            .contains("approved-registries = [\"docker.io\", \"registry.example.com\"]"));
        assert!(result.config.contains("DF002 = \"error\""));
        assert!(result.config.contains("DF030 = \"info\""));
        assert_eq!(result.unmapped_rules, ["SC2086"]);
        assert_eq!(result.unmapped_settings, ["no-color"]);
        let config = root.join("droast.toml");
        std::fs::write(&config, result.config).unwrap();
        crate::config::DroastConfig::load_from(&config).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
