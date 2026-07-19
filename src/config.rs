//! Optional project and organization policy configuration.

use anyhow::{bail, Context};
use glob::Pattern;
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use crate::rules::{all_rules, ALL_CATEGORIES};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PolicySettings {
    pub skip: Option<Vec<String>>,
    pub min_severity: Option<String>,
    pub no_roast: Option<bool>,
    pub no_fail: Option<bool>,
    pub format: Option<String>,
    pub categories: Option<Vec<String>>,
    pub skip_categories: Option<Vec<String>>,
    #[serde(default)]
    pub severity_overrides: BTreeMap<String, String>,
    pub inline_suppressions: Option<bool>,
    pub require_suppression_reason: Option<bool>,
    pub suppression_reason_pattern: Option<String>,
    pub require_suppression_expiration: Option<bool>,
    pub max_suppression_days: Option<u64>,
    pub report_unused_suppressions: Option<bool>,
    pub approved_registries: Option<Vec<String>>,
    pub extend_approved_registries: Option<Vec<String>>,
    pub approved_base_images: Option<Vec<String>>,
    pub extend_approved_base_images: Option<Vec<String>>,
    #[serde(default)]
    pub required_labels: BTreeMap<String, String>,
    pub strict_labels: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PathOverride {
    pub paths: Vec<String>,
    pub preset: Option<String>,
    #[serde(flatten)]
    pub settings: PolicySettings,
    #[serde(skip)]
    base_dir: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DroastConfig {
    #[serde(default, deserialize_with = "deserialize_one_or_many")]
    pub extends: Vec<String>,
    pub preset: Option<String>,
    #[serde(flatten)]
    pub settings: PolicySettings,
    #[serde(default)]
    pub overrides: Vec<PathOverride>,
    #[serde(skip)]
    source_path: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

fn deserialize_one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

impl PolicySettings {
    pub fn validate(&self, scope: &str) -> anyhow::Result<()> {
        validate_settings(self, scope)
    }

    pub fn merge(&mut self, child: PolicySettings) {
        merge_list(&mut self.skip, child.skip);
        replace(&mut self.min_severity, child.min_severity);
        replace(&mut self.no_roast, child.no_roast);
        replace(&mut self.no_fail, child.no_fail);
        replace(&mut self.format, child.format);
        replace(&mut self.categories, child.categories);
        merge_list(&mut self.skip_categories, child.skip_categories);
        self.severity_overrides.extend(child.severity_overrides);
        merge_restrictive_switch(
            &mut self.inline_suppressions,
            child.inline_suppressions,
            false,
        );
        merge_restrictive_switch(
            &mut self.require_suppression_reason,
            child.require_suppression_reason,
            true,
        );
        if self.suppression_reason_pattern.is_none() {
            self.suppression_reason_pattern = child.suppression_reason_pattern;
        }
        merge_restrictive_switch(
            &mut self.require_suppression_expiration,
            child.require_suppression_expiration,
            true,
        );
        if let Some(child_days) = child.max_suppression_days {
            self.max_suppression_days = Some(
                self.max_suppression_days
                    .map_or(child_days, |current| current.min(child_days)),
            );
        }
        merge_restrictive_switch(
            &mut self.report_unused_suppressions,
            child.report_unused_suppressions,
            true,
        );
        replace(&mut self.approved_registries, child.approved_registries);
        merge_list(
            &mut self.approved_registries,
            child.extend_approved_registries,
        );
        replace(&mut self.approved_base_images, child.approved_base_images);
        merge_list(
            &mut self.approved_base_images,
            child.extend_approved_base_images,
        );
        for (name, format) in child.required_labels {
            self.required_labels.entry(name).or_insert(format);
        }
        merge_restrictive_switch(&mut self.strict_labels, child.strict_labels, true);
    }

    /// Overlay explicit settings on preset defaults without applying inherited
    /// policy restrictions. Extension lists stay separate until this layer is
    /// merged into its parent.
    fn overlay_preset(&mut self, explicit: PolicySettings) {
        merge_list(&mut self.skip, explicit.skip);
        replace(&mut self.min_severity, explicit.min_severity);
        replace(&mut self.no_roast, explicit.no_roast);
        replace(&mut self.no_fail, explicit.no_fail);
        replace(&mut self.format, explicit.format);
        replace(&mut self.categories, explicit.categories);
        merge_list(&mut self.skip_categories, explicit.skip_categories);
        self.severity_overrides.extend(explicit.severity_overrides);
        replace(&mut self.inline_suppressions, explicit.inline_suppressions);
        replace(
            &mut self.require_suppression_reason,
            explicit.require_suppression_reason,
        );
        replace(
            &mut self.suppression_reason_pattern,
            explicit.suppression_reason_pattern,
        );
        replace(
            &mut self.require_suppression_expiration,
            explicit.require_suppression_expiration,
        );
        replace(
            &mut self.max_suppression_days,
            explicit.max_suppression_days,
        );
        replace(
            &mut self.report_unused_suppressions,
            explicit.report_unused_suppressions,
        );
        replace(&mut self.approved_registries, explicit.approved_registries);
        merge_list(
            &mut self.extend_approved_registries,
            explicit.extend_approved_registries,
        );
        replace(
            &mut self.approved_base_images,
            explicit.approved_base_images,
        );
        merge_list(
            &mut self.extend_approved_base_images,
            explicit.extend_approved_base_images,
        );
        self.required_labels.extend(explicit.required_labels);
        replace(&mut self.strict_labels, explicit.strict_labels);
    }
}

impl DroastConfig {
    /// Backward-compatible best-effort discovery for library callers.
    pub fn load() -> Self {
        Self::try_load().unwrap_or_default()
    }

    /// Discover and strictly validate the nearest `droast.toml`.
    pub fn try_load() -> anyhow::Result<Self> {
        match Self::find() {
            Some(path) => Self::load_from(&path),
            None => Ok(Self::default()),
        }
    }

    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        let mut stack = Vec::new();
        let config = Self::load_recursive(path, &mut stack)?;
        config.validate()?;
        Ok(config)
    }

    fn load_recursive(path: &Path, stack: &mut Vec<PathBuf>) -> anyhow::Result<Self> {
        let path = absolute_path(path)?
            .canonicalize()
            .with_context(|| format!("Cannot resolve config file '{}'", path.display()))?;
        if let Some(position) = stack.iter().position(|candidate| candidate == &path) {
            let mut cycle = stack[position..]
                .iter()
                .map(|item| item.display().to_string())
                .collect::<Vec<_>>();
            cycle.push(path.display().to_string());
            bail!("Configuration inheritance cycle: {}", cycle.join(" -> "));
        }
        stack.push(path.clone());

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
        let mut local: DroastConfig = toml::from_str(&content).map_err(|error| {
            anyhow::anyhow!("Invalid config file '{}': {error}", path.display())
        })?;
        local.source_path = Some(path.clone());
        let base_dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        for item in &mut local.overrides {
            item.base_dir = base_dir.clone();
        }

        let mut merged = DroastConfig::default();
        for inherited in &local.extends {
            if inherited.starts_with("http://") || inherited.starts_with("https://") {
                bail!(
                    "Remote configuration '{}' is not fetched automatically; download a pinned file in CI and extend its local path",
                    inherited
                );
            }
            let inherited_path = if Path::new(inherited).is_absolute() {
                PathBuf::from(inherited)
            } else {
                base_dir.join(inherited)
            };
            merged.merge(Self::load_recursive(&inherited_path, stack)?);
        }

        let mut layer = preset_settings(local.preset.as_deref())?;
        layer.overlay_preset(local.settings);
        merged.settings.merge(layer);
        merged.overrides.extend(local.overrides);
        merged.source_path = Some(path);
        stack.pop();
        Ok(merged)
    }

    fn merge(&mut self, child: DroastConfig) {
        self.settings.merge(child.settings);
        self.overrides.extend(child.overrides);
        if child.source_path.is_some() {
            self.source_path = child.source_path;
        }
    }

    pub fn effective_for(&self, path: &Path) -> anyhow::Result<PolicySettings> {
        let mut effective = self.settings.clone();
        for path_override in &self.overrides {
            if path_override.matches(path)? {
                let mut layer = preset_settings(path_override.preset.as_deref())?;
                layer.overlay_preset(path_override.settings.clone());
                effective.merge(layer);
            }
        }
        validate_settings(&effective, "effective configuration")?;
        Ok(effective)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        preset_settings(self.preset.as_deref())?;
        validate_settings(&self.settings, "configuration")?;
        for path_override in &self.overrides {
            if path_override.paths.is_empty() {
                bail!("Every [[overrides]] block must contain at least one path pattern");
            }
            for pattern in &path_override.paths {
                Pattern::new(pattern)
                    .with_context(|| format!("Invalid path override glob pattern '{pattern}'"))?;
            }
            preset_settings(path_override.preset.as_deref())?;
            validate_settings(&path_override.settings, "path override")?;
        }
        Ok(())
    }

    fn find() -> Option<PathBuf> {
        let cwd = std::env::current_dir().ok()?;
        let mut dir: &Path = &cwd;
        loop {
            let candidate = dir.join("droast.toml");
            if candidate.is_file() {
                return Some(candidate);
            }
            if dir.join(".git").exists() {
                break;
            }
            dir = dir.parent()?;
        }
        None
    }
}

impl PathOverride {
    fn matches(&self, path: &Path) -> anyhow::Result<bool> {
        let absolute = absolute_path(path)?;
        let absolute = absolute.canonicalize().unwrap_or(absolute);
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let candidates = [
            Some(normalized_path(&absolute)),
            absolute
                .strip_prefix(&self.base_dir)
                .ok()
                .map(normalized_path),
            absolute.strip_prefix(&cwd).ok().map(normalized_path),
        ];
        for pattern in &self.paths {
            let pattern = Pattern::new(pattern)
                .with_context(|| format!("Invalid path override glob pattern '{pattern}'"))?;
            if candidates
                .iter()
                .flatten()
                .any(|path| pattern.matches(path))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub fn preset_settings(name: Option<&str>) -> anyhow::Result<PolicySettings> {
    let Some(name) = name else {
        return Ok(PolicySettings::default());
    };
    let mut settings = PolicySettings::default();
    match name.to_ascii_lowercase().as_str() {
        "minimal" => {
            settings.min_severity = Some("error".into());
            settings.no_roast = Some(true);
        }
        "security" => {
            settings.categories = Some(vec!["security".into(), "supply-chain".into()]);
            settings.min_severity = Some("warning".into());
            settings.no_roast = Some(true);
        }
        "performance" => {
            settings.categories = Some(vec!["performance".into()]);
            settings.min_severity = Some("info".into());
            settings.no_roast = Some(true);
        }
        "production" => {
            settings.min_severity = Some("warning".into());
            settings.no_roast = Some(true);
        }
        "strict" => {
            settings.min_severity = Some("info".into());
            settings.no_roast = Some(true);
            settings.require_suppression_reason = Some(true);
            settings.require_suppression_expiration = Some(true);
            settings.report_unused_suppressions = Some(true);
        }
        _ => bail!(
            "Unknown preset '{name}'; expected minimal, security, performance, production, or strict"
        ),
    }
    Ok(settings)
}

fn validate_settings(settings: &PolicySettings, scope: &str) -> anyhow::Result<()> {
    let known_rules = all_rules()
        .into_iter()
        .map(|rule| rule.id.to_string())
        .collect::<HashSet<_>>();
    for id in settings
        .skip
        .iter()
        .flatten()
        .chain(settings.severity_overrides.keys())
    {
        if !known_rules.contains(&id.to_ascii_uppercase()) {
            bail!("Unknown rule ID '{id}' in {scope}");
        }
    }
    for severity in settings
        .min_severity
        .iter()
        .chain(settings.severity_overrides.values())
    {
        if !matches!(
            severity.to_ascii_lowercase().as_str(),
            "info" | "warning" | "error"
        ) {
            bail!("Unknown severity '{severity}' in {scope}");
        }
    }
    if let Some(format) = &settings.format {
        if !matches!(
            format.to_ascii_lowercase().as_str(),
            "terminal" | "json" | "github" | "compact" | "sarif"
        ) {
            bail!("Unknown output format '{format}' in {scope}");
        }
    }
    for category in settings
        .categories
        .iter()
        .flatten()
        .chain(settings.skip_categories.iter().flatten())
    {
        if !ALL_CATEGORIES
            .iter()
            .any(|known| known.eq_ignore_ascii_case(category))
        {
            bail!("Unknown rule category '{category}' in {scope}");
        }
    }
    for (label, format) in &settings.required_labels {
        if label.trim().is_empty() {
            bail!("Required label names cannot be empty in {scope}");
        }
        validate_label_format(format)
            .with_context(|| format!("Invalid format for required label '{label}' in {scope}"))?;
    }
    for (field, patterns) in [
        ("approved-registries", &settings.approved_registries),
        (
            "extend-approved-registries",
            &settings.extend_approved_registries,
        ),
        ("approved-base-images", &settings.approved_base_images),
        (
            "extend-approved-base-images",
            &settings.extend_approved_base_images,
        ),
    ] {
        for pattern in patterns.iter().flatten() {
            if pattern.trim().is_empty() {
                bail!("Empty glob pattern in {field} in {scope}");
            }
            Pattern::new(pattern).with_context(|| {
                format!("Invalid glob pattern '{pattern}' in {field} in {scope}")
            })?;
        }
    }
    if settings
        .max_suppression_days
        .is_some_and(|days| days > 365_000)
    {
        bail!("max-suppression-days cannot exceed 365000 in {scope}");
    }
    if let Some(pattern) = &settings.suppression_reason_pattern {
        regex::Regex::new(pattern)
            .with_context(|| format!("Invalid suppression-reason-pattern in {scope}"))?;
    }
    Ok(())
}

fn validate_label_format(format: &str) -> anyhow::Result<()> {
    if matches!(
        format.to_ascii_lowercase().as_str(),
        "text" | "url" | "semver" | "hash" | "rfc3339" | "spdx" | "email"
    ) {
        return Ok(());
    }
    if let Some(pattern) = format.strip_prefix("regex:") {
        regex::Regex::new(pattern).context("invalid regular expression")?;
        return Ok(());
    }
    bail!("expected text, url, semver, hash, rfc3339, spdx, email, or regex:<pattern>")
}

fn replace<T>(target: &mut Option<T>, child: Option<T>) {
    if child.is_some() {
        *target = child;
    }
}

fn merge_restrictive_switch(target: &mut Option<bool>, child: Option<bool>, restrictive: bool) {
    let Some(child) = child else {
        return;
    };
    *target = Some(match *target {
        Some(parent) if restrictive => parent || child,
        Some(parent) => parent && child,
        None => child,
    });
}

fn merge_list(target: &mut Option<Vec<String>>, child: Option<Vec<String>>) {
    let Some(child) = child else {
        return;
    };
    let target = target.get_or_insert_with(Vec::new);
    for value in child {
        if !target
            .iter()
            .any(|current| current.eq_ignore_ascii_case(&value))
        {
            target.push(value);
        }
    }
}

fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("Cannot resolve the current directory")?
            .join(path))
    }
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::{DroastConfig, PolicySettings};
    fn fixture(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("droast-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn loads_legacy_fields_and_new_policy_fields() {
        let config: DroastConfig = toml::from_str(
            r#"
skip = ["DF001"]
no-roast = true
preset = "production"
categories = ["security"]

[severity-overrides]
DF013 = "warning"

[required-labels]
"org.opencontainers.image.source" = "url"
"#,
        )
        .unwrap();

        assert_eq!(config.settings.skip.as_deref().unwrap(), ["DF001"]);
        assert_eq!(config.settings.no_roast, Some(true));
        assert_eq!(config.preset.as_deref(), Some("production"));
        assert_eq!(config.settings.severity_overrides["DF013"], "warning");
    }

    #[test]
    fn inherited_lists_are_additive_and_scalars_are_overridden() {
        let mut parent = PolicySettings {
            skip: Some(vec!["DF001".into()]),
            min_severity: Some("error".into()),
            ..PolicySettings::default()
        };
        parent.merge(PolicySettings {
            skip: Some(vec!["DF002".into()]),
            min_severity: Some("warning".into()),
            ..PolicySettings::default()
        });

        assert_eq!(parent.skip.unwrap(), ["DF001", "DF002"]);
        assert_eq!(parent.min_severity.as_deref(), Some("warning"));
    }

    #[test]
    fn allowlists_replace_by_default_and_extend_only_when_explicit() {
        let mut settings = PolicySettings {
            approved_registries: Some(vec!["docker.io".into(), "ghcr.io".into()]),
            ..PolicySettings::default()
        };
        settings.merge(PolicySettings {
            approved_registries: Some(vec!["registry.example.com".into()]),
            ..PolicySettings::default()
        });
        assert_eq!(
            settings.approved_registries.as_deref().unwrap(),
            ["registry.example.com"]
        );

        settings.merge(PolicySettings {
            extend_approved_registries: Some(vec!["mirror.example.com".into()]),
            ..PolicySettings::default()
        });
        assert_eq!(
            settings.approved_registries.unwrap(),
            ["registry.example.com", "mirror.example.com"]
        );
    }

    #[test]
    fn inherited_governance_cannot_be_weakened() {
        let mut parent = PolicySettings {
            inline_suppressions: Some(false),
            require_suppression_reason: Some(true),
            require_suppression_expiration: Some(true),
            max_suppression_days: Some(30),
            report_unused_suppressions: Some(true),
            strict_labels: Some(true),
            ..PolicySettings::default()
        };
        parent.merge(PolicySettings {
            inline_suppressions: Some(true),
            require_suppression_reason: Some(false),
            require_suppression_expiration: Some(false),
            max_suppression_days: Some(90),
            report_unused_suppressions: Some(false),
            strict_labels: Some(false),
            ..PolicySettings::default()
        });

        assert_eq!(parent.inline_suppressions, Some(false));
        assert_eq!(parent.require_suppression_reason, Some(true));
        assert_eq!(parent.require_suppression_expiration, Some(true));
        assert_eq!(parent.max_suppression_days, Some(30));
        assert_eq!(parent.report_unused_suppressions, Some(true));
        assert_eq!(parent.strict_labels, Some(true));
    }

    #[test]
    fn explicit_inheritance_merges_organization_and_repository_policy() {
        let root = fixture("inheritance");
        let parent = root.join("organization.toml");
        let child = root.join("droast.toml");
        std::fs::write(
            &parent,
            r#"
skip = ["DF012"]
approved-registries = ["registry.example.com"]
require-suppression-reason = true
"#,
        )
        .unwrap();
        std::fs::write(
            &child,
            r#"
extends = "organization.toml"
skip = ["DF022"]
extend-approved-registries = ["ghcr.io"]
require-suppression-expiration = true
"#,
        )
        .unwrap();

        let config = DroastConfig::load_from(&child).unwrap();
        assert_eq!(config.settings.skip.unwrap(), ["DF012", "DF022"]);
        assert_eq!(
            config.settings.approved_registries.unwrap(),
            ["registry.example.com", "ghcr.io"]
        );
        assert_eq!(config.settings.require_suppression_reason, Some(true));
        assert_eq!(config.settings.require_suppression_expiration, Some(true));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inheritance_cycles_are_rejected() {
        let root = fixture("cycle");
        let first = root.join("first.toml");
        let second = root.join("second.toml");
        std::fs::write(&first, "extends = \"second.toml\"\n").unwrap();
        std::fs::write(&second, "extends = \"first.toml\"\n").unwrap();

        let error = DroastConfig::load_from(&first).unwrap_err().to_string();
        assert!(error.contains("inheritance cycle"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_overrides_apply_in_order() {
        let root = fixture("paths");
        std::fs::create_dir_all(root.join("services/legacy")).unwrap();
        let config_path = root.join("droast.toml");
        std::fs::write(
            &config_path,
            r#"
min-severity = "warning"

[[overrides]]
paths = ["services/**/Dockerfile"]
min-severity = "error"
skip = ["DF012"]

[[overrides]]
paths = ["services/legacy/Dockerfile"]
skip = ["DF022"]
"#,
        )
        .unwrap();

        let config = DroastConfig::load_from(&config_path).unwrap();
        let settings = config
            .effective_for(&root.join("services/legacy/Dockerfile"))
            .unwrap();
        assert_eq!(settings.min_severity.as_deref(), Some("error"));
        assert_eq!(settings.skip.unwrap(), ["DF012", "DF022"]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preset_is_a_default_that_explicit_values_can_override() {
        let root = fixture("preset");
        let config_path = root.join("droast.toml");
        std::fs::write(
            &config_path,
            "preset = \"strict\"\nmin-severity = \"warning\"\nrequire-suppression-expiration = false\n",
        )
        .unwrap();

        let config = DroastConfig::load_from(&config_path).unwrap();
        assert_eq!(config.settings.min_severity.as_deref(), Some("warning"));
        assert_eq!(config.settings.require_suppression_reason, Some(true));
        assert_eq!(config.settings.require_suppression_expiration, Some(false));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_rules_and_categories_are_rejected() {
        let root = fixture("validation");
        let config_path = root.join("droast.toml");
        std::fs::write(&config_path, "skip = [\"DF999\"]\n").unwrap();
        assert!(DroastConfig::load_from(&config_path)
            .unwrap_err()
            .to_string()
            .contains("Unknown rule ID"));

        std::fs::write(&config_path, "categories = [\"imaginary\"]\n").unwrap();
        assert!(DroastConfig::load_from(&config_path)
            .unwrap_err()
            .to_string()
            .contains("Unknown rule category"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_keys_and_invalid_policy_globs_are_rejected() {
        assert!(toml::from_str::<DroastConfig>("minimum-severity = \"error\"\n").is_err());

        let root = fixture("bad-glob");
        let config_path = root.join("droast.toml");
        std::fs::write(&config_path, "approved-registries = [\"[bad\"]\n").unwrap();
        assert!(DroastConfig::load_from(&config_path)
            .unwrap_err()
            .to_string()
            .contains("Invalid glob pattern"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remote_inheritance_requires_an_explicit_pinned_download() {
        let root = fixture("remote");
        let config_path = root.join("droast.toml");
        std::fs::write(
            &config_path,
            "extends = \"https://example.com/droast.toml\"\n",
        )
        .unwrap();

        let error = DroastConfig::load_from(&config_path)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not fetched automatically"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn published_configuration_examples_are_valid_toml() {
        for (name, content) in [
            (
                "enterprise",
                include_str!("../examples/droast-enterprise.toml"),
            ),
            (
                "organization",
                include_str!("../examples/droast-organization.toml"),
            ),
            (
                "repository",
                include_str!("../examples/droast-repository.toml"),
            ),
        ] {
            let config: DroastConfig =
                toml::from_str(content).unwrap_or_else(|error| panic!("{name}: {error}"));
            config
                .validate()
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }

        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/droast.schema.json"))
                .expect("published configuration schema must be valid JSON");
        assert_eq!(schema["title"], "droast configuration");
    }
}
