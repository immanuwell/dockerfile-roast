//! Optional, human-facing message overrides for terminal output.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::rules;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageMode {
    #[default]
    Message,
    Replace,
    Append,
}

impl std::fmt::Display for MessageMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message => write!(f, "message"),
            Self::Replace => write!(f, "replace"),
            Self::Append => write!(f, "append"),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageDefaults {
    pub mode: Option<MessageMode>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageOverride {
    pub message: String,
    #[serde(default)]
    pub help: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MessageFile {
    version: u8,
    #[serde(default)]
    defaults: MessageDefaults,
    #[serde(default)]
    rules: BTreeMap<String, MessageOverride>,
}

#[derive(Debug, Clone, Default)]
pub struct MessageOverrides {
    pub mode: MessageMode,
    pub rules: BTreeMap<String, MessageOverride>,
}

impl MessageOverrides {
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let mut effective = Self::default();
        let user = user_messages_path();
        effective.merge_optional(&user)?;
        if let Some(project) = project_messages_path() {
            effective.merge_optional(&project)?;
        }
        if let Some(path) = explicit {
            effective.merge_required(path)?;
        }
        Ok(effective)
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let file = parse_file(path)?;
        let mut overrides = Self::default();
        overrides.merge(file);
        Ok(overrides)
    }

    fn merge_optional(&mut self, path: &Path) -> Result<()> {
        if path.exists() {
            self.merge_required(path)?;
        }
        Ok(())
    }

    fn merge_required(&mut self, path: &Path) -> Result<()> {
        self.merge(parse_file(path)?);
        Ok(())
    }

    fn merge(&mut self, file: MessageFile) {
        if let Some(mode) = file.defaults.mode {
            self.mode = mode;
        }
        self.rules.extend(file.rules);
    }

    pub fn get(&self, rule: &str) -> Option<&MessageOverride> {
        self.rules.get(&rule.to_ascii_uppercase())
    }
}

fn parse_file(path: &Path) -> Result<MessageFile> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read message overrides from {}", path.display()))?;
    let mut file: MessageFile = serde_yaml::from_str(&text)
        .with_context(|| format!("Invalid message YAML in {}", path.display()))?;
    if file.version != 1 {
        bail!("{}: expected version: 1", path.display());
    }
    let known = rules::all_rules()
        .into_iter()
        .map(|rule| rule.id.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    let mut normalized = BTreeMap::new();
    for (id, override_) in file.rules {
        let id = id.to_ascii_uppercase();
        if !known.contains(&id) {
            bail!("{}: unknown rule ID '{}'", path.display(), id);
        }
        if override_.message.trim().is_empty() {
            bail!("{}: {} has an empty message", path.display(), id);
        }
        validate_placeholders(&override_.message, path, &id)?;
        if let Some(help) = &override_.help {
            let valid_url = help.split_once("://").is_some_and(|(scheme, remainder)| {
                matches!(scheme, "http" | "https")
                    && !remainder.is_empty()
                    && !remainder.starts_with('/')
                    && !remainder.chars().any(char::is_whitespace)
            });
            if !valid_url {
                bail!("{}: {} help URL must use http or https", path.display(), id);
            }
        }
        normalized.insert(id, override_);
    }
    file.rules = normalized;
    Ok(file)
}

fn validate_placeholders(message: &str, path: &Path, rule: &str) -> Result<()> {
    let allowed = ["rule", "severity", "file", "line", "default_message"];
    let mut rest = message;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            bail!("{}: {} has an unclosed placeholder", path.display(), rule);
        };
        let name = &after[..end];
        if !allowed.contains(&name) {
            bail!(
                "{}: {} uses unknown placeholder '{{{}}}'",
                path.display(),
                rule,
                name
            );
        }
        rest = &after[end + 1..];
    }
    Ok(())
}

pub fn render(
    message: &str,
    rule: &str,
    severity: &str,
    file: &str,
    line: usize,
    default_message: &str,
) -> String {
    message
        .replace("{rule}", rule)
        .replace("{severity}", severity)
        .replace("{file}", file)
        .replace("{line}", &line.to_string())
        .replace("{default_message}", default_message)
}

pub fn user_messages_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("droast").join("messages.yaml")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join("Library")
            .join("Application Support")
            .join("droast")
            .join("messages.yaml")
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("droast").join("messages.yaml")
    }
}

pub fn project_messages_path() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".droast").join("messages.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn project_init_path() -> Result<PathBuf> {
    Ok(std::env::current_dir()?
        .join(".droast")
        .join("messages.yaml"))
}

pub fn template(preset: Option<&str>) -> Result<&'static str> {
    match preset.unwrap_or("default") {
        "default" => Ok(MESSAGE_TEMPLATE),
        "friendly" => Ok(FRIENDLY_TEMPLATE),
        "onboarding" => Ok(ONBOARDING_TEMPLATE),
        other => bail!(
            "Unknown message preset '{}'. Use friendly or onboarding.",
            other
        ),
    }
}

pub fn reference_yaml() -> String {
    let mut output = String::from(
        "version: 1\n\n# Reference catalog. Copy only the rules you want to override.\nrules:\n",
    );
    for rule in rules::all_rules() {
        output.push_str(&format!(
            "  {}:\n    message: {:?}\n",
            rule.id, rule.description
        ));
    }
    output
}

const MESSAGE_TEMPLATE: &str = r#"# Optional terminal message overrides for droast.
# Personal: droast messages init
# Repository: droast messages init --project
version: 1

# modes: message (default), replace, append
defaults:
  mode: message

rules:
  DF013:
    message: >-
      Secrets in ENV persist in image layers. Use BuildKit secrets instead.
    help: https://engineering.example.com/container-secrets
  DF021:
    message: "Piping curl to a shell is not an installation strategy."
"#;

const FRIENDLY_TEMPLATE: &str = r#"version: 1
defaults:
  mode: message
rules:
  DF013:
    message: "You put the password in the fossil record again."
  DF021:
    message: "A download pipe is not a trust policy. Please verify it first."
"#;

const ONBOARDING_TEMPLATE: &str = r#"version: 1
defaults:
  mode: message
rules:
  DF013:
    message: "Use BuildKit secrets for credentials. See the container security guide."
    help: https://engineering.example.com/container-secrets
  DF020:
    message: "Production images must set a non-root USER. See the runtime baseline."
    help: https://engineering.example.com/container-runtime
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_safe_placeholders() {
        assert_eq!(
            render(
                "{rule} {severity} {file}:{line} {default_message}",
                "DF013",
                "ERROR",
                "Dockerfile",
                4,
                "Keep secrets out"
            ),
            "DF013 ERROR Dockerfile:4 Keep secrets out"
        );
    }

    #[test]
    fn rejects_unknown_placeholders_and_rule_ids() {
        let root = std::env::temp_dir().join(format!("droast-messages-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("messages.yaml");
        std::fs::write(
            &path,
            "version: 1\nrules:\n  DF013:\n    message: '{unknown}'\n",
        )
        .unwrap();
        assert!(MessageOverrides::load_file(&path)
            .unwrap_err()
            .to_string()
            .contains("unknown placeholder"));
        std::fs::write(&path, "version: 1\nrules:\n  DF999:\n    message: nope\n").unwrap();
        assert!(MessageOverrides::load_file(&path)
            .unwrap_err()
            .to_string()
            .contains("unknown rule ID"));
        std::fs::write(
            &path,
            "version: 1\nrules:\n  DF013:\n    message: nope\n    help: not-a-url\n",
        )
        .unwrap();
        assert!(MessageOverrides::load_file(&path)
            .unwrap_err()
            .to_string()
            .contains("help URL"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
