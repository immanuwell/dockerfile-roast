/// Project-level configuration loaded from `droast.toml`.
///
/// droast works great with zero configuration — this file is purely optional
/// and exists for teams that want to commit project-level defaults into their
/// repo (e.g. in CI/CD setups) rather than repeat flags on every invocation.
///
/// Discovery: droast searches for `droast.toml` starting from the current
/// working directory and walking up until it finds the file, reaches a `.git`
/// directory, or hits the filesystem root — whichever comes first.
///
/// Merge order (highest wins): CLI flag > droast.toml > built-in default.
/// The one exception is `skip`: CLI and config are **unioned** so that the
/// config can establish a project baseline without preventing developers from
/// suppressing additional rules on the command line.

use anyhow::Context;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DroastConfig {
    /// Rule IDs to skip (merged with --skip on CLI).
    pub skip: Option<Vec<String>>,

    /// Minimum severity to report: "info", "warning", or "error".
    pub min_severity: Option<String>,

    /// Suppress roast messages; show technical descriptions only.
    pub no_roast: Option<bool>,

    /// Never exit with code 1 (advisory / non-blocking mode).
    pub no_fail: Option<bool>,

    /// Output format: "terminal", "json", "github", or "compact".
    pub format: Option<String>,
}

impl DroastConfig {
    /// Search for and load `droast.toml`, returning `Default` if none found.
    pub fn load() -> Self {
        if let Some(path) = Self::find() {
            Self::load_from(&path).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    /// Walk up from cwd looking for `droast.toml`.
    /// Stops at a `.git` boundary or the filesystem root.
    fn find() -> Option<std::path::PathBuf> {
        let cwd = std::env::current_dir().ok()?;
        let mut dir: &Path = &cwd;
        loop {
            let candidate = dir.join("droast.toml");
            if candidate.is_file() {
                return Some(candidate);
            }
            // Stop at repository root so we don't cross project boundaries.
            if dir.join(".git").exists() {
                break;
            }
            match dir.parent() {
                Some(parent) => dir = parent,
                None => break,
            }
        }
        None
    }

    /// Load configuration from an explicit path.
    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{}'", path.display()))?;
        let cfg: DroastConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid config file '{}': {e}", path.display()))?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::DroastConfig;

    #[test]
    fn loads_config_from_explicit_path() {
        let path = std::env::temp_dir().join(format!(
            "droast-explicit-config-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, "skip = [\"DF001\"]\nno-roast = true\n").unwrap();

        let config = DroastConfig::load_from(&path).unwrap();

        assert_eq!(config.skip.unwrap(), ["DF001"]);
        assert_eq!(config.no_roast, Some(true));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn explicit_config_reports_invalid_toml() {
        let path = std::env::temp_dir().join(format!(
            "droast-invalid-config-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, "skip = [\n").unwrap();

        let error = DroastConfig::load_from(&path).unwrap_err().to_string();

        assert!(error.contains("Invalid config file"));
        std::fs::remove_file(path).unwrap();
    }
}
