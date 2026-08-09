use crate::output::finding_fingerprint;
use crate::rules::Finding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
struct BaselineDocument {
    schema_version: u32,
    fingerprints: BTreeSet<String>,
}

pub fn load(path: &Path) -> Result<BTreeSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read baseline '{}'", path.display()))?;
    let document: BaselineDocument = serde_json::from_str(&content)
        .with_context(|| format!("Baseline '{}' is not valid JSON", path.display()))?;
    if document.schema_version != 2 {
        anyhow::bail!(
            "Baseline '{}' uses unsupported schema version {}",
            path.display(),
            document.schema_version
        );
    }
    Ok(document.fingerprints)
}

pub fn write(path: &Path, results: &[(&str, &[Finding])]) -> Result<()> {
    let fingerprints = results
        .iter()
        .flat_map(|(file, findings)| {
            findings
                .iter()
                .map(move |finding| finding_fingerprint(file, finding))
        })
        .collect();
    let document = BaselineDocument {
        schema_version: 2,
        fingerprints,
    };
    let content = format!("{}\n", serde_json::to_string_pretty(&document)?);
    std::fs::write(path, content)
        .with_context(|| format!("Failed to write baseline '{}'", path.display()))
}

pub fn contains(fingerprints: &BTreeSet<String>, file: &str, finding: &Finding) -> bool {
    fingerprints.contains(&finding_fingerprint(file, finding))
}
