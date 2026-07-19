use crate::rules::{Finding, Severity};
use colored::*;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Github,
    Compact,
    Sarif,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "tty" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            "github" | "gh" => Ok(OutputFormat::Github),
            "compact" => Ok(OutputFormat::Compact),
            "sarif" => Ok(OutputFormat::Sarif),
            other => Err(format!("unknown format '{}'", other)),
        }
    }
}

#[derive(Serialize)]
struct JsonFinding {
    rule: String,
    severity: String,
    line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<usize>,
    message: String,
    roast: String,
}

#[derive(Serialize)]
struct JsonOutput {
    file: String,
    total: usize,
    errors: usize,
    warnings: usize,
    infos: usize,
    findings: Vec<JsonFinding>,
}

pub fn print_findings(file: &str, findings: &[Finding], format: OutputFormat, no_roast: bool) {
    match format {
        OutputFormat::Terminal => print_terminal(file, findings, no_roast),
        OutputFormat::Json => print_json(file, findings),
        OutputFormat::Github => print_github(file, findings),
        OutputFormat::Compact => print_compact(file, findings),
        OutputFormat::Sarif => {
            unreachable!("SARIF output is handled via print_sarif, not print_findings")
        }
    }
}

fn severity_color(s: &Severity) -> ColoredString {
    match s {
        Severity::Error => "ERROR".red().bold(),
        Severity::Warning => "WARN ".yellow().bold(),
        Severity::Info => "INFO ".cyan(),
    }
}

fn print_terminal(file: &str, findings: &[Finding], no_roast: bool) {
    if findings.is_empty() {
        println!(
            "\n  {} {}\n",
            "✓".green().bold(),
            format!("{} passed with no issues. Impressive restraint.", file).green()
        );
        return;
    }

    println!(
        "\n  {} {}\n",
        "🔥".bold(),
        format!("Roasting {}...", file).bold()
    );

    for f in findings {
        let line_info = if f.line > 0 {
            let location = if f.column > 0 {
                format!("{}:{}:{}", file, f.line, f.column)
            } else {
                format!("{}:{}", file, f.line)
            };
            location.dimmed().to_string()
        } else {
            file.dimmed().to_string()
        };

        println!(
            "  {} [{}]  {}",
            severity_color(&f.severity),
            f.rule.dimmed(),
            f.message.bold()
        );
        println!("  {}      at {}", " ".repeat(5), line_info);
        if !no_roast {
            println!(
                "  {}      {} {}\n",
                " ".repeat(5),
                "💬".dimmed(),
                format!("\"{}\"", f.roast).italic().dimmed()
            );
        } else {
            println!();
        }
    }

    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let infos = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    println!(
        "  {} {} error(s), {} warning(s), {} info(s)",
        "Summary:".bold(),
        errors.to_string().red().bold(),
        warnings.to_string().yellow().bold(),
        infos.to_string().cyan()
    );

    if errors > 0 {
        println!(
            "\n  {} This Dockerfile is a liability. Fix the errors.",
            "💀".bold()
        );
    } else if warnings > 0 {
        println!(
            "\n  {} Could be worse. Could also be much better.",
            "🤔".bold()
        );
    } else {
        println!(
            "\n  {} Only informational findings. You're almost competent.",
            "📝".bold()
        );
    }
    println!();
}

fn print_json(file: &str, findings: &[Finding]) {
    println!(
        "{}",
        serde_json::to_string_pretty(&json_output(file, findings)).unwrap()
    );
}

fn json_output(file: &str, findings: &[Finding]) -> JsonOutput {
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let infos = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();
    JsonOutput {
        file: file.to_string(),
        total: findings.len(),
        errors,
        warnings,
        infos,
        findings: findings
            .iter()
            .map(|f| JsonFinding {
                rule: f.rule.to_string(),
                severity: f.severity.to_string(),
                line: f.line,
                column: (f.column > 0).then_some(f.column),
                end_line: (f.end_line > 0).then_some(f.end_line),
                end_column: (f.end_column > 0).then_some(f.end_column),
                message: f.message.clone(),
                roast: f.roast.clone(),
            })
            .collect(),
    }
}

/// Emit one valid JSON document for a repository scan while preserving the
/// historical object shape for a single Dockerfile.
pub fn print_json_results(results: &[(&str, &[Finding])]) {
    if let [(file, findings)] = results {
        print_json(file, findings);
        return;
    }
    let output = results
        .iter()
        .map(|(file, findings)| json_output(file, findings))
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn print_github(file: &str, findings: &[Finding]) {
    for f in findings {
        let level = match f.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "notice",
        };
        let mut location = if f.line > 0 {
            format!(",line={}", f.line)
        } else {
            String::new()
        };
        if f.column > 0 {
            location.push_str(&format!(",col={}", f.column));
        }
        if f.end_line > 0 {
            location.push_str(&format!(",endLine={}", f.end_line));
        }
        if f.end_column > 0 {
            location.push_str(&format!(",endColumn={}", f.end_column));
        }
        println!(
            "::{} file={}{},title=[{}] {}::{}",
            level, file, location, f.rule, f.message, f.roast
        );
    }
}

fn print_compact(file: &str, findings: &[Finding]) {
    for f in findings {
        let line_info = if f.line > 0 {
            if f.column > 0 {
                format!(":{}:{}", f.line, f.column)
            } else {
                format!(":{}", f.line)
            }
        } else {
            String::new()
        };
        println!(
            "{}{}:{} [{}] {}",
            file, line_info, f.severity, f.rule, f.message
        );
    }
}

/// Emit a SARIF 2.1.0 document covering all linted files at once.
///
/// SARIF is a document format — all files and findings must be collected
/// before emission. Call this once after linting every file, not per-file.
///
/// Compatible with GitHub Advanced Security (`upload-sarif`), VS Code SARIF
/// Viewer, and any tool that consumes the OASIS SARIF 2.1.0 schema.
pub fn print_sarif(results: &[(&str, &[Finding])]) {
    println!("{}", build_sarif(results));
}

fn build_sarif(results: &[(&str, &[Finding])]) -> String {
    let all_rule_meta = crate::rules::all_rules();
    let rule_desc: HashMap<&str, &str> = all_rule_meta
        .iter()
        .map(|r| (r.id, r.description))
        .collect();
    let rule_categories: HashMap<&str, &[&str]> = all_rule_meta
        .iter()
        .map(|rule| (rule.id, rule.categories()))
        .collect();

    // Collect the ordered, deduplicated set of rule IDs that actually fired.
    // Sorted for deterministic output and so ruleIndex values are stable.
    let mut seen_ids = std::collections::BTreeSet::new();
    for (_, findings) in results {
        for f in *findings {
            seen_ids.insert(f.rule.clone());
        }
    }
    let rule_ids: Vec<String> = seen_ids.into_iter().collect();

    // ruleId → index in the rules array (ruleIndex in results must match).
    let rule_index: HashMap<String, usize> = rule_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.clone(), i))
        .collect();

    // Highest severity seen per rule — used for defaultConfiguration.level.
    let mut rule_max_sev: HashMap<String, Severity> = HashMap::new();
    for (_, findings) in results {
        for f in *findings {
            let entry = rule_max_sev.entry(f.rule.clone()).or_insert(Severity::Info);
            if f.severity > *entry {
                *entry = f.severity;
            }
        }
    }

    // Build tool.driver.rules
    let sarif_rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|id| {
            let desc = rule_desc.get(id.as_str()).copied().unwrap_or(id.as_str());
            let level = sarif_level(rule_max_sev.get(id).unwrap_or(&Severity::Info));
            let categories = rule_categories
                .get(id.as_str())
                .copied()
                .unwrap_or_default();
            serde_json::json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": desc },
                "helpUri": "https://github.com/immanuwell/dockerfile-roast",
                "defaultConfiguration": { "level": level },
                "properties": { "tags": categories }
            })
        })
        .collect();

    // Build results array
    let mut sarif_results: Vec<serde_json::Value> = Vec::new();
    for (file, findings) in results {
        let uri = normalize_uri(file);
        for f in *findings {
            let idx = *rule_index.get(&f.rule).unwrap_or(&0);
            let mut result = serde_json::json!({
                "ruleId": f.rule,
                "ruleIndex": idx,
                "level": sarif_level(&f.severity),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                }]
            });
            // region is optional in SARIF; only add when we have a real line number.
            if f.line > 0 {
                result["locations"][0]["physicalLocation"]["region"] =
                    serde_json::json!({ "startLine": f.line });
                if f.column > 0 {
                    result["locations"][0]["physicalLocation"]["region"]["startColumn"] =
                        serde_json::json!(f.column);
                }
                if f.end_line > 0 {
                    result["locations"][0]["physicalLocation"]["region"]["endLine"] =
                        serde_json::json!(f.end_line);
                }
                if f.end_column > 0 {
                    result["locations"][0]["physicalLocation"]["region"]["endColumn"] =
                        serde_json::json!(f.end_column);
                }
            }
            sarif_results.push(result);
        }
    }

    // Artifacts — the list of scanned files (optional but useful for tooling).
    let artifacts: Vec<serde_json::Value> = results
        .iter()
        .map(|(file, _)| {
            serde_json::json!({
                "location": {
                    "uri": normalize_uri(file),
                    "uriBaseId": "%SRCROOT%"
                }
            })
        })
        .collect();

    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "droast",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/immanuwell/dockerfile-roast",
                    "rules": sarif_rules
                }
            },
            "results": sarif_results,
            "artifacts": artifacts
        }]
    });

    serde_json::to_string_pretty(&doc).unwrap()
}

/// Map droast severity to the SARIF level string.
/// SARIF uses "note" for informational findings, not "info".
fn sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

/// Convert a file path to a forward-slash URI relative to the repo root.
/// Absolute paths are made relative by stripping the current working directory.
fn normalize_uri(path: &str) -> String {
    let p = std::path::Path::new(path);
    let relative = if p.is_absolute() {
        std::env::current_dir()
            .ok()
            .and_then(|cwd| p.strip_prefix(&cwd).ok().map(|r| r.to_path_buf()))
            .unwrap_or_else(|| p.to_path_buf())
    } else {
        p.to_path_buf()
    };
    relative.to_string_lossy().replace('\\', "/")
}

pub fn print_summary_header() {
    println!(
        "\n{}",
        r#"
  ██████╗ ██████╗  ██████╗  █████╗ ███████╗████████╗
  ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝
  ██║  ██║██████╔╝██║   ██║███████║███████╗   ██║
  ██║  ██║██╔══██╗██║   ██║██╔══██║╚════██║   ██║
  ██████╔╝██║  ██║╚██████╔╝██║  ██║███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝
  Dockerfile linter with personality
"#
        .bold()
        .red()
    );
}

#[cfg(test)]
mod tests {
    use super::{build_sarif, json_output};
    use crate::rules::{Finding, Severity};

    fn shellcheck_finding() -> Finding {
        Finding {
            rule: "SC2086".into(),
            severity: Severity::Warning,
            line: 4,
            column: 9,
            end_line: 4,
            end_column: 14,
            message: "Double quote to prevent globbing".into(),
            roast: "ShellCheck found a shell-script problem inside this RUN instruction.".into(),
        }
    }

    #[test]
    fn json_and_sarif_preserve_shellcheck_ids_and_ranges() {
        let finding = shellcheck_finding();
        let json = serde_json::to_value(json_output("Dockerfile", &[finding.clone()])).unwrap();
        assert_eq!(json["findings"][0]["rule"], "SC2086");
        assert_eq!(json["findings"][0]["column"], 9);

        let sarif: serde_json::Value =
            serde_json::from_str(&build_sarif(&[("Dockerfile", &[finding])])).unwrap();
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "SC2086");
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startColumn"],
            9
        );
    }
}
