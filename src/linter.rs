/// Top-level linting orchestration.

use std::path::Path;
use anyhow::{Context, Result};

use crate::parser;
use crate::rules::{self, Finding, Severity};

pub struct LintOptions {
    pub skip_rules: Vec<String>,
    pub min_severity: Severity,
    pub check_dockerignore: bool,
}

pub struct LintResult {
    pub file: String,
    pub findings: Vec<Finding>,
}

pub fn lint_file(path: &Path, opts: &LintOptions) -> Result<LintResult> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;

    let instructions = parser::parse(&content);

    let mut findings: Vec<Finding> = Vec::new();

    for rule in rules::all_rules() {
        if opts.skip_rules.iter().any(|s| s.eq_ignore_ascii_case(rule.id)) {
            continue;
        }
        let mut rule_findings = (rule.func)(&instructions, &content);

        // Filter by minimum severity
        rule_findings.retain(|f| f.severity >= opts.min_severity);

        findings.extend(rule_findings);
    }

    // Check for .dockerignore if requested
    if opts.check_dockerignore {
        let dir = path.parent().unwrap_or(Path::new("."));
        let di_path = dir.join(".dockerignore");
        if !di_path.exists() {
            if Severity::Info >= opts.min_severity {
                findings.push(Finding {
                    rule: "DF033",
                    severity: Severity::Info,
                    line: 0,
                    message: "No .dockerignore file found in the same directory".to_string(),
                    roast: "No .dockerignore? You're COPY-ing your entire build context including \
                            node_modules, .git, test fixtures, and possibly your diary. \
                            A .dockerignore takes 5 minutes to write and saves you from \
                            shipping your secrets to production.".to_string(),
                });
            }
        }
    }

    // Sort by line number, then severity
    findings.sort_by(|a, b| {
        a.line.cmp(&b.line)
            .then(b.severity.cmp(&a.severity))
    });

    Ok(LintResult {
        file: path.display().to_string(),
        findings,
    })
}

pub fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}
