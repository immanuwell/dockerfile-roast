/// Top-level linting orchestration.

use std::path::Path;
use anyhow::{Context, Result};

use crate::parser;
use crate::repository::{self, DockerignoreProblem};
use crate::rules::{self, Finding, Severity};

pub struct LintOptions {
    pub skip_rules: Vec<String>,
    /// When non-empty, only rules whose IDs appear in this list are run.
    pub only_rules: Vec<String>,
    pub min_severity: Severity,
    pub check_dockerignore: bool,
}

pub struct LintResult {
    pub file: String,
    pub findings: Vec<Finding>,
}

/// Lint Dockerfile content that has already been read into a string.
///
/// `filename` is used only for display and for locating `.dockerignore`.
/// Pass `"<stdin>"` when linting content read from standard input.
pub fn lint_content(content: &str, filename: &str, opts: &LintOptions) -> LintResult {
    let mut result = lint_content_without_context(content, filename, opts);
    if opts.check_dockerignore && rule_enabled(opts, "DF033") {
        let context = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let stdin_marker = context.join(".droast-stdin");
        add_dockerignore_finding(&mut result, &stdin_marker, &context, opts);
    }
    result.findings.sort_by(|a, b| a.line.cmp(&b.line).then(b.severity.cmp(&a.severity)));
    result
}

fn lint_content_without_context(content: &str, filename: &str, opts: &LintOptions) -> LintResult {
    let instructions = parser::parse(content);
    let mut findings: Vec<Finding> = Vec::new();

    for rule in rules::all_rules() {
        if !opts.only_rules.is_empty() && !opts.only_rules.iter().any(|s| s.eq_ignore_ascii_case(rule.id)) {
            continue;
        }
        if opts.skip_rules.iter().any(|s| s.eq_ignore_ascii_case(rule.id)) {
            continue;
        }
        let mut rule_findings = (rule.func)(&instructions, content);
        rule_findings.retain(|f| f.severity >= opts.min_severity);
        findings.extend(rule_findings);
    }

    findings.sort_by(|a, b| a.line.cmp(&b.line).then(b.severity.cmp(&a.severity)));

    LintResult { file: filename.to_string(), findings }
}

/// Read `path` from disk and lint it. Thin wrapper around `lint_content`.
pub fn lint_file(path: &Path, opts: &LintOptions) -> Result<LintResult> {
    let context = path.parent().unwrap_or_else(|| Path::new("."));
    lint_file_with_context(path, context, opts)
}

/// Read and lint a Dockerfile using the context selected by Compose, Bake, or
/// repository discovery when resolving its effective `.dockerignore`.
pub fn lint_file_with_context(path: &Path, context: &Path, opts: &LintOptions) -> Result<LintResult> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;
    let mut result = lint_content_without_context(&content, &path.display().to_string(), opts);
    if opts.check_dockerignore && rule_enabled(opts, "DF033") {
        add_dockerignore_finding(&mut result, path, context, opts);
    }
    result.findings.sort_by(|a, b| a.line.cmp(&b.line).then(b.severity.cmp(&a.severity)));
    Ok(result)
}

fn rule_enabled(opts: &LintOptions, id: &str) -> bool {
    (opts.only_rules.is_empty() || opts.only_rules.iter().any(|rule| rule.eq_ignore_ascii_case(id)))
        && !opts.skip_rules.iter().any(|rule| rule.eq_ignore_ascii_case(id))
        && Severity::Info >= opts.min_severity
}

fn add_dockerignore_finding(
    result: &mut LintResult,
    dockerfile: &Path,
    context: &Path,
    opts: &LintOptions,
) {
    if !rule_enabled(opts, "DF033") {
        return;
    }
    let problem = match repository::dockerignore_problem(dockerfile, context) {
        Ok(problem) => problem,
        Err(error) => {
            result.findings.push(Finding {
                rule: "DF033",
                severity: Severity::Info,
                line: 0,
                message: format!("Cannot read the effective .dockerignore: {error}"),
                roast: "The build-context filter is unreadable, so nobody can tell what Docker will receive.".to_string(),
            });
            return;
        }
    };
    let Some(problem) = problem else {
        return;
    };
    let message = match problem {
        DockerignoreProblem::Missing { expected } => format!(
            "No effective .dockerignore for build context '{}' (expected '{}')",
            context.display(),
            expected.display()
        ),
        DockerignoreProblem::Empty { path } => format!(
            "Effective .dockerignore '{}' has no exclusion patterns",
            path.display()
        ),
    };
    result.findings.push(Finding {
        rule: "DF033",
        severity: Severity::Info,
        line: 0,
        message,
        roast: "This build context has no effective exclusions, so caches, repositories, dependencies, and secrets can all join the image-build road trip.".to_string(),
    });
}

pub fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}
