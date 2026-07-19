//! Top-level linting orchestration.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::parser;
use crate::repository::{self, DockerignoreProblem};
use crate::rules::{self, Finding, Severity};
use crate::shellcheck;

pub struct LintOptions {
    pub skip_rules: Vec<String>,
    /// When non-empty, only rules whose IDs appear in this list are run.
    pub only_rules: Vec<String>,
    pub min_severity: Severity,
    pub check_dockerignore: bool,
    pub severity_overrides: BTreeMap<String, Severity>,
    pub categories: Vec<String>,
    pub skip_categories: Vec<String>,
    pub inline_suppressions: bool,
    pub require_suppression_reason: bool,
    pub suppression_reason_pattern: Option<String>,
    pub require_suppression_expiration: bool,
    pub max_suppression_days: Option<u64>,
    pub report_unused_suppressions: bool,
    pub approved_registries: Option<Vec<String>>,
    pub approved_base_images: Option<Vec<String>>,
    pub required_labels: BTreeMap<String, String>,
    pub strict_labels: bool,
    pub shellcheck_mode: shellcheck::Mode,
    pub shellcheck_exclude: Vec<String>,
}

impl Default for LintOptions {
    fn default() -> Self {
        Self {
            skip_rules: Vec::new(),
            only_rules: Vec::new(),
            min_severity: Severity::Info,
            check_dockerignore: true,
            severity_overrides: BTreeMap::new(),
            categories: Vec::new(),
            skip_categories: Vec::new(),
            inline_suppressions: true,
            require_suppression_reason: false,
            suppression_reason_pattern: None,
            require_suppression_expiration: false,
            max_suppression_days: None,
            report_unused_suppressions: false,
            approved_registries: None,
            approved_base_images: None,
            required_labels: BTreeMap::new(),
            strict_labels: false,
            shellcheck_mode: shellcheck::Mode::Off,
            shellcheck_exclude: Vec::new(),
        }
    }
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
    if opts.check_dockerignore && rule_id_enabled(opts, "DF033") {
        let context = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let stdin_marker = context.join(".droast-stdin");
        add_dockerignore_finding(&mut result, &stdin_marker, &context, opts);
    }
    finalize_findings(content, &mut result.findings, opts);
    result
}

fn lint_content_without_context(content: &str, filename: &str, opts: &LintOptions) -> LintResult {
    let instructions = parser::parse(content);
    let mut findings: Vec<Finding> = Vec::new();

    for rule in rules::all_rules() {
        if !rule_enabled(opts, &rule) {
            continue;
        }
        if rule.id == "DF065" && opts.approved_registries.is_some() {
            continue;
        }
        let rule_findings = (rule.func)(&instructions, content);
        findings.extend(rule_findings);
    }

    findings.extend(crate::policy::configured_findings(&instructions, opts));
    if opts.only_rules.is_empty() {
        findings.extend(shellcheck::lint(
            content,
            &instructions,
            opts.shellcheck_mode,
            &opts.shellcheck_exclude,
        ));
    }

    LintResult {
        file: filename.to_string(),
        findings,
    }
}

/// Read `path` from disk and lint it. Thin wrapper around `lint_content`.
pub fn lint_file(path: &Path, opts: &LintOptions) -> Result<LintResult> {
    let context = path.parent().unwrap_or_else(|| Path::new("."));
    lint_file_with_context(path, context, opts)
}

/// Read and lint a Dockerfile using the context selected by Compose, Bake, or
/// repository discovery when resolving its effective `.dockerignore`.
pub fn lint_file_with_context(
    path: &Path,
    context: &Path,
    opts: &LintOptions,
) -> Result<LintResult> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;
    let mut result = lint_content_without_context(&content, &path.display().to_string(), opts);
    if opts.check_dockerignore && rule_id_enabled(opts, "DF033") {
        add_dockerignore_finding(&mut result, path, context, opts);
    }
    finalize_findings(&content, &mut result.findings, opts);
    Ok(result)
}

fn rule_enabled(opts: &LintOptions, rule: &rules::Rule) -> bool {
    let selected_by_id = opts.only_rules.is_empty()
        || opts
            .only_rules
            .iter()
            .any(|selected| selected.eq_ignore_ascii_case(rule.id));
    let selected_by_category = !opts.only_rules.is_empty()
        || opts.categories.is_empty()
        || matches!(rule.id, "DF071" | "DF072")
        || rule.categories().iter().any(|category| {
            opts.categories
                .iter()
                .any(|selected| selected.eq_ignore_ascii_case(category))
        });
    let skipped_by_category = opts.only_rules.is_empty()
        && rule.categories().iter().any(|category| {
            opts.skip_categories
                .iter()
                .any(|skipped| skipped.eq_ignore_ascii_case(category))
        });
    selected_by_id
        && selected_by_category
        && !skipped_by_category
        && !opts
            .skip_rules
            .iter()
            .any(|skipped| skipped.eq_ignore_ascii_case(rule.id))
}

pub(crate) fn rule_id_enabled(opts: &LintOptions, id: &str) -> bool {
    rules::all_rules()
        .iter()
        .find(|rule| rule.id.eq_ignore_ascii_case(id))
        .is_some_and(|rule| rule_enabled(opts, rule))
}

fn finalize_findings(content: &str, findings: &mut Vec<Finding>, opts: &LintOptions) {
    crate::policy::apply_inline_suppressions(content, findings, opts);
    for finding in findings.iter_mut() {
        if let Some(severity) = opts.severity_overrides.get(&finding.rule) {
            finding.severity = *severity;
        }
    }
    findings.retain(|finding| finding.severity >= opts.min_severity);
    findings.sort_by(|a, b| a.line.cmp(&b.line).then(b.severity.cmp(&a.severity)));
}

fn add_dockerignore_finding(
    result: &mut LintResult,
    dockerfile: &Path,
    context: &Path,
    opts: &LintOptions,
) {
    if !rule_id_enabled(opts, "DF033") {
        return;
    }
    let problem = match repository::dockerignore_problem(dockerfile, context) {
        Ok(problem) => problem,
        Err(error) => {
            result.findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF033".into(),
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
        column: 0,
        end_line: 0,
        end_column: 0,
        rule: "DF033".into(),
        severity: Severity::Info,
        line: 0,
        message,
        roast: "This build context has no effective exclusions, so caches, repositories, dependencies, and secrets can all join the image-build road trip.".to_string(),
    });
}

pub fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}
