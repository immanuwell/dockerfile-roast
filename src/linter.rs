//! Top-level linting orchestration.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::fixes::{self, FixPlan};
use crate::parser;
use crate::repository::{self, ContainerEngine, DockerignoreProblem};
use crate::rules::{self, Finding, Severity};
use crate::shellcheck;

pub struct LintOptions {
    pub skip_rules: Vec<String>,
    /// When non-empty, only rules whose IDs appear in this list are run.
    pub only_rules: Vec<String>,
    pub min_severity: Severity,
    pub check_dockerignore: bool,
    pub engine: ContainerEngine,
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
    pub plan_fixes: bool,
}

impl Default for LintOptions {
    fn default() -> Self {
        Self {
            skip_rules: Vec::new(),
            only_rules: Vec::new(),
            min_severity: Severity::Info,
            check_dockerignore: true,
            engine: ContainerEngine::Docker,
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
            plan_fixes: false,
        }
    }
}

pub struct LintResult {
    pub file: String,
    pub findings: Vec<Finding>,
    /// Safe, deterministic fixes associated with the finalized findings.
    pub fix_plan: Option<FixPlan>,
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
        add_ignorefile_finding(&mut result, &stdin_marker, &context, opts);
    }
    finalize_findings(content, &mut result.findings, opts);
    if opts.plan_fixes {
        result.fix_plan = fixes::plan(
            filename,
            content,
            &result.findings,
            &std::collections::HashSet::new(),
        )
        .ok();
    }
    result
}

fn lint_content_without_context(content: &str, filename: &str, opts: &LintOptions) -> LintResult {
    let instructions = parser::parse(content);
    let mut findings: Vec<Finding> = Vec::new();

    for rule in rules::all_rules() {
        if !rule_enabled(opts, &rule) {
            continue;
        }
        // DF065 is an organization policy, not a universal registry opinion.
        // policy::configured_findings emits it only when approved-registries
        // has been explicitly configured.
        if rule.id == "DF065" {
            continue;
        }
        let rule_findings = (rule.func)(&instructions, content);
        findings.extend(rule_findings);
    }

    findings.extend(crate::policy::configured_findings(&instructions, opts));
    findings.extend(podman_workflow_findings(filename, opts));
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
        fix_plan: None,
    }
}

fn podman_workflow_findings(filename: &str, opts: &LintOptions) -> Vec<Finding> {
    if opts.engine != ContainerEngine::Podman || !rule_id_enabled(opts, "DF075") {
        return Vec::new();
    }
    let is_preprocessed = Path::new(filename)
        .file_name()
        .is_some_and(|name| name == "Containerfile.in");
    if !is_preprocessed {
        return Vec::new();
    }
    vec![Finding {
        rule: "DF075".into(),
        severity: Severity::Info,
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 1,
        message: "Containerfile.in is preprocessed by Podman with CPP; lint the generated Containerfile too".into(),
        roast: "CPP gets the last word here. Make sure the file Podman actually builds gets roasted too.".into(),
    }]
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
        add_ignorefile_finding(&mut result, path, context, opts);
    }
    if rule_id_enabled(opts, "DF077") {
        add_copy_ignored_findings(&mut result, path, context, opts);
    }
    if rule_id_enabled(opts, "DF007") {
        contextualize_copy_all_findings(&mut result, path, context, opts);
    }
    finalize_findings(&content, &mut result.findings, opts);
    if opts.plan_fixes {
        result.fix_plan = fixes::plan(
            &result.file,
            &content,
            &result.findings,
            &std::collections::HashSet::new(),
        )
        .ok();
    }
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
    let document = parser::parse_document(content);
    for finding in findings
        .iter_mut()
        .filter(|finding| finding.line > 0 && finding.column == 0)
    {
        if let Some(instruction) = document
            .instructions
            .iter()
            .find(|instruction| instruction.line == finding.line)
        {
            finding.column = instruction.span.start.column;
            finding.end_line = instruction.span.end.line;
            finding.end_column = instruction.span.end.column;
        }
    }
    crate::policy::apply_inline_suppressions(content, findings, opts);
    for finding in findings.iter_mut() {
        if let Some(severity) = opts.severity_overrides.get(&finding.rule) {
            finding.severity = *severity;
        }
    }
    findings.retain(|finding| finding.severity >= opts.min_severity);
    findings.sort_by(|a, b| a.line.cmp(&b.line).then(b.severity.cmp(&a.severity)));
}

fn add_ignorefile_finding(
    result: &mut LintResult,
    dockerfile: &Path,
    context: &Path,
    opts: &LintOptions,
) {
    if !rule_id_enabled(opts, "DF033") {
        return;
    }
    let problem = match repository::ignorefile_problem_for_engine(dockerfile, context, opts.engine)
    {
        Ok(problem) => problem,
        Err(error) => {
            result.findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF033".into(),
                severity: Severity::Info,
                line: 0,
                message: format!("Cannot read the effective build-context ignore file: {error}"),
                roast: "The build-context filter is unreadable, so nobody can tell what the image build will receive.".to_string(),
            });
            return;
        }
    };
    let Some(problem) = problem else {
        return;
    };
    let message = match problem {
        DockerignoreProblem::Missing { expected } => format!(
            "No effective build-context ignore file for '{}' (expected '{}')",
            context.display(),
            expected.display()
        ),
        DockerignoreProblem::Empty { path } => format!(
            "Effective build-context ignore file '{}' has no exclusion patterns",
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

fn add_copy_ignored_findings(
    result: &mut LintResult,
    dockerfile: &Path,
    context: &Path,
    opts: &LintOptions,
) {
    let ignored = match repository::ignored_copy_sources(dockerfile, context, opts.engine) {
        Ok(ignored) => ignored,
        Err(_) => return,
    };
    for (line, source) in ignored {
        result.findings.push(Finding {
            rule: "DF077".into(), severity: Severity::Error, line, column: 0, end_line: 0, end_column: 0,
            message: format!("{} source '{}' is excluded by the effective build-context ignore file", "COPY/ADD", source),
            roast: "That source is ignored before the build starts. Docker cannot copy a file it never received.".into(),
        });
    }
}

fn contextualize_copy_all_findings(
    result: &mut LintResult,
    dockerfile: &Path,
    context: &Path,
    opts: &LintOptions,
) {
    if !repository::ignores_common_copy_all_hazards(dockerfile, context, opts.engine)
        .unwrap_or(false)
    {
        return;
    }
    for finding in result
        .findings
        .iter_mut()
        .filter(|finding| finding.rule == "DF007")
    {
        finding.message =
            "COPY . uses a protected build context but still broadens cache invalidation".into();
        finding.roast = "Your ignore file keeps .git, node_modules, .env, and dist out of the build context. Nice. COPY . still makes every included file part of this layer's cache key, so prefer explicit copies when practical.".into();
    }
}

pub fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}
