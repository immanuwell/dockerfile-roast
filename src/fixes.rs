//! Conservative, versioned source edits for mechanically fixable findings.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::TextDiff;

use crate::parser::{
    self, DiagnosticSeverity, Instruction, QuoteStyle, SourcePosition, SourceSpan,
};
use crate::rules::Finding;

pub const FIX_PROTOCOL_VERSION: u32 = 1;
pub const SAFE_FIX_RULES: &[&str] = &["DF076", "DF078", "DF079", "DF083"];

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Applicability {
    Safe,
    Review,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    None,
    Formatting,
    SemanticsPreserving,
    MayInvalidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct FixImpact {
    pub behavioral: Impact,
    pub syntax: Impact,
    pub cache: Impact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct EditPosition {
    pub line: usize,
    pub column: usize,
}

impl From<SourcePosition> for EditPosition {
    fn from(position: SourcePosition) -> Self {
        Self {
            line: position.line,
            column: position.column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TextEdit {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start: EditPosition,
    pub end: EditPosition,
    pub original: String,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PlannedFix {
    pub id: String,
    pub version: u32,
    pub rule: String,
    pub applicability: Applicability,
    pub title: String,
    pub rationale: String,
    pub source_hash: String,
    pub impact: FixImpact,
    pub edits: Vec<TextEdit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FixPlan {
    pub protocol_version: u32,
    pub file: String,
    pub source_hash: String,
    pub fixes: Vec<PlannedFix>,
}

impl FixPlan {
    pub fn edit_count(&self) -> usize {
        self.fixes.iter().map(|fix| fix.edits.len()).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFixes {
    pub content: String,
    pub fix_count: usize,
    pub edit_count: usize,
}

/// Build safe fixes only for findings that were actually reported after policy,
/// severity, and inline-suppression processing.
pub fn plan(
    file: &str,
    source: &str,
    findings: &[Finding],
    selected_rules: &HashSet<String>,
) -> Result<FixPlan> {
    validate_selected_rules(selected_rules)?;
    let source_hash = source_hash(source);
    let document = parser::parse_document(source);
    if let Some(diagnostic) = document
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        bail!(
            "Cannot safely plan fixes for '{}': {} at {}:{} ({})",
            file,
            diagnostic.message,
            diagnostic.span.start.line,
            diagnostic.span.start.column,
            diagnostic.code
        );
    }
    let reported = findings
        .iter()
        .map(|finding| {
            (
                finding.rule.as_str(),
                finding.line,
                finding.column,
                finding.end_line,
                finding.end_column,
            )
        })
        .collect::<HashSet<_>>();
    let casing = instruction_casing(&document.instructions, source);
    let mut fixes = Vec::new();

    for instruction in &document.instructions {
        if rule_selected(selected_rules, "DF076")
            && reported_span(&reported, "DF076", instruction.keyword_span)
        {
            if let Some(uppercase) = casing {
                let original = instruction.keyword_span.text(source);
                let replacement = if uppercase {
                    original.to_ascii_uppercase()
                } else {
                    original.to_ascii_lowercase()
                };
                if replacement != original {
                    fixes.push(single_edit_fix(
                        "DF076/instruction-casing",
                        "DF076",
                        "Normalize instruction keyword casing",
                        "The first consistently cased instruction establishes the file's existing casing convention.",
                        source,
                        source_hash.clone(),
                        instruction.keyword_span,
                        replacement,
                        Impact::Formatting,
                    ));
                }
            }
        }

        if instruction.instruction == "EXPOSE" && rule_selected(selected_rules, "DF078") {
            plan_expose_protocol_fixes(instruction, source, &source_hash, &reported, &mut fixes);
        }

        if instruction.instruction == "FROM" {
            if rule_selected(selected_rules, "DF079") {
                plan_from_as_fix(instruction, source, &source_hash, &reported, &mut fixes);
            }
            if rule_selected(selected_rules, "DF083") {
                plan_redundant_platform_fixes(
                    instruction,
                    source,
                    &source_hash,
                    &reported,
                    &mut fixes,
                );
            }
        }
    }

    fixes.sort_by(|left, right| {
        let left_start = left
            .edits
            .first()
            .map_or(usize::MAX, |edit| edit.start_byte);
        let right_start = right
            .edits
            .first()
            .map_or(usize::MAX, |edit| edit.start_byte);
        left_start.cmp(&right_start).then(left.id.cmp(&right.id))
    });
    validate_fixes(source, &source_hash, &fixes)?;
    Ok(FixPlan {
        protocol_version: FIX_PROTOCOL_VERSION,
        file: file.to_string(),
        source_hash,
        fixes,
    })
}

pub fn apply(source: &str, plan: &FixPlan) -> Result<AppliedFixes> {
    let actual_hash = source_hash(source);
    if actual_hash != plan.source_hash {
        bail!(
            "Refusing to apply stale fixes to '{}': source hash changed",
            plan.file
        );
    }
    validate_fixes(source, &actual_hash, &plan.fixes)?;

    let mut edits = plan
        .fixes
        .iter()
        .filter(|fix| fix.applicability == Applicability::Safe)
        .flat_map(|fix| fix.edits.iter())
        .collect::<Vec<_>>();
    edits.sort_by(|left, right| {
        right
            .start_byte
            .cmp(&left.start_byte)
            .then(right.end_byte.cmp(&left.end_byte))
    });

    let mut content = source.to_string();
    for edit in &edits {
        content.replace_range(edit.start_byte..edit.end_byte, &edit.replacement);
    }
    Ok(AppliedFixes {
        content,
        fix_count: plan
            .fixes
            .iter()
            .filter(|fix| fix.applicability == Applicability::Safe)
            .count(),
        edit_count: edits.len(),
    })
}

/// Apply a plan to a regular file through a same-directory temporary file.
/// The source is checked once while planning and again immediately before the
/// atomic rename, and the original permissions are retained.
pub fn apply_file(path: &Path, plan: &FixPlan) -> Result<AppliedFixes> {
    let metadata = rewrite_metadata(path)?;

    let source =
        fs::read_to_string(path).with_context(|| format!("Failed to read '{}'", path.display()))?;
    let applied = apply(&source, plan)?;
    if applied.edit_count == 0 {
        return Ok(applied);
    }

    let temp_path = temporary_path(path)?;
    let write_result = (|| -> Result<()> {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .with_context(|| format!("Failed to create temporary file for '{}'", path.display()))?;
        temp.set_permissions(metadata.permissions())
            .with_context(|| format!("Failed to preserve permissions for '{}'", path.display()))?;
        temp.write_all(applied.content.as_bytes())
            .with_context(|| format!("Failed to write temporary file for '{}'", path.display()))?;
        temp.sync_all()
            .with_context(|| format!("Failed to flush temporary file for '{}'", path.display()))?;

        let current = fs::read_to_string(path).with_context(|| {
            format!("Failed to re-read '{}' before replacement", path.display())
        })?;
        if source_hash(&current) != plan.source_hash {
            bail!(
                "Refusing to apply stale fixes to '{}': source changed before replacement",
                path.display()
            );
        }
        replace_file(&temp_path, path)
            .with_context(|| format!("Failed to atomically replace '{}'", path.display()))?;
        sync_parent(path);
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result?;
    Ok(applied)
}

/// Refuse targets whose filesystem semantics cannot be preserved by an atomic
/// single-path replacement.
pub fn validate_rewrite_target(path: &Path) -> Result<()> {
    rewrite_metadata(path).map(|_| ())
}

pub fn unified_diff(file: &str, before: &str, after: &str) -> String {
    if before == after {
        return String::new();
    }
    TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{file}"), &format!("b/{file}"))
        .to_string()
}

pub fn source_hash(source: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(source.as_bytes()))
}

fn validate_selected_rules(selected_rules: &HashSet<String>) -> Result<()> {
    for rule in selected_rules {
        if !SAFE_FIX_RULES
            .iter()
            .any(|supported| supported.eq_ignore_ascii_case(rule))
        {
            bail!(
                "Rule '{}' has no safe deterministic fixer; available fixers: {}",
                rule,
                SAFE_FIX_RULES.join(", ")
            );
        }
    }
    Ok(())
}

fn rule_selected(selected_rules: &HashSet<String>, rule: &str) -> bool {
    selected_rules.is_empty()
        || selected_rules
            .iter()
            .any(|selected| selected.eq_ignore_ascii_case(rule))
}

fn reported_span(
    reported: &HashSet<(&str, usize, usize, usize, usize)>,
    rule: &str,
    span: SourceSpan,
) -> bool {
    reported.contains(&(
        rule,
        span.start.line,
        span.start.column,
        span.end.line,
        span.end.column,
    ))
}

fn instruction_casing(instructions: &[Instruction], source: &str) -> Option<bool> {
    instructions.iter().find_map(|instruction| {
        let spelling = instruction.keyword_span.text(source);
        let uppercase = spelling
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
        let lowercase = spelling
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase());
        (uppercase || lowercase).then_some(uppercase)
    })
}

fn plan_expose_protocol_fixes(
    instruction: &Instruction,
    source: &str,
    source_hash: &str,
    reported: &HashSet<(&str, usize, usize, usize, usize)>,
    fixes: &mut Vec<PlannedFix>,
) {
    for word in &instruction.words {
        if !reported_span(reported, "DF078", word.span)
            || word.quote != QuoteStyle::Unquoted
            || word.raw != word.value
        {
            continue;
        }
        let Some(slash) = word.raw.rfind('/') else {
            continue;
        };
        let protocol = &word.raw[slash + 1..];
        if !matches!(protocol.to_ascii_lowercase().as_str(), "tcp" | "udp") {
            continue;
        }
        let start = word.span.start.offset + slash + 1;
        let span = source_span(source, start, word.span.end.offset);
        fixes.push(single_edit_fix(
            "DF078/expose-protocol-casing",
            "DF078",
            "Lowercase the EXPOSE protocol",
            "Docker's supported EXPOSE protocol literals are case-insensitive; normalizing literal TCP or UDP changes only spelling.",
            source,
            source_hash.to_string(),
            span,
            protocol.to_ascii_lowercase(),
            Impact::Formatting,
        ));
    }
}

fn plan_from_as_fix(
    instruction: &Instruction,
    source: &str,
    source_hash: &str,
    reported: &HashSet<(&str, usize, usize, usize, usize)>,
    fixes: &mut Vec<PlannedFix>,
) {
    let from = instruction.keyword_span.text(source);
    let uppercase = from
        .bytes()
        .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
    let lowercase = from
        .bytes()
        .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase());
    if !uppercase && !lowercase {
        return;
    }
    let Some(word) = instruction.words.iter().find(|word| {
        word.value.eq_ignore_ascii_case("as") && reported_span(reported, "DF079", word.span)
    }) else {
        return;
    };
    if !word.raw.eq_ignore_ascii_case("as") {
        return;
    }
    fixes.push(single_edit_fix(
        "DF079/from-as-casing",
        "DF079",
        "Match AS casing to FROM",
        "FROM establishes the instruction's existing casing, and AS is an equivalent case-insensitive keyword.",
        source,
        source_hash.to_string(),
        word.span,
        if uppercase { "AS" } else { "as" }.to_string(),
        Impact::Formatting,
    ));
}

fn plan_redundant_platform_fixes(
    instruction: &Instruction,
    source: &str,
    source_hash: &str,
    reported: &HashSet<(&str, usize, usize, usize, usize)>,
    fixes: &mut Vec<PlannedFix>,
) {
    for flag in &instruction.flags {
        if !reported_span(reported, "DF083", flag.span)
            || !flag.name.eq_ignore_ascii_case("platform")
            || flag.value.as_deref() != Some("$TARGETPLATFORM")
        {
            continue;
        }
        let mut start = flag.span.start.offset;
        while start > instruction.keyword_span.end.offset
            && matches!(source.as_bytes()[start - 1], b' ' | b'\t')
        {
            start -= 1;
        }
        let span = source_span(source, start, flag.span.end.offset);
        fixes.push(single_edit_fix(
            "DF083/redundant-target-platform",
            "DF083",
            "Remove the redundant target platform flag",
            "TARGETPLATFORM is the default platform for FROM, so removing this exact literal flag preserves the selected platform.",
            source,
            source_hash.to_string(),
            span,
            String::new(),
            Impact::SemanticsPreserving,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn single_edit_fix(
    id: &str,
    rule: &str,
    title: &str,
    rationale: &str,
    source: &str,
    source_hash: String,
    span: SourceSpan,
    replacement: String,
    syntax_impact: Impact,
) -> PlannedFix {
    PlannedFix {
        id: id.to_string(),
        version: 1,
        rule: rule.to_string(),
        applicability: Applicability::Safe,
        title: title.to_string(),
        rationale: rationale.to_string(),
        source_hash,
        impact: FixImpact {
            behavioral: Impact::None,
            syntax: syntax_impact,
            cache: Impact::MayInvalidate,
        },
        edits: vec![TextEdit {
            start_byte: span.start.offset,
            end_byte: span.end.offset,
            start: span.start.into(),
            end: span.end.into(),
            original: span.text(source).to_string(),
            replacement,
        }],
    }
}

fn validate_fixes(source: &str, expected_hash: &str, fixes: &[PlannedFix]) -> Result<()> {
    let mut edits = Vec::new();
    for fix in fixes {
        if fix.source_hash != expected_hash {
            bail!("Fix '{}' was planned for a different source hash", fix.id);
        }
        if fix.applicability != Applicability::Safe {
            continue;
        }
        for edit in &fix.edits {
            if edit.start_byte > edit.end_byte
                || edit.end_byte > source.len()
                || !source.is_char_boundary(edit.start_byte)
                || !source.is_char_boundary(edit.end_byte)
            {
                bail!("Fix '{}' contains an invalid UTF-8 byte range", fix.id);
            }
            if source[edit.start_byte..edit.end_byte] != edit.original {
                bail!(
                    "Fix '{}' no longer matches its original source text",
                    fix.id
                );
            }
            edits.push((edit.start_byte, edit.end_byte, fix.id.as_str()));
        }
    }
    edits.sort_by_key(|(start, end, _)| (*start, *end));
    for pair in edits.windows(2) {
        let (left_start, left_end, left_id) = pair[0];
        let (right_start, right_end, right_id) = pair[1];
        if left_end > right_start || (left_start == right_start && left_end == right_end) {
            bail!(
                "Refusing overlapping fixes '{}' and '{}' at bytes {}..{} and {}..{}",
                left_id,
                right_id,
                left_start,
                left_end,
                right_start,
                right_end
            );
        }
    }
    Ok(())
}

fn source_span(source: &str, start: usize, end: usize) -> SourceSpan {
    SourceSpan {
        start: source_position(source, start),
        end: source_position(source, end),
    }
}

fn source_position(source: &str, offset: usize) -> SourcePosition {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rfind('\n')
        .map_or(offset + 1, |newline| offset - newline);
    SourcePosition {
        offset,
        line,
        column,
    }
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!("Cannot create a temporary name for '{}'", path.display())
        })?;
    for _ in 0..100 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{name}.droast-{}-{sequence}.tmp",
            std::process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!(
        "Could not allocate a temporary file beside '{}'",
        path.display()
    )
}

fn rewrite_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!(
            "Refusing to rewrite symlink '{}'; fix the resolved file explicitly",
            path.display()
        );
    }
    if !metadata.file_type().is_file() {
        bail!("Refusing to rewrite non-regular file '{}'", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() > 1 {
            bail!(
                "Refusing to rewrite hard-linked file '{}'; copy or unlink it first",
                path.display()
            );
        }
    }
    Ok(metadata)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(
            replaced_file_name: *const u16,
            replacement_file_name: *const u16,
            backup_file_name: *const u16,
            replace_flags: u32,
            exclude: *mut std::ffi::c_void,
            reserved: *mut std::ffi::c_void,
        ) -> i32;
    }

    const REPLACEFILE_WRITE_THROUGH: u32 = 0x0000_0001;
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replaced = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            source.as_ptr(),
            ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linter::{lint_content, LintOptions};

    fn plan_all(source: &str) -> FixPlan {
        let options = LintOptions {
            check_dockerignore: false,
            ..LintOptions::default()
        };
        let findings = lint_content(source, "Dockerfile", &options).findings;
        plan("Dockerfile", source, &findings, &HashSet::new()).unwrap()
    }

    #[test]
    fn plans_and_applies_only_deterministic_edits() {
        let source = "FROM --platform=$TARGETPLATFORM alpine:3.20 as build\nrun true\nEXPOSE 8080/TCP 5353/UdP\n";
        let plan = plan_all(source);
        assert_eq!(plan.fixes.len(), 5);
        assert!(plan
            .fixes
            .iter()
            .all(|fix| fix.applicability == Applicability::Safe));
        let applied = apply(source, &plan).unwrap();
        assert_eq!(
            applied.content,
            "FROM alpine:3.20 AS build\nRUN true\nEXPOSE 8080/tcp 5353/udp\n"
        );
        assert_eq!(plan_all(&applied.content).edit_count(), 0);
    }

    #[test]
    fn preserves_utf8_crlf_comments_continuations_and_heredocs() {
        let source = "# café\r\nFROM --platform=$TARGETPLATFORM \\\r\n  alpine:3.20 as build\r\nrun <<'EOF'\r\necho FROM AS 8080/TCP\r\nEOF\r\nEXPOSE 8080/TCP # service\r\n";
        let applied = apply(source, &plan_all(source)).unwrap();
        assert!(applied.content.starts_with("# café\r\nFROM \\\r\n"));
        assert!(applied
            .content
            .contains("RUN <<'EOF'\r\necho FROM AS 8080/TCP\r\nEOF\r\n"));
        assert!(applied.content.ends_with("EXPOSE 8080/tcp # service\r\n"));
    }

    #[test]
    fn refuses_stale_and_overlapping_edits() {
        let source = "FROM alpine:3.20 as build\n";
        let plan = plan_all(source);
        let stale = format!("# changed\n{source}");
        assert!(apply(&stale, &plan)
            .unwrap_err()
            .to_string()
            .contains("stale"));

        let mut overlapping = plan.clone();
        let duplicate = overlapping.fixes[0].clone();
        overlapping.fixes.push(duplicate);
        assert!(apply(source, &overlapping)
            .unwrap_err()
            .to_string()
            .contains("overlapping"));
    }

    #[test]
    fn never_applies_review_or_none_fixes() {
        let source = "FROM alpine:3.20 as build\n";
        let mut plan = plan_all(source);
        plan.fixes[0].applicability = Applicability::Review;
        assert_eq!(apply(source, &plan).unwrap().content, source);
        plan.fixes[0].applicability = Applicability::None;
        assert_eq!(apply(source, &plan).unwrap().content, source);
    }

    #[test]
    fn leaves_ambiguous_or_non_literal_tokens_unchanged() {
        let source = "FrOm alpine:3.20 AS build\nExPoSe 8080/$PROTO\n";
        let plan = plan_all(source);
        assert_eq!(plan.edit_count(), 0);
    }

    #[test]
    fn refuses_to_plan_edits_for_a_syntactically_invalid_dockerfile() {
        let source = "FR@M alpine:3.20\nrun true\n";
        let options = LintOptions {
            check_dockerignore: false,
            only_rules: vec!["DF071".to_string(), "DF076".to_string()],
            ..LintOptions::default()
        };
        let findings = lint_content(source, "Dockerfile", &options).findings;
        let error = plan("Dockerfile", source, &findings, &HashSet::new()).unwrap_err();
        assert!(error.to_string().contains("Cannot safely plan fixes"));
        assert!(error.to_string().contains("P004"));
    }

    #[test]
    fn unified_diff_is_stable_and_has_file_headers() {
        let diff = unified_diff("Dockerfile", "run true\n", "RUN true\n");
        assert_eq!(
            diff,
            "--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1 +1 @@\n-run true\n+RUN true\n"
        );
    }

    #[test]
    fn fix_plan_json_round_trips_without_losing_protocol_data() {
        let source = "FROM alpine:3.20 as build";
        let plan = plan_all(source);
        let encoded = serde_json::to_string(&plan).unwrap();
        let decoded: FixPlan = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, plan);
        let applied = apply(source, &decoded).unwrap();
        assert_eq!(applied.content, "FROM alpine:3.20 AS build");
        assert!(parser::parse_document(&applied.content)
            .diagnostics
            .is_empty());
    }
}
