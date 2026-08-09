//! Optional bridge to an installed ShellCheck executable.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context};
use serde::Deserialize;

use crate::parser::{Heredoc, Instruction, InstructionForm, SourcePosition};
use crate::rules::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Auto,
    Required,
}

impl Mode {
    pub fn parse(value: Option<&str>) -> anyhow::Result<Self> {
        match value.unwrap_or("off").to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "auto" => Ok(Self::Auto),
            "required" => Ok(Self::Required),
            value => bail!("Unknown ShellCheck mode '{value}'; expected off, auto, or required"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Diagnostic {
    line: usize,
    #[serde(default)]
    end_line: usize,
    column: usize,
    #[serde(default)]
    end_column: usize,
    level: String,
    code: u64,
    message: String,
}

struct Script {
    source: String,
    line_starts: Vec<SourcePosition>,
    dialect: &'static str,
    preamble_lines: usize,
}

#[derive(Clone, Copy)]
struct ShellBehavior {
    dialect: Option<&'static str>,
    busybox_extensions: bool,
}

impl Default for ShellBehavior {
    fn default() -> Self {
        Self {
            dialect: Some("sh"),
            busybox_extensions: false,
        }
    }
}

/// Lint every shell-form RUN independently, matching Docker's one-shell-per-RUN
/// execution model. `auto` skips cleanly when ShellCheck is not installed.
pub fn lint(
    content: &str,
    instructions: &[Instruction],
    mode: Mode,
    exclude: &[String],
) -> Vec<Finding> {
    if mode == Mode::Off {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let mut shell = ShellBehavior::default();
    let mut stage_shells = HashMap::<String, ShellBehavior>::new();
    let mut stage_environment = HashMap::<String, HashSet<String>>::new();
    let mut environment = HashSet::new();
    let mut current_stage_alias = None;
    for instruction in instructions {
        if instruction.instruction == "FROM" {
            environment = from_stage_environment(instruction, &stage_environment);
            shell = from_stage_shell(instruction, &stage_shells);
            current_stage_alias = from_alias(instruction);
            if let Some(alias) = &current_stage_alias {
                stage_environment.insert(alias.clone(), environment.clone());
                stage_shells.insert(alias.clone(), shell);
            }
            continue;
        }
        if matches!(instruction.instruction.as_str(), "ENV" | "ARG") {
            environment.extend(declared_names(instruction));
            if let Some(alias) = &current_stage_alias {
                stage_environment.insert(alias.clone(), environment.clone());
            }
            continue;
        }
        if instruction.instruction == "SHELL" {
            shell = shell_behavior(instruction, shell.busybox_extensions);
            if let Some(alias) = &current_stage_alias {
                stage_shells.insert(alias.clone(), shell);
            }
            continue;
        }
        if instruction.instruction != "RUN" || !matches!(instruction.form, InstructionForm::Shell) {
            continue;
        }
        let Some(dialect) = shell.dialect else {
            continue;
        };
        for script in scripts_for_run(content, instruction, dialect, &environment) {
            match run(&script, exclude) {
                Ok(mut shellcheck_findings) => {
                    shellcheck_findings.retain(|finding| {
                        shellcheck_finding_applies(finding, shell.busybox_extensions)
                    });
                    findings.append(&mut shellcheck_findings);
                }
                Err(error) if mode == Mode::Auto && is_not_found(&error) => return findings,
                Err(error) => findings.push(bridge_error(instruction.line, error)),
            }
        }
    }
    findings
}

fn shell_dialect(instruction: &Instruction) -> Option<&'static str> {
    let InstructionForm::Json(command) = &instruction.form else {
        return None;
    };
    let executable = command.first()?.rsplit('/').next()?.to_ascii_lowercase();
    match executable.as_str() {
        "sh" | "ash" => Some("sh"),
        "bash" => Some("bash"),
        "dash" => Some("dash"),
        "ksh" => Some("ksh"),
        // PowerShell and cmd use incompatible syntax. Do not feed them to a
        // POSIX analyzer and manufacture misleading diagnostics.
        _ => None,
    }
}

fn shell_behavior(instruction: &Instruction, inherited_busybox: bool) -> ShellBehavior {
    let dialect = shell_dialect(instruction);
    let executable = match &instruction.form {
        InstructionForm::Json(command) => command
            .first()
            .and_then(|value| value.rsplit(['/', '\\']).next())
            .unwrap_or_default()
            .to_ascii_lowercase(),
        _ => String::new(),
    };
    ShellBehavior {
        dialect,
        busybox_extensions: executable == "ash" || executable == "sh" && inherited_busybox,
    }
}

fn from_alias(instruction: &Instruction) -> Option<String> {
    let mut tokens = instruction
        .arguments
        .split_whitespace()
        .filter(|token| !token.starts_with("--"));
    tokens.next()?;
    (tokens.next()?.eq_ignore_ascii_case("as"))
        .then(|| tokens.next().map(str::to_ascii_lowercase))
        .flatten()
}

fn from_stage_environment(
    instruction: &Instruction,
    stage_environment: &HashMap<String, HashSet<String>>,
) -> HashSet<String> {
    let image = instruction
        .arguments
        .split_whitespace()
        .find(|token| !token.starts_with("--"));
    image
        .and_then(|image| stage_environment.get(&image.to_ascii_lowercase()))
        .cloned()
        .unwrap_or_default()
}

fn from_stage_shell(
    instruction: &Instruction,
    stage_shells: &HashMap<String, ShellBehavior>,
) -> ShellBehavior {
    let image = instruction
        .arguments
        .split_whitespace()
        .find(|token| !token.starts_with("--"))
        .unwrap_or_default();
    if let Some(shell) = stage_shells.get(&image.to_ascii_lowercase()) {
        return *shell;
    }
    let without_digest = image.split('@').next().unwrap_or(image);
    let last_slash = without_digest.rfind('/');
    let repository = without_digest.rfind(':').map_or(without_digest, |colon| {
        if last_slash.is_none_or(|slash| colon > slash) {
            &without_digest[..colon]
        } else {
            without_digest
        }
    });
    let image_name = repository.rsplit('/').next().unwrap_or(repository);
    ShellBehavior {
        dialect: Some("sh"),
        busybox_extensions: matches!(
            image_name.to_ascii_lowercase().as_str(),
            "alpine" | "busybox"
        ),
    }
}

fn shellcheck_finding_applies(finding: &Finding, busybox_extensions: bool) -> bool {
    !busybox_extensions || !matches!(finding.rule.as_str(), "SC3010" | "SC3020" | "SC3060")
}

fn declared_names(instruction: &Instruction) -> Vec<String> {
    let words = &instruction.words;
    let Some(first) = words.first() else {
        return Vec::new();
    };
    if first.value.contains('=') {
        return words
            .iter()
            .filter_map(|word| word.value.split_once('=').map(|(name, _)| name))
            .filter(|name| is_shell_name(name))
            .map(str::to_string)
            .collect();
    }
    if is_shell_name(&first.value) {
        vec![first.value.clone()]
    } else {
        Vec::new()
    }
}

fn is_shell_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some(character) if character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn scripts_for_run(
    content: &str,
    instruction: &Instruction,
    dialect: &'static str,
    environment: &HashSet<String>,
) -> Vec<Script> {
    // `RUN <<EOF` is BuildKit's script-heredoc form. ShellCheck must receive
    // the body itself, not the header, which would otherwise be an incomplete
    // redirection with no command.
    if is_script_heredoc(content, instruction) {
        let heredoc = &instruction.heredocs[0];
        return (!heredoc.content.is_empty())
            .then(|| Script {
                source: script_source(&heredoc.content, environment),
                line_starts: heredoc_line_starts(content, heredoc),
                dialect,
                preamble_lines: environment.len(),
            })
            .into_iter()
            .collect();
    }

    let mut start = instruction
        .flags
        .last()
        .map(|flag| flag.span.end.offset)
        .unwrap_or(instruction.keyword_span.end.offset);
    while let Some(character) = content[start..instruction.span.end.offset].chars().next() {
        if !character.is_whitespace() {
            break;
        }
        start += character.len_utf8();
    }
    (start < instruction.span.end.offset)
        .then(|| {
            let (source, line_starts) =
                logical_shell_source(content, start, instruction.span.end.offset);
            Script {
                source: script_source(&source, environment),
                line_starts,
                dialect,
                preamble_lines: environment.len(),
            }
        })
        .into_iter()
        .collect()
}

/// Docker permits comment-only lines between escaped continuation lines.  The
/// comment is Dockerfile syntax, not part of the logical shell command; sending
/// it to ShellCheck changes the meaning of the preceding backslash and causes
/// a cascade of parser diagnostics.  Drop only those continuation comments and
/// retain a source-start entry for every emitted logical line.
fn logical_shell_source(content: &str, start: usize, end: usize) -> (String, Vec<SourcePosition>) {
    let mut source = String::new();
    let mut starts = Vec::new();
    let mut offset = start;
    for line in content[start..end].split_inclusive('\n') {
        let comment = line.trim_start().starts_with('#');
        if !comment {
            starts.push(position_at(content, offset));
            source.push_str(line);
        }
        offset += line.len();
    }
    (source, starts)
}

fn script_source(source: &str, environment: &HashSet<String>) -> String {
    let mut names = environment.iter().collect::<Vec<_>>();
    names.sort_unstable();
    names
        .into_iter()
        .map(|name| format!("export {name}\n"))
        .collect::<String>()
        + source
}

fn is_script_heredoc(content: &str, instruction: &Instruction) -> bool {
    let Some(marker) = instruction
        .heredocs
        .first()
        .map(|heredoc| heredoc.marker_span)
    else {
        return false;
    };
    content[marker.end.offset..instruction.arguments_span.end.offset]
        .trim()
        .is_empty()
}

fn heredoc_line_starts(content: &str, heredoc: &Heredoc) -> Vec<SourcePosition> {
    let raw = heredoc.content_span.text(content);
    let mut offset = heredoc.content_span.start.offset;
    raw.split_inclusive('\n')
        .map(|line| {
            let stripped_tabs = heredoc
                .strip_tabs
                .then(|| line.bytes().take_while(|byte| *byte == b'\t').count())
                .unwrap_or(0);
            let start = position_at(content, offset + stripped_tabs);
            offset += line.len();
            start
        })
        .collect()
}

#[cfg(test)]
fn source_line_starts(content: &str, start: usize, end: usize) -> Vec<SourcePosition> {
    let mut offset = start;
    content[start..end]
        .split_inclusive('\n')
        .map(|line| {
            let line_start = position_at(content, offset);
            offset += line.len();
            line_start
        })
        .collect()
}

fn position_at(source: &str, offset: usize) -> SourcePosition {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix.rsplit('\n').next().unwrap_or_default().len() + 1;
    SourcePosition {
        offset,
        line,
        column,
    }
}

fn run(script: &Script, exclude: &[String]) -> anyhow::Result<Vec<Finding>> {
    let mut child = Command::new("shellcheck")
        .args(["--format=json", "--shell", script.dialect])
        .args(exclude.iter().map(|code| format!("--exclude={code}")))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Cannot start ShellCheck")?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(script.source.as_bytes())?;
    let output = child
        .wait_with_output()
        .context("Cannot read ShellCheck output")?;
    if !output.status.success() && output.status.code() != Some(1) {
        bail!(
            "ShellCheck failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let diagnostics: Vec<Diagnostic> =
        serde_json::from_slice(&output.stdout).context("ShellCheck returned invalid JSON")?;
    Ok(diagnostics
        .into_iter()
        // `chmod =2775 path` is a valid symbolic chmod mode meaning "set
        // exactly these bits". ShellCheck mistakes it for a shell assignment.
        .filter(|diagnostic| {
            diagnostic.code != 2283
                || !script.source.lines().any(|line| {
                    let words = line.split_whitespace().collect::<Vec<_>>();
                    words.first() == Some(&"chmod")
                        && words.get(1).is_some_and(|mode| {
                            mode.starts_with('=')
                                && mode[1..]
                                    .chars()
                                    .all(|character| character.is_ascii_digit())
                        })
                })
        })
        .filter_map(|diagnostic| {
            (diagnostic.line > script.preamble_lines)
                .then(|| map_diagnostic(diagnostic, &script.line_starts, script.preamble_lines))
        })
        .collect())
}

fn map_diagnostic(
    diagnostic: Diagnostic,
    line_starts: &[SourcePosition],
    preamble_lines: usize,
) -> Finding {
    let shell_line = diagnostic.line.saturating_sub(preamble_lines);
    let (line, column) = map_position(line_starts, shell_line, diagnostic.column);
    let end_source_line = diagnostic
        .end_line
        .max(diagnostic.line)
        .saturating_sub(preamble_lines);
    let (end_line, end_column) = map_position(
        line_starts,
        end_source_line,
        diagnostic.end_column.max(diagnostic.column),
    );
    Finding {
        rule: format!("SC{:04}", diagnostic.code),
        severity: match diagnostic.level.as_str() {
            "error" => Severity::Error,
            "warning" => Severity::Warning,
            _ => Severity::Info,
        },
        line,
        column,
        end_line,
        end_column,
        message: diagnostic.message,
        roast: "ShellCheck found a shell-script problem inside this RUN instruction.".to_string(),
    }
}

fn map_position(
    line_starts: &[SourcePosition],
    shell_line: usize,
    shell_column: usize,
) -> (usize, usize) {
    let start = line_starts
        .get(shell_line.saturating_sub(1))
        .copied()
        .or_else(|| line_starts.last().copied())
        .unwrap_or(SourcePosition {
            offset: 0,
            line: 0,
            column: 0,
        });
    (start.line, start.column + shell_column.saturating_sub(1))
}

fn bridge_error(line: usize, error: anyhow::Error) -> Finding {
    Finding {
        rule: "SC0000".into(),
        severity: Severity::Error,
        line,
        column: 0,
        end_line: 0,
        end_column: 0,
        message: format!("ShellCheck integration failed: {error:#}"),
        roast: "ShellCheck was required, but the shell-analysis sidecar could not run.".to_string(),
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        declared_names, from_stage_shell, heredoc_line_starts, map_diagnostic, script_source,
        scripts_for_run, shell_dialect, shellcheck_finding_applies, source_line_starts, Diagnostic,
    };
    use crate::parser::parse;
    use crate::rules::{Finding, Severity};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn filters_only_known_busybox_extension_diagnostics() {
        let finding = |rule: &str| Finding {
            rule: rule.into(),
            severity: Severity::Warning,
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 2,
            message: String::new(),
            roast: String::new(),
        };
        for rule in ["SC3010", "SC3020", "SC3060"] {
            assert!(!shellcheck_finding_applies(&finding(rule), true));
            assert!(shellcheck_finding_applies(&finding(rule), false));
        }
        assert!(shellcheck_finding_applies(&finding("SC2086"), true));
    }

    #[test]
    fn recognizes_busybox_base_and_named_stage_inheritance() {
        let instructions =
            parse("FROM alpine:3.21 AS base\nFROM base AS inherited\nFROM ubuntu:24.04 AS posix\n");
        let direct = from_stage_shell(&instructions[0], &HashMap::new());
        assert!(direct.busybox_extensions);

        let inherited = from_stage_shell(
            &instructions[1],
            &HashMap::from([("base".to_string(), direct)]),
        );
        assert!(inherited.busybox_extensions);
        assert!(!from_stage_shell(&instructions[2], &HashMap::new()).busybox_extensions);
    }

    #[test]
    fn maps_shellcheck_ranges_to_dockerfile_source_positions() {
        let source = "FROM alpine\nRUN echo $name\n";
        let finding = map_diagnostic(
            Diagnostic {
                line: 1,
                end_line: 1,
                column: 6,
                end_column: 11,
                level: "warning".into(),
                code: 2086,
                message: "Double quote to prevent globbing".into(),
            },
            &source_line_starts(source, 16, source.len() - 1),
            0,
        );
        assert_eq!(finding.rule, "SC2086");
        assert_eq!((finding.line, finding.column), (2, 10));
        assert_eq!((finding.end_line, finding.end_column), (2, 15));
    }

    #[test]
    fn preserves_source_columns_for_tab_stripped_heredocs() {
        let source = "FROM alpine\nRUN <<-SCRIPT\n\techo $name\nSCRIPT\n";
        let instruction = &parse(source)[1];
        let scripts = scripts_for_run(source, instruction, "sh", &HashSet::new());
        assert_eq!(scripts[0].source, "echo $name\n");
        let starts = heredoc_line_starts(source, &instruction.heredocs[0]);
        let finding = map_diagnostic(
            Diagnostic {
                line: 1,
                end_line: 1,
                column: 6,
                end_column: 11,
                level: "warning".into(),
                code: 2086,
                message: "Double quote to prevent globbing".into(),
            },
            &starts,
            0,
        );
        assert_eq!((finding.line, finding.column), (3, 7));
        assert_eq!((finding.end_line, finding.end_column), (3, 12));
    }

    #[test]
    fn extracts_run_commands_after_buildkit_flags_and_continuations() {
        let source =
            "FROM alpine\nRUN --mount=type=cache,target=/cache echo one && \\\n  echo $name\n";
        let instruction = &parse(source)[1];
        let scripts = scripts_for_run(source, instruction, "sh", &HashSet::new());
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].source, "echo one && \\\n  echo $name");
        assert_eq!(
            scripts[0]
                .line_starts
                .iter()
                .map(|position| (position.line, position.column))
                .collect::<Vec<_>>(),
            [(2, 38), (3, 1)]
        );
        let finding = map_diagnostic(
            Diagnostic {
                line: 2,
                end_line: 2,
                column: 3,
                end_column: 8,
                level: "warning".into(),
                code: 2086,
                message: "Double quote to prevent globbing".into(),
            },
            &scripts[0].line_starts,
            0,
        );
        assert_eq!((finding.line, finding.column), (3, 3));
    }

    #[test]
    fn omits_docker_continuation_comments_before_shellcheck() {
        let source = "FROM alpine\nRUN echo one \\\n  # Dockerfile-only continuation comment\n  && echo $name\n";
        let instruction = &parse(source)[1];
        let scripts = scripts_for_run(source, instruction, "sh", &HashSet::new());
        assert_eq!(scripts[0].source, "echo one \\\n  && echo $name");
        assert_eq!(scripts[0].line_starts[1].line, 4);
    }

    #[test]
    fn keeps_command_attached_heredocs_as_shell_source() {
        let source = "FROM alpine\nRUN <<EOF cat > /message\nhello\nEOF\n";
        let instruction = &parse(source)[1];
        let scripts = scripts_for_run(source, instruction, "sh", &HashSet::new());
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].source, "<<EOF cat > /message\nhello\nEOF");
    }

    #[test]
    fn recognizes_posix_shells_and_skips_non_posix_shells() {
        let source = "SHELL [\"/bin/bash\", \"-c\"]\nSHELL [\"powershell\", \"-command\"]\n";
        let instructions = parse(source);
        assert_eq!(shell_dialect(&instructions[0]), Some("bash"));
        assert_eq!(shell_dialect(&instructions[1]), None);
    }

    #[test]
    fn env_declarations_are_exported_without_changing_source_positions() {
        let instructions = parse("ENV FIRST=one SECOND=two\nENV THIRD three\n");
        assert_eq!(declared_names(&instructions[0]), ["FIRST", "SECOND"]);
        assert_eq!(declared_names(&instructions[1]), ["THIRD"]);

        let environment = HashSet::from(["SECOND".to_string(), "FIRST".to_string()]);
        assert_eq!(
            script_source("echo \"$FIRST\"\n", &environment),
            "export FIRST\nexport SECOND\necho \"$FIRST\"\n"
        );
        let finding = map_diagnostic(
            Diagnostic {
                line: 3,
                end_line: 3,
                column: 7,
                end_column: 13,
                level: "warning".into(),
                code: 2154,
                message: "FIRST is referenced but not assigned.".into(),
            },
            &source_line_starts("RUN echo \"$FIRST\"\n", 4, 18),
            2,
        );
        assert_eq!((finding.line, finding.column), (1, 11));
    }
}
