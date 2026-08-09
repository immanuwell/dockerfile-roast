use dockerfile_roast::parser::{parse_document, DiagnosticSeverity, InstructionForm, QuoteStyle};

fn diagnostic_codes(source: &str) -> Vec<&'static str> {
    parse_document(source)
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

#[test]
fn parser_directives_are_structured_and_control_the_escape_token() {
    let source = "# syntax=docker/dockerfile:1.18\n# escape=`\n# check=skip=JSONArgsRecommended\nFROM scratch\n";
    let document = parse_document(source);

    assert_eq!(document.escape, '`');
    assert_eq!(document.directives.len(), 3);
    assert_eq!(document.directives[0].name, "syntax");
    assert_eq!(document.directives[0].value, "docker/dockerfile:1.18");
    assert_eq!(
        document.directives[0].span.text(source),
        "# syntax=docker/dockerfile:1.18"
    );
    assert!(document.diagnostics.is_empty());
}

#[test]
fn spans_recover_exact_crlf_source_across_continuations() {
    let source = "FROM alpine:3.20\r\nRUN echo one \\\r\n    && echo two\r\n";
    let document = parse_document(source);
    let run = &document.instructions[1];

    assert_eq!(run.span.start.line, 2);
    assert_eq!(run.span.start.column, 1);
    assert_eq!(run.span.end.line, 3);
    assert_eq!(run.keyword_span.text(source), "RUN");
    assert_eq!(run.span.text(source), "RUN echo one \\\r\n    && echo two");
    assert_eq!(run.logical_arguments, "echo one     && echo two");
}

#[test]
fn arbitrary_buildkit_flags_are_structured_without_hiding_the_command() {
    let source = "# syntax=docker/dockerfile:1-labs\nFROM --platform=$BUILDPLATFORM alpine:3.20 AS build\nRUN --mount=type=cache,target=/root/.cache --network=none --security=insecure --device=vendor.com/device echo ok\nCOPY --link --parents --exclude=*.md --chmod=0755 --chown=1:1 /src /dst\n";
    let document = parse_document(source);

    let run = &document.instructions[1];
    assert_eq!(
        run.flags
            .iter()
            .map(|flag| flag.name.as_str())
            .collect::<Vec<_>>(),
        ["mount", "network", "security", "device"]
    );
    assert_eq!(run.command, "echo ok");
    assert_eq!(
        run.flags[0].value.as_deref(),
        Some("type=cache,target=/root/.cache")
    );

    let copy = &document.instructions[2];
    assert_eq!(
        copy.flags
            .iter()
            .map(|flag| flag.name.as_str())
            .collect::<Vec<_>>(),
        ["link", "parents", "exclude", "chmod", "chown"]
    );
    assert_eq!(copy.command, "/src /dst");
}

#[test]
fn heredocs_retain_content_metadata_and_exact_spans() {
    let source = "FROM alpine:3.20\nRUN 3<<'SCRIPT' cat && <<-DATA cat\necho $NOT_EXPANDED\nSCRIPT\n\tunicode: café 🔥\n\tDATA\nCMD [\"sh\"]\n";
    let document = parse_document(source);
    let run = &document.instructions[1];

    assert_eq!(run.heredocs.len(), 2);
    assert_eq!(run.heredocs[0].delimiter, "SCRIPT");
    assert_eq!(run.heredocs[0].file_descriptor, Some(3));
    assert!(!run.heredocs[0].expand);
    assert_eq!(run.heredocs[0].content, "echo $NOT_EXPANDED\n");
    assert_eq!(run.heredocs[0].marker_span.text(source), "3<<'SCRIPT'");
    assert_eq!(
        run.heredocs[0]
            .terminator_span
            .expect("terminator")
            .text(source),
        "SCRIPT"
    );

    assert_eq!(run.heredocs[1].delimiter, "DATA");
    assert!(run.heredocs[1].strip_tabs);
    assert!(run.heredocs[1].expand);
    assert_eq!(run.heredocs[1].content, "unicode: café 🔥\n");
    assert_eq!(run.span.end.line, 6);
    assert_eq!(document.instructions[2].line, 7);
}

#[test]
fn copy_and_onbuild_heredocs_consume_their_bodies() {
    let source = "FROM scratch\nCOPY <<EOF /message\nFROM is data\nEOF\nONBUILD RUN <<SCRIPT\necho later\nSCRIPT\nCMD [\"/message\"]\n";
    let document = parse_document(source);

    assert_eq!(
        document
            .instructions
            .iter()
            .map(|instruction| instruction.instruction.as_str())
            .collect::<Vec<_>>(),
        ["FROM", "COPY", "ONBUILD", "CMD"]
    );
    assert_eq!(
        document.instructions[1].heredocs[0].content,
        "FROM is data\n"
    );
    assert_eq!(document.instructions[2].heredocs[0].content, "echo later\n");
}

#[test]
fn json_and_shell_forms_are_distinguished_and_validated() {
    let source = "FROM scratch\nRUN [\"echo\", \"hello\"]\nCMD echo hello\nENTRYPOINT [\"unterminated\"\nSHELL powershell -command\n";
    let document = parse_document(source);

    assert_eq!(
        document.instructions[1].form,
        InstructionForm::Json(vec!["echo".into(), "hello".into()])
    );
    assert_eq!(document.instructions[2].form, InstructionForm::Shell);
    assert_eq!(document.instructions[3].form, InstructionForm::InvalidJson);
    assert_eq!(document.instructions[4].form, InstructionForm::Shell);
    assert_eq!(
        document
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "P007")
            .count(),
        2
    );
}

#[test]
fn run_posix_test_command_is_not_misparsed_as_json() {
    let source =
        "FROM debian:trixie\nRUN [ ! -f /marker ] || touch /marker\nRUN [\"echo\", \"ok\"]\n";
    let document = parse_document(source);

    assert_eq!(document.instructions[1].form, InstructionForm::Shell);
    assert_eq!(
        document.instructions[2].form,
        InstructionForm::Json(vec!["echo".into(), "ok".into()])
    );
    assert!(document
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.code != "P007"));
}

#[test]
fn quotes_and_variable_expansions_are_structured() {
    let source = "FROM alpine:${VERSION:-3.20}\nENV A=$PLAIN B=\"${BRACED#prefix}\" C='$LITERAL' D=\\$ESCAPED\n";
    let document = parse_document(source);
    let env = &document.instructions[1];

    assert_eq!(
        document.instructions[0]
            .variables
            .iter()
            .map(|variable| (variable.name.as_str(), variable.modifier.as_deref()))
            .collect::<Vec<_>>(),
        [("VERSION", Some(":-3.20"))]
    );
    assert_eq!(
        env.variables
            .iter()
            .map(|variable| variable.name.as_str())
            .collect::<Vec<_>>(),
        ["PLAIN", "BRACED"]
    );
    assert_eq!(env.words[1].quote, QuoteStyle::Mixed);
    assert_eq!(env.words[1].value, "B=${BRACED#prefix}");
    assert_eq!(env.words[2].value, "C=$LITERAL");
    assert_eq!(env.words[3].value, "D=$ESCAPED");
}

#[test]
fn backtick_escape_keeps_windows_and_powershell_backslashes_literal() {
    let source = "# escape=`\nFROM mcr.microsoft.com/windows/nanoserver:ltsc2022\nSHELL [\"powershell\", \"-command\"]\nRUN Write-Host C:\\ProgramData\\app $env:TEMP\n";
    let document = parse_document(source);
    let run = &document.instructions[2];

    assert_eq!(run.words[1].value, "C:\\ProgramData\\app");
    assert_eq!(run.command, "Write-Host C:\\ProgramData\\app $env:TEMP");
    assert!(document.diagnostics.is_empty());
}

#[test]
fn unicode_words_and_heredoc_delimiters_are_lossless() {
    let source =
        "FROM alpine:3.20\nLABEL greeting=\"Բարեւ աշխարհ\"\nRUN <<'ՎԵՐՋ'\necho café 🔥\nՎԵՐՋ\n";
    let document = parse_document(source);

    assert_eq!(
        document.instructions[1].words[0].value,
        "greeting=Բարեւ աշխարհ"
    );
    assert_eq!(document.instructions[2].heredocs[0].delimiter, "ՎԵՐՋ");
    assert_eq!(
        document.instructions[2].heredocs[0].content,
        "echo café 🔥\n"
    );
}

#[test]
fn quoted_and_json_heredoc_markers_do_not_start_bodies() {
    let source = "FROM alpine:3.20\nRUN echo '<<NOT_A_HEREDOC'\nRUN [\"echo\", \"<<ALSO_NOT\"]\nCMD [\"sh\"]\n";
    let document = parse_document(source);

    assert!(document.instructions[1].heredocs.is_empty());
    assert!(document.instructions[2].heredocs.is_empty());
    assert_eq!(document.instructions.len(), 4);
}

#[test]
fn syntax_failures_are_recoverable_and_have_source_locations() {
    let source =
        "# escape=x\n# escape=\\\nFROM\nNOTREAL value\nCOPY [\"broken\"\nRUN <<EOF\nbody\n";
    let document = parse_document(source);
    let codes = document
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect::<Vec<_>>();

    assert!(codes.contains(&"P010"));
    assert!(codes.contains(&"P012"));
    assert!(codes.contains(&"P002"));
    assert!(codes.contains(&"P005"));
    assert!(codes.contains(&"P006"));
    assert!(codes.contains(&"P007"));
    assert!(document
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .all(|diagnostic| diagnostic.span.start.line >= 1));
}

#[test]
fn empty_files_and_unterminated_continuations_report_diagnostics() {
    assert_eq!(diagnostic_codes(""), ["P001"]);
    assert!(diagnostic_codes("FROM alpine:3.20\\").contains(&"P003"));
}

#[test]
fn lone_continuation_token_is_reported_without_panicking() {
    let document = parse_document("\\\nFROM alpine:3.20\n");
    assert!(document
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "P004"));
}

#[test]
fn trailing_whitespace_after_continuation_escape_is_reported() {
    let document = parse_document("FROM alpine:3.20\nRUN echo one \\  \n    && echo two\n");
    let diagnostic = document
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "P013")
        .expect("trailing continuation whitespace diagnostic");
    assert_eq!(diagnostic.severity, DiagnosticSeverity::Warning);
    assert_eq!(diagnostic.span.start.line, 2);
}

#[test]
fn modern_fixture_parses_without_recovery_diagnostics() {
    let source = include_str!("fixtures/modern.Dockerfile");
    let document = parse_document(source);

    assert!(
        document.diagnostics.is_empty(),
        "{:?}",
        document.diagnostics
    );
    assert_eq!(document.instructions.len(), 6);
    assert_eq!(document.instructions[1].heredocs.len(), 1);
    assert_eq!(document.instructions[3].flags[0].name, "mount");
    assert_eq!(document.instructions[3].heredocs.len(), 1);
}
