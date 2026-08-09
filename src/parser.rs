//! Span-aware Dockerfile parser.
//!
//! The parser deliberately keeps the long-standing `Instruction` fields used
//! by the linter while attaching structured flags, heredocs, words, variables,
//! directives, source spans, forms, and recoverable diagnostics.

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePosition {
    /// Zero-based UTF-8 byte offset in the original Dockerfile.
    pub offset: usize,
    /// One-based physical line number.
    pub line: usize,
    /// One-based byte column.
    pub column: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    /// Inclusive start position.
    pub start: SourcePosition,
    /// Exclusive end position.
    pub end: SourcePosition,
}

impl SourceSpan {
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start.offset..self.end.offset]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDiagnostic {
    pub code: &'static str,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserDirective {
    pub name: String,
    pub value: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionFlag {
    pub name: String,
    pub value: Option<String>,
    pub raw: String,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteStyle {
    Unquoted,
    Single,
    Double,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableReference {
    pub name: String,
    /// Everything following the variable name inside `${...}`, such as
    /// `:-fallback`, `#prefix`, or `/from/to`.
    pub modifier: Option<String>,
    pub braced: bool,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub raw: String,
    pub value: String,
    pub quote: QuoteStyle,
    pub span: SourceSpan,
    pub variables: Vec<VariableReference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    pub delimiter: String,
    pub file_descriptor: Option<u32>,
    pub strip_tabs: bool,
    pub expand: bool,
    pub content: String,
    pub marker_span: SourceSpan,
    pub content_span: SourceSpan,
    pub terminator_span: Option<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionForm {
    Shell,
    Json(Vec<String>),
    InvalidJson,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Compatibility field: one-based line where the instruction starts.
    pub line: usize,
    /// Uppercase instruction keyword.
    pub instruction: String,
    /// Compatibility field: normalized arguments. RUN heredoc bodies are
    /// appended so existing shell-oriented rules inspect the executed script.
    pub arguments: String,
    /// Exact original source covered by this instruction, including heredocs.
    pub raw: String,
    pub span: SourceSpan,
    pub keyword_span: SourceSpan,
    pub arguments_span: SourceSpan,
    /// Continuation-normalized arguments with significant whitespace retained.
    pub logical_arguments: String,
    /// Arguments after leading BuildKit flags.
    pub command: String,
    pub flags: Vec<InstructionFlag>,
    pub words: Vec<Word>,
    pub variables: Vec<VariableReference>,
    pub heredocs: Vec<Heredoc>,
    pub form: InstructionForm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dockerfile {
    pub escape: char,
    pub directives: Vec<ParserDirective>,
    pub instructions: Vec<Instruction>,
    pub diagnostics: Vec<ParseDiagnostic>,
}

/// Compatibility entry point used by existing rules.
pub fn parse(content: &str) -> Vec<Instruction> {
    parse_document(content).instructions
}

/// Parse a complete Dockerfile and retain both its AST and diagnostics.
pub fn parse_document(content: &str) -> Dockerfile {
    let lines = physical_lines(content);
    let (directives, escape, mut diagnostics) = parse_directives(&lines);
    let mut instructions = Vec::new();
    let mut line_index = 0usize;

    while line_index < lines.len() {
        let line = &lines[line_index];
        let trimmed = line.text.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            line_index += 1;
            continue;
        }

        let leading = line.text.len() - trimmed.len();
        let keyword_start = line.start + leading;
        let keyword_len = trimmed
            .bytes()
            .take_while(|byte| byte.is_ascii_alphabetic())
            .count();
        let token_len = trimmed
            .bytes()
            .take_while(|byte| !byte.is_ascii_whitespace())
            .count();

        let effective_keyword_len = if keyword_len == 0 {
            token_len
        } else {
            keyword_len
        };
        let keyword_source = &trimmed[..effective_keyword_len.min(trimmed.len())];
        let keyword = keyword_source.to_ascii_uppercase();
        let keyword_end = keyword_start + effective_keyword_len;
        let keyword_span = span(&lines, keyword_start, keyword_end);

        if keyword_len == 0 || keyword_len != token_len {
            diagnostics.push(ParseDiagnostic {
                code: "P004",
                severity: DiagnosticSeverity::Error,
                message: format!("invalid Dockerfile instruction {:?}", keyword_source),
                span: keyword_span,
            });
        } else if !is_known_instruction(&keyword) {
            let custom_syntax = directives
                .iter()
                .find(|directive| directive.name == "syntax")
                .is_some_and(|directive| !directive.value.starts_with("docker/dockerfile:"));
            diagnostics.push(ParseDiagnostic {
                code: "P005",
                severity: if custom_syntax {
                    DiagnosticSeverity::Warning
                } else {
                    DiagnosticSeverity::Error
                },
                message: format!("unknown Dockerfile instruction {keyword}"),
                span: keyword_span,
            });
        }

        let mut logical = LogicalBuffer::default();
        let mut normalized_parts = Vec::new();
        let mut current = line_index;
        let mut header_end;

        loop {
            let physical = &lines[current];
            let is_first = current == line_index;
            let semantic = if is_first {
                let relative = keyword_start - physical.start;
                &physical.text[relative..]
            } else {
                physical.text
            };

            if !is_first {
                let trimmed_continuation = semantic.trim_start_matches([' ', '\t']);
                if trimmed_continuation.is_empty() || trimmed_continuation.starts_with('#') {
                    if trimmed_continuation.is_empty() {
                        diagnostics.push(ParseDiagnostic {
                            code: "P009",
                            severity: DiagnosticSeverity::Warning,
                            message: "empty continuation line is deprecated".to_string(),
                            span: span(&lines, physical.start, physical.semantic_end),
                        });
                    }
                    header_end = physical.semantic_end;
                    if current + 1 == lines.len() {
                        diagnostics.push(ParseDiagnostic {
                            code: "P003",
                            severity: DiagnosticSeverity::Error,
                            message: "unterminated line continuation".to_string(),
                            span: span(&lines, keyword_start, header_end),
                        });
                        break;
                    }
                    current += 1;
                    continue;
                }
            }

            if continuation_has_trailing_whitespace(semantic, escape) {
                diagnostics.push(ParseDiagnostic {
                    code: "P013",
                    severity: DiagnosticSeverity::Warning,
                    message: "line continuation has trailing whitespace after the escape character"
                        .to_string(),
                    span: span(&lines, physical.start, physical.semantic_end),
                });
            }
            let cut = continuation_cut(semantic, escape);
            let semantic_start = if is_first {
                keyword_start
            } else {
                physical.start
            };
            let kept = cut.unwrap_or(semantic.len());
            logical.push(&semantic[..kept], semantic_start);

            let normalized = if is_first {
                semantic[effective_keyword_len.min(kept)..kept].trim()
            } else {
                semantic[..kept].trim()
            };
            if !normalized.is_empty() {
                normalized_parts.push(normalized.to_string());
            }

            header_end = physical.semantic_end;
            if cut.is_none() {
                break;
            }
            if current + 1 == lines.len() {
                diagnostics.push(ParseDiagnostic {
                    code: "P003",
                    severity: DiagnosticSeverity::Error,
                    message: "unterminated line continuation".to_string(),
                    span: span(&lines, keyword_start, header_end),
                });
                break;
            }
            current += 1;
        }

        let logical_keyword_end = effective_keyword_len.min(logical.text.len());
        let logical_arguments_start = logical.text[logical_keyword_end..]
            .find(|character: char| !character.is_whitespace())
            .map(|relative| logical_keyword_end + relative)
            .unwrap_or(logical.text.len());
        let logical_arguments = logical.text[logical_arguments_start..].to_string();
        let arguments_start = first_argument_offset(line, keyword_end);
        let arguments_span = span(&lines, arguments_start, header_end);
        let variables = variable_references(
            &logical.text[logical_arguments_start..],
            &logical.source_offsets,
            logical_arguments_start,
            &lines,
            escape,
        );
        let (lexed_words, unterminated_quote) = lex_words(
            &logical.text[logical_arguments_start..],
            logical_arguments_start,
            &logical.source_offsets,
            &lines,
            escape,
        );

        if let Some((quote, quote_span)) = unterminated_quote {
            if !matches!(keyword.as_str(), "RUN" | "CMD" | "ENTRYPOINT") {
                diagnostics.push(ParseDiagnostic {
                    code: "P008",
                    severity: DiagnosticSeverity::Error,
                    message: format!("unterminated {quote} quote"),
                    span: quote_span,
                });
            }
        }

        let mut flags = Vec::new();
        let mut command_word = 0usize;
        for lexed in &lexed_words {
            let Some(flag) = parse_flag(&lexed.word) else {
                break;
            };
            flags.push(flag);
            command_word += 1;
        }
        let command = lexed_words
            .get(command_word)
            .map(|word| logical.text[word.logical_start..].trim().to_string())
            .unwrap_or_default();
        let words = lexed_words
            .iter()
            .map(|lexed| lexed.word.clone())
            .collect::<Vec<_>>();
        let form = parse_form(
            &keyword,
            &command,
            &lexed_words,
            command_word,
            &lines,
            &mut diagnostics,
        );

        let mut heredocs = Vec::new();
        let mut body_cursor = current + 1;
        let can_contain_heredoc = can_contain_heredoc(&keyword, &command, &form);
        let heredoc_seeds = if can_contain_heredoc {
            find_heredocs(&logical, &lines, escape)
        } else {
            Vec::new()
        };
        let mut instruction_end = header_end;

        for seed in heredoc_seeds {
            let content_start = lines
                .get(body_cursor)
                .map_or(header_end, |physical| physical.start);
            let mut content = String::new();
            let mut terminator_span = None;

            while body_cursor < lines.len() {
                let physical = &lines[body_cursor];
                let possible_terminator = if seed.strip_tabs {
                    physical.text.trim_start_matches('\t')
                } else {
                    physical.text
                };
                if possible_terminator == seed.delimiter {
                    terminator_span = Some(span(&lines, physical.start, physical.semantic_end));
                    instruction_end = physical.semantic_end;
                    body_cursor += 1;
                    break;
                }

                let body_line = if seed.strip_tabs {
                    physical.text.trim_start_matches('\t')
                } else {
                    physical.text
                };
                content.push_str(body_line);
                if physical.full_end > physical.semantic_end {
                    content.push('\n');
                }
                instruction_end = physical.semantic_end;
                body_cursor += 1;
            }

            let content_end =
                terminator_span.map_or(instruction_end, |terminator| terminator.start.offset);
            let content_span = span(&lines, content_start, content_end.max(content_start));
            if terminator_span.is_none() {
                diagnostics.push(ParseDiagnostic {
                    code: "P002",
                    severity: DiagnosticSeverity::Error,
                    message: format!("unterminated heredoc {:?}", seed.delimiter),
                    span: seed.marker_span,
                });
            }

            heredocs.push(Heredoc {
                delimiter: seed.delimiter,
                file_descriptor: seed.file_descriptor,
                strip_tabs: seed.strip_tabs,
                expand: seed.expand,
                content,
                marker_span: seed.marker_span,
                content_span,
                terminator_span,
            });
        }

        let mut arguments = normalized_parts.join(" ");
        if keyword == "RUN" {
            for heredoc in &heredocs {
                if !heredoc.content.is_empty() {
                    arguments.push('\n');
                    arguments.push_str(&heredoc.content);
                }
            }
        }
        if arguments.trim().is_empty() {
            diagnostics.push(ParseDiagnostic {
                code: "P006",
                severity: DiagnosticSeverity::Error,
                message: format!("{keyword} requires arguments"),
                span: keyword_span,
            });
        }

        let instruction_span = span(&lines, keyword_start, instruction_end);
        instructions.push(Instruction {
            line: line.number,
            instruction: keyword,
            arguments,
            raw: content[keyword_start..instruction_end].to_string(),
            span: instruction_span,
            keyword_span,
            arguments_span,
            logical_arguments,
            command,
            flags,
            words,
            variables,
            heredocs,
            form,
        });

        line_index = if body_cursor > current + 1 {
            body_cursor
        } else {
            current + 1
        };
    }

    if instructions.is_empty()
        && diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "P004")
    {
        diagnostics.push(ParseDiagnostic {
            code: "P001",
            severity: DiagnosticSeverity::Error,
            message: "Dockerfile contains no instructions".to_string(),
            span: span(&lines, 0, 0),
        });
    }

    Dockerfile {
        escape,
        directives,
        instructions,
        diagnostics,
    }
}

#[derive(Debug)]
struct PhysicalLine<'a> {
    number: usize,
    start: usize,
    semantic_end: usize,
    full_end: usize,
    text: &'a str,
}

fn physical_lines(content: &str) -> Vec<PhysicalLine<'_>> {
    let mut result = Vec::new();
    let mut start = 0usize;

    for (index, physical) in content.split_inclusive('\n').enumerate() {
        let full_end = start + physical.len();
        let without_newline = physical.strip_suffix('\n').unwrap_or(physical);
        let semantic = without_newline
            .strip_suffix('\r')
            .unwrap_or(without_newline);
        let semantic_end = start + semantic.len();
        result.push(PhysicalLine {
            number: index + 1,
            start,
            semantic_end,
            full_end,
            text: semantic,
        });
        start = full_end;
    }

    result
}

fn parse_directives(
    lines: &[PhysicalLine<'_>],
) -> (Vec<ParserDirective>, char, Vec<ParseDiagnostic>) {
    let mut directives = Vec::new();
    let mut diagnostics = Vec::new();
    let mut seen = HashSet::new();
    let mut escape = '\\';

    for line in lines {
        let trimmed = line.text.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || !trimmed.starts_with('#') {
            break;
        }

        let body = trimmed[1..].trim();
        let Some((raw_name, raw_value)) = body.split_once('=') else {
            break;
        };
        let name = raw_name.trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "syntax" | "escape" | "check") {
            break;
        }

        let value = raw_value.trim().to_string();
        let leading = line.text.len() - trimmed.len();
        let directive_span = span(lines, line.start + leading, line.semantic_end);
        if !seen.insert(name.clone()) {
            diagnostics.push(ParseDiagnostic {
                code: "P010",
                severity: DiagnosticSeverity::Error,
                message: format!("parser directive {name:?} may only be used once"),
                span: directive_span,
            });
        }
        if value.is_empty() {
            diagnostics.push(ParseDiagnostic {
                code: "P011",
                severity: DiagnosticSeverity::Error,
                message: format!("parser directive {name:?} requires a value"),
                span: directive_span,
            });
        }
        if name == "escape" {
            match value.as_str() {
                "\\" => escape = '\\',
                "`" => escape = '`',
                _ => diagnostics.push(ParseDiagnostic {
                    code: "P012",
                    severity: DiagnosticSeverity::Error,
                    message: format!("invalid escape token {value:?}; expected ` or \\"),
                    span: directive_span,
                }),
            }
        }
        directives.push(ParserDirective {
            name,
            value,
            span: directive_span,
        });
    }

    (directives, escape, diagnostics)
}

fn first_argument_offset(line: &PhysicalLine<'_>, keyword_end: usize) -> usize {
    let relative = keyword_end.saturating_sub(line.start);
    let tail = &line.text[relative.min(line.text.len())..];
    tail.find(|character: char| !character.is_whitespace())
        .map_or(keyword_end, |offset| keyword_end + offset)
}

fn continuation_cut(line: &str, escape: char) -> Option<usize> {
    let end = line.trim_end_matches([' ', '\t']).len();
    let prefix = &line[..end];
    if !prefix.ends_with(escape) {
        return None;
    }
    let count = prefix
        .chars()
        .rev()
        .take_while(|character| *character == escape)
        .count();
    (count % 2 == 1).then(|| end - escape.len_utf8())
}

fn continuation_has_trailing_whitespace(line: &str, escape: char) -> bool {
    let trimmed = line.trim_end_matches([' ', '\t']);
    trimmed.len() < line.len() && trimmed.ends_with(escape)
}

fn is_known_instruction(keyword: &str) -> bool {
    matches!(
        keyword,
        "ADD"
            | "ARG"
            | "CMD"
            | "COPY"
            | "ENTRYPOINT"
            | "ENV"
            | "EXPOSE"
            | "FROM"
            | "HEALTHCHECK"
            | "LABEL"
            | "MAINTAINER"
            | "ONBUILD"
            | "RUN"
            | "SHELL"
            | "STOPSIGNAL"
            | "USER"
            | "VOLUME"
            | "WORKDIR"
    )
}

#[derive(Default)]
struct LogicalBuffer {
    text: String,
    source_offsets: Vec<usize>,
}

impl LogicalBuffer {
    fn push(&mut self, value: &str, source_start: usize) {
        self.text.push_str(value);
        self.source_offsets
            .extend((0..value.len()).map(|offset| source_start + offset));
    }
}

#[derive(Clone)]
struct LexedWord {
    word: Word,
    logical_start: usize,
}

fn lex_words(
    text: &str,
    logical_base: usize,
    source_offsets: &[usize],
    lines: &[PhysicalLine<'_>],
    escape: char,
) -> (Vec<LexedWord>, Option<(&'static str, SourceSpan)>) {
    let mut result = Vec::new();
    let mut index = 0usize;
    let mut unterminated = None;

    while index < text.len() {
        while index < text.len() {
            let character = text[index..]
                .chars()
                .next()
                .expect("valid character boundary");
            if !character.is_whitespace() {
                break;
            }
            index += character.len_utf8();
        }
        if index == text.len() {
            break;
        }

        let start = index;
        let mut value = String::new();
        let mut quote: Option<char> = None;
        let mut saw_single = false;
        let mut saw_double = false;
        let mut saw_unquoted = false;

        while index < text.len() {
            let character = text[index..]
                .chars()
                .next()
                .expect("valid character boundary");
            match quote {
                Some('\'') => {
                    if character == '\'' {
                        quote = None;
                        saw_single = true;
                        index += character.len_utf8();
                    } else {
                        value.push(character);
                        index += character.len_utf8();
                    }
                }
                Some('"') => {
                    if character == '"' {
                        quote = None;
                        saw_double = true;
                        index += character.len_utf8();
                    } else if character == escape && index + escape.len_utf8() < text.len() {
                        index += escape.len_utf8();
                        let escaped = text[index..].chars().next().expect("escaped character");
                        value.push(escaped);
                        index += escaped.len_utf8();
                    } else {
                        value.push(character);
                        index += character.len_utf8();
                    }
                }
                _ => {
                    if character.is_whitespace() {
                        break;
                    }
                    if character == '\'' || character == '"' {
                        quote = Some(character);
                        index += character.len_utf8();
                    } else if character == escape && index + escape.len_utf8() < text.len() {
                        saw_unquoted = true;
                        index += escape.len_utf8();
                        let escaped = text[index..].chars().next().expect("escaped character");
                        value.push(escaped);
                        index += escaped.len_utf8();
                    } else {
                        saw_unquoted = true;
                        value.push(character);
                        index += character.len_utf8();
                    }
                }
            }
        }

        let end = index;
        if let Some(open_quote) = quote {
            let quote_name = if open_quote == '\'' {
                "single"
            } else {
                "double"
            };
            unterminated = Some((
                quote_name,
                logical_span(
                    source_offsets,
                    logical_base + start,
                    logical_base + end,
                    lines,
                ),
            ));
        }
        let quote_style = match (saw_unquoted, saw_single, saw_double) {
            (true, false, false) => QuoteStyle::Unquoted,
            (false, true, false) => QuoteStyle::Single,
            (false, false, true) => QuoteStyle::Double,
            _ => QuoteStyle::Mixed,
        };
        let word_span = logical_span(
            source_offsets,
            logical_base + start,
            logical_base + end,
            lines,
        );
        let variables = variable_references(
            &text[start..end],
            source_offsets,
            logical_base + start,
            lines,
            escape,
        );
        result.push(LexedWord {
            word: Word {
                raw: text[start..end].to_string(),
                value,
                quote: quote_style,
                span: word_span,
                variables,
            },
            logical_start: logical_base + start,
        });
    }

    (result, unterminated)
}

fn variable_references(
    text: &str,
    source_offsets: &[usize],
    logical_base: usize,
    lines: &[PhysicalLine<'_>],
    escape: char,
) -> Vec<VariableReference> {
    let bytes = text.as_bytes();
    let mut result = Vec::new();
    let mut index = 0usize;
    let mut quote = None;

    while index < bytes.len() {
        let byte = bytes[index];
        if quote == Some(b'\'') {
            if byte == b'\'' {
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'\'' {
            quote = Some(b'\'');
            index += 1;
            continue;
        }
        if byte == b'"' {
            quote = if quote == Some(b'"') {
                None
            } else {
                Some(b'"')
            };
            index += 1;
            continue;
        }
        if byte == escape as u8 && escape.is_ascii() {
            index = (index + escape.len_utf8() + 1).min(bytes.len());
            continue;
        }
        if byte != b'$' {
            index += 1;
            continue;
        }

        let start = index;
        if bytes.get(index + 1) == Some(&b'{') {
            let mut cursor = index + 2;
            let mut depth = 1usize;
            while cursor < bytes.len() && depth > 0 {
                match bytes[cursor] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    b'\\' => cursor += 1,
                    _ => {}
                }
                cursor += 1;
            }
            if depth != 0 {
                index += 1;
                continue;
            }
            let inside = &text[index + 2..cursor - 1];
            let name_end = inside
                .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .unwrap_or(inside.len());
            if name_end == 0 {
                index = cursor;
                continue;
            }
            result.push(VariableReference {
                name: inside[..name_end].to_string(),
                modifier: (name_end < inside.len()).then(|| inside[name_end..].to_string()),
                braced: true,
                span: logical_span(
                    source_offsets,
                    logical_base + start,
                    logical_base + cursor,
                    lines,
                ),
            });
            index = cursor;
        } else {
            let mut cursor = index + 1;
            if bytes
                .get(cursor)
                .is_none_or(|byte| !byte.is_ascii_alphabetic() && *byte != b'_')
            {
                index += 1;
                continue;
            }
            cursor += 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                cursor += 1;
            }
            result.push(VariableReference {
                name: text[index + 1..cursor].to_string(),
                modifier: None,
                braced: false,
                span: logical_span(
                    source_offsets,
                    logical_base + start,
                    logical_base + cursor,
                    lines,
                ),
            });
            index = cursor;
        }
    }

    result
}

fn parse_flag(word: &Word) -> Option<InstructionFlag> {
    let body = word.value.strip_prefix("--")?;
    if body.is_empty() {
        return None;
    }
    let (name, value) = body.split_once('=').map_or((body, None), |(name, value)| {
        (name, Some(value.to_string()))
    });
    if name.is_empty() {
        return None;
    }
    Some(InstructionFlag {
        name: name.to_ascii_lowercase(),
        value,
        raw: word.raw.clone(),
        span: word.span,
    })
}

fn parse_form(
    keyword: &str,
    command: &str,
    words: &[LexedWord],
    command_word: usize,
    lines: &[PhysicalLine<'_>],
    diagnostics: &mut Vec<ParseDiagnostic>,
) -> InstructionForm {
    let supports_json = matches!(
        keyword,
        "ADD" | "CMD" | "COPY" | "ENTRYPOINT" | "RUN" | "SHELL" | "VOLUME"
    );
    if !supports_json || !command.starts_with('[') {
        if keyword == "SHELL" && !command.is_empty() {
            let target = words
                .get(command_word)
                .map_or_else(|| span(lines, 0, 0), |word| word.word.span);
            diagnostics.push(ParseDiagnostic {
                code: "P007",
                severity: DiagnosticSeverity::Error,
                message: "SHELL requires JSON array syntax".to_string(),
                span: target,
            });
        }
        return InstructionForm::Shell;
    }

    match serde_json::from_str::<Vec<String>>(command) {
        Ok(values) => InstructionForm::Json(values),
        Err(error) => {
            let target = words
                .get(command_word)
                .map_or_else(|| span(lines, 0, 0), |word| word.word.span);
            diagnostics.push(ParseDiagnostic {
                code: "P007",
                severity: DiagnosticSeverity::Error,
                message: format!("invalid JSON instruction form: {error}"),
                span: target,
            });
            InstructionForm::InvalidJson
        }
    }
}

fn can_contain_heredoc(keyword: &str, command: &str, form: &InstructionForm) -> bool {
    if !matches!(form, InstructionForm::Shell) {
        return false;
    }
    if matches!(keyword, "ADD" | "COPY" | "RUN") {
        return true;
    }
    if keyword != "ONBUILD" {
        return false;
    }
    let nested = command
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(nested.as_str(), "ADD" | "COPY" | "RUN")
}

#[derive(Debug)]
struct HeredocSeed {
    delimiter: String,
    file_descriptor: Option<u32>,
    strip_tabs: bool,
    expand: bool,
    marker_span: SourceSpan,
}

fn find_heredocs(
    logical: &LogicalBuffer,
    lines: &[PhysicalLine<'_>],
    escape: char,
) -> Vec<HeredocSeed> {
    let text = logical.text.as_bytes();
    let mut result = Vec::new();
    let mut index = 0usize;
    let mut quote = None;

    while index + 1 < text.len() {
        let byte = text[index];
        if let Some(active_quote) = quote {
            if byte == active_quote {
                quote = None;
            } else if byte == escape as u8 && active_quote == b'"' {
                index += 1;
            }
            index += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            index += 1;
            continue;
        }
        if byte == escape as u8 {
            index += 2;
            continue;
        }
        if byte != b'<' || text[index + 1] != b'<' || text.get(index + 2) == Some(&b'<') {
            index += 1;
            continue;
        }

        let mut marker_start = index;
        while marker_start > 0 && text[marker_start - 1].is_ascii_digit() {
            marker_start -= 1;
        }
        let file_descriptor = (marker_start < index)
            .then(|| logical.text[marker_start..index].parse::<u32>().ok())
            .flatten();
        let mut cursor = index + 2;
        let strip_tabs = text.get(cursor) == Some(&b'-');
        if strip_tabs {
            cursor += 1;
        }
        while text
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            cursor += 1;
        }
        let word_start = cursor;
        let mut delimiter = String::new();
        let mut delimiter_quote: Option<char> = None;
        let mut quoted = false;

        while cursor < text.len() {
            let current = logical.text[cursor..]
                .chars()
                .next()
                .expect("valid character boundary");
            if let Some(active_quote) = delimiter_quote {
                if current == active_quote {
                    delimiter_quote = None;
                    quoted = true;
                    cursor += current.len_utf8();
                } else if current == escape
                    && active_quote == '"'
                    && cursor + escape.len_utf8() < text.len()
                {
                    cursor += escape.len_utf8();
                    let escaped = logical.text[cursor..]
                        .chars()
                        .next()
                        .expect("escaped delimiter character");
                    delimiter.push(escaped);
                    quoted = true;
                    cursor += escaped.len_utf8();
                } else {
                    delimiter.push(current);
                    cursor += current.len_utf8();
                }
                continue;
            }
            if current == '\'' || current == '"' {
                delimiter_quote = Some(current);
                quoted = true;
                cursor += current.len_utf8();
            } else if current == escape && cursor + escape.len_utf8() < text.len() {
                cursor += escape.len_utf8();
                let escaped = logical.text[cursor..]
                    .chars()
                    .next()
                    .expect("escaped delimiter character");
                delimiter.push(escaped);
                quoted = true;
                cursor += escaped.len_utf8();
            } else if current.is_whitespace() || ";&|<>".contains(current) {
                break;
            } else {
                delimiter.push(current);
                cursor += current.len_utf8();
            }
        }

        if delimiter.is_empty() || cursor == word_start {
            index += 2;
            continue;
        }
        result.push(HeredocSeed {
            delimiter,
            file_descriptor,
            strip_tabs,
            expand: !quoted,
            marker_span: logical_span(&logical.source_offsets, marker_start, cursor, lines),
        });
        index = cursor;
    }

    result
}

fn logical_span(
    source_offsets: &[usize],
    start: usize,
    end: usize,
    lines: &[PhysicalLine<'_>],
) -> SourceSpan {
    let source_start = source_offsets
        .get(start)
        .copied()
        .or_else(|| source_offsets.last().map(|offset| offset + 1))
        .unwrap_or(0);
    let source_end = if end > start {
        source_offsets
            .get(end - 1)
            .map_or(source_start, |offset| offset + 1)
    } else {
        source_start
    };
    span(lines, source_start, source_end)
}

fn span(lines: &[PhysicalLine<'_>], start: usize, end: usize) -> SourceSpan {
    SourceSpan {
        start: position(lines, start),
        end: position(lines, end),
    }
}

fn position(lines: &[PhysicalLine<'_>], offset: usize) -> SourcePosition {
    let Some(line) = lines
        .iter()
        .rev()
        .find(|line| line.start <= offset)
        .or_else(|| lines.first())
    else {
        return SourcePosition {
            offset: 0,
            line: 1,
            column: 1,
        };
    };
    SourcePosition {
        offset,
        line: line.number,
        column: offset.saturating_sub(line.start) + 1,
    }
}
