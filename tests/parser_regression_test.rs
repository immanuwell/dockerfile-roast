use dockerfile_roast::parser::parse;

#[test]
fn heredoc_bodies_are_not_parsed_as_instructions() {
    let dockerfile = "# syntax=docker/dockerfile:1\n\
FROM alpine:3.20\n\
RUN <<EOF\n\
echo hello\n\
apk add --no-cache curl\n\
EOF\n\
CMD [\"sh\"]\n";

    let instructions = parse(dockerfile);
    let names: Vec<_> = instructions
        .iter()
        .map(|instruction| instruction.instruction.as_str())
        .collect();

    assert_eq!(names, ["FROM", "RUN", "CMD"]);
    assert_eq!(instructions[1].line, 3);
}

#[test]
fn multiple_heredocs_belong_to_one_instruction() {
    let dockerfile = "FROM alpine:3.20\n\
RUN <<FIRST cat > /first && 3<<'SECOND' cat > /second\n\
one\n\
FIRST\n\
two\n\
SECOND\n\
CMD [\"sh\"]\n";

    let instructions = parse(dockerfile);
    let names: Vec<_> = instructions
        .iter()
        .map(|instruction| instruction.instruction.as_str())
        .collect();

    assert_eq!(names, ["FROM", "RUN", "CMD"]);
}

#[test]
fn copy_heredoc_body_is_not_interpreted_as_dockerfile_syntax() {
    let dockerfile = "FROM alpine:3.20\n\
COPY <<EOF /usr/local/bin/start\n\
#!/bin/sh\n\
FROM this-is-script-text\n\
RUN echo this-is-script-text\n\
EOF\n\
RUN chmod +x /usr/local/bin/start\n";

    let instructions = parse(dockerfile);
    let names: Vec<_> = instructions
        .iter()
        .map(|instruction| instruction.instruction.as_str())
        .collect();

    assert_eq!(names, ["FROM", "COPY", "RUN"]);
    assert_eq!(instructions[2].line, 7);
}

#[test]
fn backtick_escape_directive_preserves_windows_paths() {
    let dockerfile = "# escape=`\n\
FROM mcr.microsoft.com/windows/nanoserver:ltsc2022\n\
COPY test.txt C:\\\n\
RUN Write-Host C:\\test.txt\n";

    let instructions = parse(dockerfile);
    let names: Vec<_> = instructions
        .iter()
        .map(|instruction| instruction.instruction.as_str())
        .collect();

    assert_eq!(names, ["FROM", "COPY", "RUN"]);
    assert_eq!(instructions[1].arguments, "test.txt C:\\");
    assert_eq!(instructions[2].arguments, "Write-Host C:\\test.txt");
}

#[test]
fn backtick_escape_directive_joins_backtick_continuations() {
    let dockerfile = "# escape=`\n\
FROM mcr.microsoft.com/windows/nanoserver:ltsc2022\n\
RUN Write-Host `\n\
    'hello world'\n";

    let instructions = parse(dockerfile);

    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[1].instruction, "RUN");
    assert_eq!(instructions[1].arguments, "Write-Host 'hello world'");
    assert_eq!(instructions[1].line, 3);
}

#[test]
fn buildkit_flags_stay_attached_to_their_instruction() {
    let dockerfile = "FROM --platform=$BUILDPLATFORM rust:1.86 AS build\n\
RUN --mount=type=cache,target=/usr/local/cargo/registry \\\n+    --mount=type=secret,id=token \\\n+    cargo build --release\n\
COPY --link --from=build /src/target/release/app /usr/local/bin/app\n";

    let instructions = parse(dockerfile);

    assert_eq!(instructions.len(), 3);
    assert!(instructions[0].arguments.starts_with("--platform="));
    assert!(instructions[1].arguments.contains("--mount=type=cache"));
    assert!(instructions[1].arguments.contains("--mount=type=secret"));
    assert!(instructions[2].arguments.starts_with("--link --from=build"));
}

#[test]
fn hash_characters_inside_arguments_are_not_comments() {
    let dockerfile = "FROM alpine:3.20\nRUN printf '%s\\n' '# still data'\n";
    let instructions = parse(dockerfile);

    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[1].arguments, "printf '%s\\n' '# still data'");
}

#[test]
fn crlf_input_has_stable_instruction_lines() {
    let dockerfile =
        "FROM alpine:3.20\r\nRUN echo first \\\r\n    && echo second\r\nCMD [\"sh\"]\r\n";
    let instructions = parse(dockerfile);

    assert_eq!(instructions.len(), 3);
    assert_eq!(instructions[1].line, 2);
    assert_eq!(instructions[1].arguments, "echo first && echo second");
    assert_eq!(instructions[2].line, 4);
}
