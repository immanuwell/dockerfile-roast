use dockerfile_roast::evaluate::{evaluate, EvalError, EvalOptions, ImageConfig};
use dockerfile_roast::parser::parse_document;

const SCRATCH_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn scratch_env(rest: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = pairs(&[("PATH", SCRATCH_PATH)]);
    env.extend(pairs(rest));
    env
}

fn try_eval(
    source: &str,
    build_args: &[(&str, &str)],
    target: Option<&str>,
) -> Result<ImageConfig, EvalError> {
    let options = EvalOptions {
        build_args: pairs(build_args),
        target: target.map(str::to_string),
    };
    evaluate(&parse_document(source), &options)
}

fn eval(source: &str) -> ImageConfig {
    try_eval(source, &[], None).expect("evaluation should succeed")
}

fn eval_args(source: &str, build_args: &[(&str, &str)]) -> ImageConfig {
    try_eval(source, build_args, None).expect("evaluation should succeed")
}

fn eval_target(source: &str, target: &str) -> ImageConfig {
    try_eval(source, &[], Some(target)).expect("evaluation should succeed")
}

#[test]
fn scratch_stage_gets_default_config_and_path() {
    let config = eval("FROM scratch\n");
    assert_eq!(
        config,
        ImageConfig {
            env: scratch_env(&[]),
            workdir: "/".to_string(),
            user: None,
            cmd: None,
            entrypoint: None,
            shell: strs(&["/bin/sh", "-c"]),
            labels: vec![],
            exposed_ports: vec![],
            base_image: None,
        }
    );
}

#[test]
fn external_image_is_recorded_as_base_image_with_empty_env() {
    let config = eval("FROM alpine:3.20\nENV X=1\n");
    assert_eq!(config.base_image.as_deref(), Some("alpine:3.20"));
    assert_eq!(config.env, pairs(&[("X", "1")]));
}

#[test]
fn last_stage_is_the_default_target() {
    let source = "FROM scratch AS one\nENV S=one\nFROM scratch AS two\nENV S=two\n";
    assert_eq!(eval(source).env, scratch_env(&[("S", "two")]));
}

#[test]
fn target_matches_stage_names_case_insensitively() {
    let source = "FROM scratch AS Base\nENV A=1\nFROM scratch AS last\nENV B=2\n";
    for target in ["Base", "BASE", "base"] {
        assert_eq!(
            eval_target(source, target).env,
            scratch_env(&[("A", "1")]),
            "target {target}"
        );
    }
}

#[test]
fn unknown_target_reports_the_requested_name() {
    let result = try_eval("FROM scratch AS build\n", &[], Some("Release"));
    assert_eq!(result, Err(EvalError::UnknownTarget("Release".to_string())));
}

#[test]
fn file_without_from_has_no_stages() {
    assert_eq!(try_eval("", &[], None), Err(EvalError::NoStages));
    assert_eq!(
        try_eval("# only a comment\n", &[], None),
        Err(EvalError::NoStages)
    );
}

#[test]
fn lowercase_from_reference_continues_an_earlier_stage() {
    let source = "FROM alpine:3.20 AS Base\nENV A=1\nWORKDIR /app\nFROM base\nENV B=2\n";
    let config = eval(source);
    assert_eq!(config.env, pairs(&[("A", "1"), ("B", "2")]));
    assert_eq!(config.workdir, "/app");
    assert_eq!(config.base_image.as_deref(), Some("alpine:3.20"));
}

#[test]
fn from_naming_a_later_stage_is_an_external_image() {
    let source = "FROM later AS x\nFROM scratch AS later\nENV A=1\nFROM x\n";
    let config = eval(source);
    assert_eq!(config.base_image.as_deref(), Some("later"));
    assert!(config.env.is_empty());
}

#[test]
fn sibling_stages_do_not_share_state() {
    let source = "FROM scratch AS a\nENV A=1\nFROM scratch AS b\nENV B=2\n";
    assert_eq!(eval_target(source, "b").env, scratch_env(&[("B", "2")]));
}

#[test]
fn arg_default_and_build_arg_override() {
    let source = "FROM scratch\nARG V=1.0\nENV VERSION=$V\n";
    assert_eq!(eval(source).env, scratch_env(&[("VERSION", "1.0")]));
    assert_eq!(
        eval_args(source, &[("V", "2.0")]).env,
        scratch_env(&[("VERSION", "2.0")])
    );
}

#[test]
fn undeclared_build_args_and_args_never_reach_env() {
    let source = "ARG G=g\nFROM scratch\nARG A=a\nENV E=$A\n";
    let config = eval_args(source, &[("UNUSED", "x")]);
    assert_eq!(config.env, scratch_env(&[("E", "a")]));
}

#[test]
fn global_arg_needs_redeclaration_inside_a_stage() {
    let source = "ARG V=1\nFROM scratch\nENV BEFORE=$V\nARG V\nENV AFTER=$V\n";
    assert_eq!(
        eval(source).env,
        scratch_env(&[("BEFORE", ""), ("AFTER", "1")])
    );
}

#[test]
fn global_arg_can_choose_the_base_image() {
    let source = "ARG TAG=3.20\nFROM alpine:${TAG}\n";
    assert_eq!(eval(source).base_image.as_deref(), Some("alpine:3.20"));
    assert_eq!(
        eval_args(source, &[("TAG", "3.19")]).base_image.as_deref(),
        Some("alpine:3.19")
    );
}

#[test]
fn arg_values_reach_child_stages() {
    let source = "FROM scratch AS base\nARG V=1\nFROM base\nENV X=$V\n";
    assert_eq!(eval(source).env, scratch_env(&[("X", "1")]));
}

#[test]
fn arg_line_values_see_earlier_values_on_the_same_line() {
    let source = "FROM scratch\nARG A=1 B=${A}2\nENV R=$B\n";
    assert_eq!(eval(source).env, scratch_env(&[("R", "12")]));
}

#[test]
fn env_and_label_lines_only_see_values_set_before_the_line() {
    let source = "FROM scratch\nENV A=1\nENV A=2 B=$A\nLABEL x=$A y=$B\n";
    let config = eval(source);
    assert_eq!(config.env, scratch_env(&[("A", "2"), ("B", "1")]));
    assert_eq!(config.labels, pairs(&[("x", "2"), ("y", "1")]));
}

#[test]
fn valued_arg_after_env_wins_for_expansion_but_env_keeps_its_value() {
    let source = "FROM scratch\nENV V=env\nARG V=arg\nENV COPY=$V\n";
    let config = eval(source);
    assert_eq!(config.env, scratch_env(&[("V", "env"), ("COPY", "arg")]));
}

#[test]
fn modifiers_and_quoting_are_expanded() {
    let source = "FROM scratch\nENV A=x\nENV B=${A:-d} C=${U:-d} D=${A:+set} E='$A' F=\"$A y\"\n";
    let config = eval(source);
    assert_eq!(
        config.env,
        scratch_env(&[
            ("A", "x"),
            ("B", "x"),
            ("C", "d"),
            ("D", "set"),
            ("E", "$A"),
            ("F", "x y"),
        ])
    );
}

#[test]
fn legacy_env_form_takes_the_rest_of_the_line() {
    let config = eval("FROM scratch\nENV GREETING hello big world\n");
    assert_eq!(config.env, scratch_env(&[("GREETING", "hello big world")]));
}

#[test]
fn workdir_resolves_relative_paths_against_the_current_directory() {
    let source = "FROM scratch\nWORKDIR /srv\nWORKDIR app/../web\nWORKDIR ./static\n";
    assert_eq!(eval(source).workdir, "/srv/web/static");
}

#[test]
fn user_is_expanded() {
    let config = eval("FROM scratch\nARG U=app\nUSER $U:1000\n");
    assert_eq!(config.user.as_deref(), Some("app:1000"));
}

#[test]
fn labels_accumulate_and_later_values_win() {
    let source = "FROM scratch AS base\nLABEL a=1 b=2\nFROM base\nLABEL b=3 c=4\n";
    assert_eq!(
        eval(source).labels,
        pairs(&[("a", "1"), ("b", "3"), ("c", "4")])
    );
}

#[test]
fn expose_normalizes_protocols_ranges_and_duplicates() {
    let source = "FROM scratch\nEXPOSE 80 443/TCP 53/udp 8000-8002 80\n";
    assert_eq!(
        eval(source).exposed_ports,
        strs(&["80/tcp", "443/tcp", "53/udp", "8000/tcp", "8001/tcp", "8002/tcp"])
    );
}

#[test]
fn expose_accepts_variables() {
    let config = eval("FROM scratch\nARG P=8080\nEXPOSE $P/udp\n");
    assert_eq!(config.exposed_ports, strs(&["8080/udp"]));
}

#[test]
fn shell_form_cmd_and_entrypoint_use_the_shell_in_effect() {
    let source = "FROM scratch\nCMD echo $HOME\nSHELL [\"/bin/bash\", \"-c\"]\nENTRYPOINT run it\n";
    let config = eval(source);
    assert_eq!(config.cmd, Some(strs(&["/bin/sh", "-c", "echo $HOME"])));
    assert_eq!(
        config.entrypoint,
        Some(strs(&["/bin/bash", "-c", "run it"]))
    );
    assert_eq!(config.shell, strs(&["/bin/bash", "-c"]));
}

#[test]
fn exec_form_cmd_is_taken_as_written() {
    let config = eval("FROM scratch\nCMD [\"app\", \"--flag\", \"$HOME\"]\n");
    assert_eq!(config.cmd, Some(strs(&["app", "--flag", "$HOME"])));
}

#[test]
fn entrypoint_resets_an_inherited_cmd_unless_cmd_follows() {
    let parent = "FROM scratch AS base\nCMD [\"parent\"]\n";
    let reset = format!("{parent}FROM base\nENTRYPOINT [\"e\"]\n");
    let config = eval(&reset);
    assert_eq!(config.entrypoint, Some(strs(&["e"])));
    assert_eq!(config.cmd, None);

    let both = format!("{parent}FROM base\nENTRYPOINT [\"e\"]\nCMD [\"c\"]\n");
    assert_eq!(eval(&both).cmd, Some(strs(&["c"])));

    let untouched = format!("{parent}FROM base\nUSER app\n");
    assert_eq!(eval(&untouched).cmd, Some(strs(&["parent"])));
}

#[test]
fn shell_is_inherited_by_child_stages() {
    let source = "FROM scratch AS base\nSHELL [\"/bin/zsh\", \"-c\"]\nFROM base\nCMD go\n";
    let config = eval(source);
    assert_eq!(config.shell, strs(&["/bin/zsh", "-c"]));
    assert_eq!(config.cmd, Some(strs(&["/bin/zsh", "-c", "go"])));
}

#[test]
fn multistage_build_with_target_and_build_args() {
    let source = "\
ARG RUST=1.80
FROM rust:${RUST} AS build
ARG PROFILE=release
ENV CARGO_PROFILE=$PROFILE
WORKDIR /src
RUN cargo build
FROM debian:bookworm AS runtime
LABEL stage=runtime
EXPOSE 8080
USER nobody
CMD [\"/app\"]
";
    let runtime = eval(source);
    assert_eq!(runtime.base_image.as_deref(), Some("debian:bookworm"));
    assert_eq!(runtime.workdir, "/");
    assert_eq!(runtime.user.as_deref(), Some("nobody"));
    assert_eq!(runtime.exposed_ports, strs(&["8080/tcp"]));

    let build = try_eval(
        source,
        &[("RUST", "1.79"), ("PROFILE", "dev")],
        Some("build"),
    )
    .unwrap();
    assert_eq!(build.base_image.as_deref(), Some("rust:1.79"));
    assert_eq!(build.env, pairs(&[("CARGO_PROFILE", "dev")]));
    assert_eq!(build.workdir, "/src");
}
