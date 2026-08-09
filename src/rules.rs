use crate::parser::{
    parse_document, DiagnosticSeverity, Instruction, InstructionForm, SourcePosition, SourceSpan,
};
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable Droast (`DF`) or upstream ShellCheck (`SC`) rule ID.
    pub rule: String,
    pub severity: Severity,
    pub line: usize,
    /// One-based source column; zero means the location is line-only.
    pub column: usize,
    /// Inclusive end line and exclusive end column when supplied by an analyzer.
    pub end_line: usize,
    pub end_column: usize,
    pub message: String,
    pub roast: String,
}

type RuleFn = fn(&[Instruction], &str) -> Vec<Finding>;

pub struct Rule {
    pub id: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub func: RuleFn,
}

impl Rule {
    pub fn categories(&self) -> &'static [&'static str] {
        categories_for(self.id)
    }
}

pub const ALL_CATEGORIES: &[&str] = &[
    "correctness",
    "maintainability",
    "performance",
    "reliability",
    "reproducibility",
    "security",
    "supply-chain",
];

pub fn categories_for(id: &str) -> &'static [&'static str] {
    match id {
        "DF002" | "DF010" | "DF013" | "DF014" | "DF020" | "DF034" => &["security"],
        "DF021" => &["security", "supply-chain"],
        "DF057" | "DF066" => &["reliability", "security"],
        "DF001" | "DF005" | "DF024" | "DF042" | "DF062" | "DF069" => {
            &["correctness", "reproducibility"]
        }
        "DF003" | "DF004" | "DF007" | "DF011" | "DF016" | "DF028" | "DF029" | "DF030" | "DF031"
        | "DF045" | "DF046" | "DF047" | "DF055" | "DF064" | "DF070" => &["performance"],
        "DF006" | "DF008" | "DF026" | "DF056" | "DF058" | "DF067" => {
            &["maintainability", "performance"]
        }
        "DF033" => &["performance", "security"],
        "DF009" | "DF019" | "DF023" | "DF037" | "DF038" | "DF043" | "DF044" | "DF059" | "DF061"
        | "DF063" => &["correctness", "maintainability"],
        "DF012" | "DF017" | "DF022" | "DF032" | "DF035" | "DF036" | "DF060" => {
            &["maintainability", "reliability"]
        }
        "DF015" | "DF018" | "DF025" | "DF027" | "DF039" | "DF040" | "DF041" | "DF048" | "DF049"
        | "DF050" | "DF068" | "DF071" => &["correctness", "reliability"],
        "DF051" | "DF052" | "DF053" | "DF054" | "DF065" | "DF073" => {
            &["reproducibility", "supply-chain"]
        }
        "DF072" | "DF074" => &["correctness", "security"],
        "DF075" => &["correctness", "reliability"],
        "DF076" | "DF077" | "DF078" | "DF079" | "DF082" | "DF084" | "DF085" | "DF086" | "DF087" => {
            &["correctness", "reliability"]
        }
        "DF083" => &["correctness", "reproducibility"],
        _ => &[],
    }
}

pub fn all_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "DF001",
            severity: Severity::Warning,
            description: "Use specific base image tags instead of 'latest'",
            func: rule_latest_tag,
        },
        Rule {
            id: "DF002",
            severity: Severity::Error,
            description: "Do not run as root",
            func: rule_running_as_root,
        },
        Rule {
            id: "DF011",
            severity: Severity::Info,
            description: "Use multi-stage builds to reduce image size",
            func: rule_no_multistage,
        },
        Rule {
            id: "DF013",
            severity: Severity::Error,
            description: "Avoid hardcoded credentials in RUN commands",
            func: rule_hardcoded_run_secrets,
        },
        Rule {
            id: "DF014",
            severity: Severity::Error,
            description: "Avoid hardcoding passwords or tokens in ARG/ENV",
            func: rule_hardcoded_secrets,
        },
        Rule {
            id: "DF020",
            severity: Severity::Info,
            description: "Set explicit non-root USER",
            func: rule_no_user_instruction,
        },
        Rule {
            id: "DF003",
            severity: Severity::Info,
            description: "Combine RUN commands to reduce layers",
            func: rule_many_run_layers,
        },
        Rule {
            id: "DF004",
            severity: Severity::Warning,
            description: "Clean apt/apk cache before it reaches the final image",
            func: rule_uncleaned_package_cache,
        },
        Rule {
            id: "DF005",
            severity: Severity::Info,
            description: "Pin package versions for reproducibility",
            func: rule_unpinned_packages,
        },
        Rule {
            id: "DF006",
            severity: Severity::Warning,
            description: "Avoid ADD for local files; prefer COPY",
            func: rule_add_instead_of_copy,
        },
        Rule {
            id: "DF007",
            severity: Severity::Warning,
            description: "Do not copy the entire build context (COPY . .)",
            func: rule_copy_all,
        },
        Rule {
            id: "DF008",
            severity: Severity::Info,
            description: "Use WORKDIR instead of inline cd commands",
            func: rule_cd_instead_of_workdir,
        },
        Rule {
            id: "DF009",
            severity: Severity::Warning,
            description: "Use absolute paths in WORKDIR",
            func: rule_relative_workdir,
        },
        Rule {
            id: "DF010",
            severity: Severity::Warning,
            description: "Avoid using sudo inside containers",
            func: rule_sudo_usage,
        },
        Rule {
            id: "DF012",
            severity: Severity::Info,
            description: "Set HEALTHCHECK for long-running services",
            func: rule_no_healthcheck,
        },
        Rule {
            id: "DF017",
            severity: Severity::Warning,
            description: "Use ENTRYPOINT with CMD for flexible images",
            func: rule_cmd_without_entrypoint,
        },
        Rule {
            id: "DF018",
            severity: Severity::Warning,
            description: "Avoid using shell form for ENTRYPOINT",
            func: rule_shell_form_entrypoint,
        },
        Rule {
            id: "DF019",
            severity: Severity::Warning,
            description: "Do not use deprecated MAINTAINER; use LABEL instead",
            func: rule_deprecated_maintainer,
        },
        Rule {
            id: "DF022",
            severity: Severity::Info,
            description: "Specify EXPOSE for documented ports",
            func: rule_no_expose,
        },
        Rule {
            id: "DF023",
            severity: Severity::Info,
            description: "Name intermediate stages instead of relying on numeric indexes",
            func: rule_multiple_from_no_alias,
        },
        Rule {
            id: "DF024",
            severity: Severity::Warning,
            description: "Avoid using :latest in FROM even with aliases",
            func: rule_from_latest_alias,
        },
        Rule {
            id: "DF025",
            severity: Severity::Warning,
            description: "Use JSON array syntax for CMD/ENTRYPOINT",
            func: rule_shell_form_cmd,
        },
        Rule {
            id: "DF026",
            severity: Severity::Warning,
            description: "Avoid broad local COPY to the filesystem root",
            func: rule_copy_root,
        },
        Rule {
            id: "DF030",
            severity: Severity::Info,
            description: "Avoid using pip without --no-cache-dir",
            func: rule_pip_no_cache,
        },
        Rule {
            id: "DF031",
            severity: Severity::Info,
            description: "Avoid npm install without ci/--production for prod images",
            func: rule_npm_install,
        },
        Rule {
            id: "DF032",
            severity: Severity::Info,
            description: "Set PYTHONDONTWRITEBYTECODE and PYTHONUNBUFFERED for Python images",
            func: rule_python_env_vars,
        },
        Rule {
            id: "DF033",
            severity: Severity::Info,
            description: "Use an effective .dockerignore for each build context",
            func: rule_no_dockerignore,
        },
        Rule {
            id: "DF034",
            severity: Severity::Error,
            description: "Avoid persistent world-writable chmod modes",
            func: rule_chmod_777,
        },
        Rule {
            id: "DF035",
            severity: Severity::Info,
            description: "Avoid using curl without --fail flags",
            func: rule_curl_no_fail,
        },
        Rule {
            id: "DF036",
            severity: Severity::Info,
            description: "Avoid Dockerfile with no CMD or ENTRYPOINT",
            func: rule_no_cmd_or_entrypoint,
        },
        Rule {
            id: "DF015",
            severity: Severity::Error,
            description: "Avoid using apt-get without -y flag",
            func: rule_apt_no_y,
        },
        Rule {
            id: "DF016",
            severity: Severity::Info,
            description: "Use --no-install-recommends with apt-get",
            func: rule_apt_recommends,
        },
        Rule {
            id: "DF021",
            severity: Severity::Error,
            description: "Avoid executing unverified remote scripts",
            func: rule_curl_pipe_sh,
        },
        Rule {
            id: "DF027",
            severity: Severity::Error,
            description: "Do not use yum without -y flag",
            func: rule_yum_no_y,
        },
        Rule {
            id: "DF028",
            severity: Severity::Warning,
            description: "Cache-bust apt-get update",
            func: rule_apt_get_update_alone,
        },
        Rule {
            id: "DF029",
            severity: Severity::Warning,
            description: "Avoid apk add without --no-cache",
            func: rule_apk_no_cache,
        },
        Rule {
            id: "DF037",
            severity: Severity::Error,
            description: "Dockerfile must begin with FROM, ARG, or a comment",
            func: rule_invalid_instruction_order,
        },
        Rule {
            id: "DF038",
            severity: Severity::Warning,
            description: "Multiple CMD instructions — only the last one takes effect",
            func: rule_multiple_cmd,
        },
        Rule {
            id: "DF039",
            severity: Severity::Error,
            description: "Multiple ENTRYPOINT instructions — only the last one takes effect",
            func: rule_multiple_entrypoint,
        },
        Rule {
            id: "DF040",
            severity: Severity::Error,
            description: "EXPOSE port must be in valid range 0-65535",
            func: rule_expose_port_range,
        },
        Rule {
            id: "DF041",
            severity: Severity::Error,
            description: "Multiple HEALTHCHECK instructions — only the last one applies",
            func: rule_multiple_healthcheck,
        },
        Rule {
            id: "DF042",
            severity: Severity::Error,
            description: "FROM stage aliases must be unique",
            func: rule_unique_stage_aliases,
        },
        Rule {
            id: "DF043",
            severity: Severity::Warning,
            description: "zypper install without non-interactive flag",
            func: rule_zypper_no_y,
        },
        Rule {
            id: "DF044",
            severity: Severity::Warning,
            description: "Avoid zypper dist-upgrade in Dockerfiles",
            func: rule_zypper_dist_upgrade,
        },
        Rule {
            id: "DF045",
            severity: Severity::Info,
            description: "Run zypper clean after zypper install",
            func: rule_zypper_clean,
        },
        Rule {
            id: "DF046",
            severity: Severity::Warning,
            description: "Run dnf clean all after dnf install",
            func: rule_dnf_clean,
        },
        Rule {
            id: "DF047",
            severity: Severity::Warning,
            description: "Run yum clean all after yum install",
            func: rule_yum_clean,
        },
        Rule {
            id: "DF048",
            severity: Severity::Error,
            description: "COPY with multiple sources requires destination to end with /",
            func: rule_copy_multi_arg_slash,
        },
        Rule {
            id: "DF049",
            severity: Severity::Info,
            description: "Review unresolved COPY --from references resembling stage aliases",
            func: rule_copy_from_undefined_stage,
        },
        Rule {
            id: "DF050",
            severity: Severity::Error,
            description: "COPY --from cannot reference the current stage",
            func: rule_copy_from_self,
        },
        Rule {
            id: "DF051",
            severity: Severity::Warning,
            description: "Pin versions in pip install",
            func: rule_pip_version_pinning,
        },
        Rule {
            id: "DF052",
            severity: Severity::Info,
            description: "Pin versions in apk add",
            func: rule_apk_version_pinning,
        },
        Rule {
            id: "DF053",
            severity: Severity::Warning,
            description: "Pin versions in gem install",
            func: rule_gem_version_pinning,
        },
        Rule {
            id: "DF054",
            severity: Severity::Warning,
            description: "Pin versions in go install with @version",
            func: rule_go_install_version,
        },
        Rule {
            id: "DF055",
            severity: Severity::Info,
            description: "Run yarn cache clean after yarn install",
            func: rule_yarn_cache_clean,
        },
        Rule {
            id: "DF056",
            severity: Severity::Info,
            description: "Use wget --progress=dot:giga to avoid bloated build logs",
            func: rule_wget_no_progress,
        },
        Rule {
            id: "DF057",
            severity: Severity::Warning,
            description: "Set -o pipefail before RUN commands that use pipes",
            func: rule_pipefail_missing,
        },
        Rule {
            id: "DF058",
            severity: Severity::Info,
            description: "Use either wget or curl consistently, not both",
            func: rule_wget_and_curl,
        },
        Rule {
            id: "DF059",
            severity: Severity::Warning,
            description: "Use apt-get or apt-cache instead of apt in scripts",
            func: rule_apt_instead_of_apt_get,
        },
        Rule {
            id: "DF060",
            severity: Severity::Info,
            description: "Avoid running pointless interactive commands inside containers",
            func: rule_useless_commands,
        },
        Rule {
            id: "DF061",
            severity: Severity::Info,
            description: "Do not use --platform in FROM unless required",
            func: rule_from_platform_flag,
        },
        Rule {
            id: "DF062",
            severity: Severity::Info,
            description: "ENV references may use inherited values",
            func: rule_env_self_reference,
        },
        Rule {
            id: "DF063",
            severity: Severity::Warning,
            description: "COPY to relative destination requires WORKDIR to be set first",
            func: rule_copy_relative_no_workdir,
        },
        Rule {
            id: "DF064",
            severity: Severity::Warning,
            description: "Use useradd -l with explicitly high UIDs",
            func: rule_useradd_no_l,
        },
        Rule {
            id: "DF065",
            severity: Severity::Warning,
            description: "Enforce configured approved registries",
            func: rule_untrusted_registry,
        },
        Rule {
            id: "DF066",
            severity: Severity::Warning,
            description: "Bash-specific syntax used without a SHELL instruction",
            func: rule_bash_syntax_no_shell,
        },
        Rule {
            id: "DF067",
            severity: Severity::Info,
            description: "Reserved: archive extraction policy is context-dependent",
            func: rule_copy_archive_use_add,
        },
        Rule {
            id: "DF068",
            severity: Severity::Error,
            description: "FROM, ONBUILD, and MAINTAINER are forbidden as ONBUILD triggers",
            func: rule_onbuild_forbidden,
        },
        Rule {
            id: "DF069",
            severity: Severity::Warning,
            description: "Avoid apt-get upgrade / dist-upgrade — makes builds non-reproducible",
            func: rule_apt_upgrade,
        },
        Rule {
            id: "DF070",
            severity: Severity::Warning,
            description: "Avoid broad COPY before package install — invalidates Docker layer cache",
            func: rule_copy_before_install,
        },
        Rule {
            id: "DF071",
            severity: Severity::Error,
            description: "Dockerfile syntax must be valid",
            func: rule_parser_syntax,
        },
        Rule {
            id: "DF072",
            severity: Severity::Error,
            description: "Suppression directives must satisfy policy",
            func: rule_configured_policy,
        },
        Rule {
            id: "DF073",
            severity: Severity::Error,
            description: "Base images must satisfy the approved image policy",
            func: rule_configured_policy,
        },
        Rule {
            id: "DF074",
            severity: Severity::Error,
            description: "Image labels must satisfy the configured schema",
            func: rule_configured_policy,
        },
        Rule {
            id: "DF075",
            severity: Severity::Info,
            description: "Containerfile.in must be linted after Podman CPP preprocessing",
            func: rule_configured_policy,
        },
        Rule {
            id: "DF076",
            severity: Severity::Warning,
            description: "Use a consistent casing style for Dockerfile instructions",
            func: rule_consistent_instruction_casing,
        },
        Rule {
            id: "DF077",
            severity: Severity::Error,
            description: "Do not COPY or ADD files excluded from the build context",
            func: rule_configured_policy,
        },
        Rule {
            id: "DF078",
            severity: Severity::Warning,
            description: "Use lowercase protocol names in EXPOSE",
            func: rule_expose_proto_casing,
        },
        Rule {
            id: "DF079",
            severity: Severity::Warning,
            description: "Match AS casing to FROM in multi-stage builds",
            func: rule_from_as_casing,
        },
        Rule {
            id: "DF082",
            severity: Severity::Info,
            description: "Use key=value syntax for ENV and LABEL",
            func: rule_legacy_key_value_format,
        },
        Rule {
            id: "DF083",
            severity: Severity::Warning,
            description: "Do not set FROM --platform to the default target platform",
            func: rule_redundant_target_platform,
        },
        Rule {
            id: "DF084",
            severity: Severity::Warning,
            description: "Avoid reserved Dockerfile stage names",
            func: rule_reserved_stage_name,
        },
        Rule {
            id: "DF085",
            severity: Severity::Warning,
            description: "Use lowercase multi-stage build names",
            func: rule_stage_name_casing,
        },
        Rule {
            id: "DF086",
            severity: Severity::Error,
            description: "Declare ARG variables used by FROM before the first FROM",
            func: rule_undefined_arg_in_from,
        },
        Rule {
            id: "DF087",
            severity: Severity::Error,
            description: "Declare Dockerfile variables before using them",
            func: rule_undefined_variable,
        },
    ]
}

fn rule_configured_policy(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    Vec::new()
}

fn finding_at_span(
    rule: &str,
    severity: Severity,
    span: SourceSpan,
    message: String,
    roast: &str,
) -> Finding {
    Finding {
        rule: rule.into(),
        severity,
        line: span.start.line,
        column: span.start.column,
        end_line: span.end.line,
        end_column: span.end.column,
        message,
        roast: roast.into(),
    }
}

fn source_position(source: &str, offset: usize) -> SourcePosition {
    let offset = offset.min(source.len());
    let prefix = &source[..offset];
    let line_start = prefix.rfind('\n').map_or(0, |newline| newline + 1);
    SourcePosition {
        offset,
        line: prefix.bytes().filter(|byte| *byte == b'\n').count() + 1,
        column: offset - line_start + 1,
    }
}

fn instruction_match_span(
    source: &str,
    instruction: &Instruction,
    start: usize,
    end: usize,
) -> SourceSpan {
    let absolute_start = instruction.span.start.offset + start;
    let absolute_end = instruction.span.start.offset + end;
    SourceSpan {
        start: source_position(source, absolute_start),
        end: source_position(source, absolute_end),
    }
}

fn instruction_substring_span(
    source: &str,
    instruction: &Instruction,
    needles: &[&str],
) -> SourceSpan {
    needles
        .iter()
        .find_map(|needle| {
            instruction.raw.find(needle).map(|start| {
                instruction_match_span(source, instruction, start, start + needle.len())
            })
        })
        .unwrap_or(instruction.span)
}

fn shell_command_span(source: &str, instruction: &Instruction, command: &str) -> SourceSpan {
    let script = mask_shell_comments(&mask_shell_array_bodies(&instruction.raw));
    let escaped = regex::escape(command);
    let pattern = Regex::new(&format!(
        r"(?im)(?:^\s*RUN(?:\s+--[^\s]+)*\s+|[;&|()]\s*|^\s*|\b(?:then|do|if|elif|while|until)\s+|!\s*)(?:sudo(?:\s+-\S+)*\s+)?(?:(?:/usr/bin/)?env(?:\s+(?:-\S+|[A-Za-z_][A-Za-z0-9_]*=\S+))*\s+)?(?P<command>{escaped})(?:\s|$)"
    ))
    .expect("escaped command creates a valid invocation regex");
    pattern
        .captures(&script)
        .and_then(|capture| capture.name("command"))
        .map(|matched| instruction_match_span(source, instruction, matched.start(), matched.end()))
        .unwrap_or(instruction.span)
}

fn mask_shell_comments(script: &str) -> String {
    let mut masked = script.as_bytes().to_vec();
    let mut offset = 0;
    for line in script.split_inclusive('\n') {
        let content = line.trim_start();
        if content.starts_with('#') && !content.starts_with("#!") {
            let start = offset + line.len() - content.len();
            for byte in &mut masked[start..offset + line.len()] {
                if *byte != b'\n' && *byte != b'\r' {
                    *byte = b' ';
                }
            }
        }
        offset += line.len();
    }
    String::from_utf8(masked).expect("masking preserves UTF-8")
}

fn rule_consistent_instruction_casing(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut expected_uppercase = None;
    let mut findings = Vec::new();
    for instruction in instrs {
        let spelling = instruction.keyword_span.text(raw);
        let is_uppercase = spelling
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
        let is_lowercase = spelling
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase());
        if !is_uppercase && !is_lowercase {
            findings.push(finding_at_span("DF076", Severity::Warning, instruction.keyword_span,
                format!("Instruction '{}' uses mixed casing", spelling),
                "Pick all-uppercase or all-lowercase Dockerfile instructions so the file stops shouting in two dialects."));
            continue;
        }
        if let Some(expected) = expected_uppercase {
            if expected != is_uppercase {
                findings.push(finding_at_span("DF076", Severity::Warning, instruction.keyword_span,
                    format!("Instruction '{}' does not match the file's instruction casing", spelling),
                    "Your Dockerfile switches typography halfway through the build. Pick one instruction casing and commit to it."));
            }
        } else {
            expected_uppercase = Some(is_uppercase);
        }
    }
    findings
}

fn rule_expose_proto_casing(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "EXPOSE").into_iter().flat_map(|instruction| {
        instruction.words.iter().filter_map(|word| {
            let (_, protocol) = word.value.rsplit_once('/')?;
            (protocol != protocol.to_ascii_lowercase()).then(|| finding_at_span("DF078", Severity::Warning, word.span,
                format!("EXPOSE protocol '{}' should be lowercase", protocol),
                "TCP and UDP are protocols, not acronyms in a ransom note. Use lowercase in EXPOSE."))
        }).collect::<Vec<_>>()
    }).collect()
}

fn rule_from_as_casing(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "FROM")
        .into_iter()
        .filter_map(|instruction| {
            let from_spelling = instruction.keyword_span.text(raw);
            let expected_uppercase = from_spelling
                .bytes()
                .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
            instruction
                .words
                .iter()
                .find(|word| word.value.eq_ignore_ascii_case("as"))
                .and_then(|word| {
                    let is_uppercase = word
                        .raw
                        .bytes()
                        .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
                    (expected_uppercase != is_uppercase).then(|| {
                        finding_at_span(
                            "DF079",
                            Severity::Warning,
                            word.span,
                            format!(
                                "'{}' should use the same casing as '{}'",
                                word.raw, from_spelling
                            ),
                            "FROM and AS are on the same team. Give them matching uniforms.",
                        )
                    })
                })
        })
        .collect()
}

fn rule_legacy_key_value_format(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs.iter().filter(|instruction| matches!(instruction.instruction.as_str(), "ENV" | "LABEL"))
        .filter_map(|instruction| {
            let words = &instruction.words;
            (words.len() >= 2 && !words[0].value.contains('='))
                .then(|| finding_at_span("DF082", Severity::Info, words[0].span,
                    format!("{} uses legacy space-separated key/value syntax", instruction.instruction),
                    "Space-separated ENV and LABEL values are vintage Dockerfile syntax. Use key=value before it starts growing sideburns."))
        }).collect()
}

fn rule_redundant_target_platform(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "FROM").into_iter().flat_map(|instruction| instruction.flags.iter().filter_map(|flag| {
        (flag.name.eq_ignore_ascii_case("platform") && flag.value.as_deref() == Some("$TARGETPLATFORM"))
            .then(|| finding_at_span("DF083", Severity::Warning, flag.span,
                "FROM --platform=$TARGETPLATFORM is redundant because it is the default".into(),
                "That platform flag repeats Docker's default. The Dockerfile is narrating what Docker already knows."))
    }).collect::<Vec<_>>()).collect()
}

fn rule_reserved_stage_name(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "FROM").into_iter().filter_map(|instruction| {
        let alias = parse_from_arguments(&instruction.arguments)?.alias?;
        (alias.eq_ignore_ascii_case("scratch")).then(|| instruction.words.iter().find(|word| word.value == alias).map(|word|
            finding_at_span("DF084", Severity::Warning, word.span, "Stage name 'scratch' is reserved".into(),
                "Calling a stage scratch can confuse readers with Docker's special empty image. Use a descriptive stage name."))).flatten()
    }).collect()
}

fn rule_stage_name_casing(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "FROM").into_iter().filter_map(|instruction| {
        let alias = parse_from_arguments(&instruction.arguments)?.alias?;
        (alias != alias.to_ascii_lowercase()).then(|| instruction.words.iter().find(|word| word.value == alias).map(|word|
            finding_at_span("DF085", Severity::Warning, word.span, format!("Stage name '{}' should be lowercase", alias),
                "Stage names are case-sensitive, which is a terrible place for a surprise. Keep them lowercase."))).flatten()
    }).collect()
}

fn global_args(instrs: &[Instruction]) -> std::collections::HashSet<String> {
    instrs
        .iter()
        .take_while(|instruction| instruction.instruction != "FROM")
        .filter(|instruction| instruction.instruction == "ARG")
        .filter_map(|instruction| instruction.words.first())
        .map(|word| {
            word.value
                .split('=')
                .next()
                .unwrap_or(&word.value)
                .to_string()
        })
        .collect()
}

fn known_build_variable(name: &str) -> bool {
    matches!(
        name,
        "BUILDPLATFORM"
            | "BUILDOS"
            | "BUILDARCH"
            | "BUILDVARIANT"
            | "TARGETPLATFORM"
            | "TARGETOS"
            | "TARGETARCH"
            | "TARGETVARIANT"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "FTP_PROXY"
            | "NO_PROXY"
            | "ALL_PROXY"
    )
}

fn rule_undefined_arg_in_from(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let declared = global_args(instrs);
    instrs_of(instrs, "FROM").into_iter().flat_map(|instruction| instruction.variables.iter().filter_map(|variable| {
        (!declared.contains(&variable.name) && !known_build_variable(&variable.name)).then(|| finding_at_span("DF086", Severity::Error, variable.span,
            format!("FROM references undefined ARG '{}'; declare it before the first FROM", variable.name),
            "This FROM variable has no global ARG declaration. Docker cannot build an image from vibes."))
    }).collect::<Vec<_>>()).collect()
}

fn rule_undefined_variable(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut stages: std::collections::HashMap<String, (std::collections::HashSet<String>, bool)> =
        std::collections::HashMap::new();
    let mut declared = std::collections::HashSet::new();
    let mut base_metadata_known = false;
    let mut current_alias = None;
    let mut in_stage = false;
    let mut findings = Vec::new();
    for instruction in instrs {
        if instruction.instruction == "FROM" {
            let Some(from) = parse_from_arguments(&instruction.arguments) else {
                continue;
            };
            (declared, base_metadata_known) = if from.image.eq_ignore_ascii_case("scratch") {
                (std::collections::HashSet::new(), true)
            } else {
                stages
                    .get(&from.image.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_else(|| (std::collections::HashSet::new(), false))
            };
            current_alias = from.alias.map(str::to_ascii_lowercase);
            in_stage = true;
            if let Some(alias) = &current_alias {
                stages.insert(alias.clone(), (declared.clone(), base_metadata_known));
            }
            continue;
        }
        if !in_stage {
            continue;
        }
        if instruction.instruction == "ARG" || instruction.instruction == "ENV" {
            for word in &instruction.words {
                declared.insert(
                    word.value
                        .split('=')
                        .next()
                        .unwrap_or(&word.value)
                        .to_string(),
                );
            }
            if let Some(alias) = &current_alias {
                stages.insert(alias.clone(), (declared.clone(), base_metadata_known));
            }
            continue;
        }
        if instruction.instruction == "RUN" {
            continue;
        }
        for variable in &instruction.variables {
            if base_metadata_known
                && !declared.contains(&variable.name)
                && !known_build_variable(&variable.name)
            {
                findings.push(finding_at_span("DF087", Severity::Error, variable.span,
                    format!("{} references undefined variable '{}'", instruction.instruction, variable.name),
                    "That variable appears from nowhere. Declare it with ARG or ENV before Docker starts improvising."));
            }
        }
    }
    findings
}

fn rule_parser_syntax(_instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    parse_document(raw)
        .diagnostics
        .into_iter()
        .map(|diagnostic| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF071".into(),
            severity: match diagnostic.severity {
                DiagnosticSeverity::Warning => Severity::Warning,
                DiagnosticSeverity::Error => Severity::Error,
            },
            line: diagnostic.span.start.line,
            message: diagnostic.message,
            roast: "The Dockerfile parser could not interpret this reliably; fix the syntax before trusting downstream lint results.".to_string(),
        })
        .collect()
}

fn instrs_of<'a>(instrs: &'a [Instruction], name: &str) -> Vec<&'a Instruction> {
    instrs.iter().filter(|i| i.instruction == name).collect()
}

/// Return instruction operands after BuildKit flags, preserving parsed quoted
/// values and using decoded JSON-array values when applicable.
fn instruction_operands(instruction: &Instruction) -> Vec<&str> {
    match &instruction.form {
        InstructionForm::Json(values) => values.iter().map(String::as_str).collect(),
        _ => instruction.words[instruction.flags.len()..]
            .iter()
            .map(|word| word.value.as_str())
            .collect(),
    }
}

fn is_absolute_container_path(path: &str) -> bool {
    let path = path.trim().trim_matches(['\'', '"']);
    path.starts_with('/')
        || path.starts_with('$')
        || matches!(path.as_bytes(), [drive, b':', b'/' | b'\\', ..] if drive.is_ascii_alphabetic())
}

fn ephemeral_mount_targets(instruction: &Instruction) -> Vec<&str> {
    instruction
        .flags
        .iter()
        .filter(|flag| flag.name == "mount")
        .filter_map(|flag| flag.value.as_deref())
        .filter_map(|mount| {
            let mut mount_type = "bind";
            let mut target = None;
            for option in mount.split(',') {
                let Some((name, value)) = option.split_once('=') else {
                    continue;
                };
                match name {
                    "type" => mount_type = value,
                    "target" | "dst" | "destination" => target = Some(value),
                    _ => {}
                }
            }
            matches!(mount_type, "cache" | "tmpfs")
                .then_some(target)
                .flatten()
                .filter(|target| !target.is_empty())
        })
        .collect()
}

fn has_ephemeral_mount_covering(instruction: &Instruction, path: &str) -> bool {
    ephemeral_mount_targets(instruction)
        .into_iter()
        .any(|target| {
            let target = target.trim_end_matches('/');
            path == target
                || path
                    .strip_prefix(target)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

fn has_language_cache_mount(instruction: &Instruction, tool: &str) -> bool {
    ephemeral_mount_targets(instruction)
        .into_iter()
        .any(|target| {
            let target = target.trim_end_matches('/').to_ascii_lowercase();
            target.ends_with("/.cache")
                || target.contains(&format!("/.cache/{tool}"))
                || target.ends_with(&format!("/{tool}"))
        })
}

fn run_script(instruction: &Instruction) -> String {
    let mut script = instruction.command.clone();
    for heredoc in &instruction.heredocs {
        script.push('\n');
        script.push_str(&heredoc.content);
    }
    script
}

fn has_instr(instrs: &[Instruction], name: &str) -> bool {
    instrs.iter().any(|i| i.instruction == name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FromArguments<'a> {
    image: &'a str,
    alias: Option<&'a str>,
}

#[derive(Clone, Debug, Default)]
struct StageRuntimeState {
    effective_user: Option<(String, usize)>,
    has_command: bool,
    has_workdir: bool,
    has_explicit_shell: bool,
    /// `false` means an external base may contribute runtime configuration
    /// that cannot be determined from this Dockerfile alone.
    base_metadata_known: bool,
}

fn inherited_runtime_state(
    from: FromArguments<'_>,
    stages: &std::collections::HashMap<String, StageRuntimeState>,
) -> StageRuntimeState {
    if from.image.eq_ignore_ascii_case("scratch") {
        return StageRuntimeState {
            base_metadata_known: true,
            ..StageRuntimeState::default()
        };
    }
    stages
        .get(&from.image.to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
}

fn final_runtime_state(instrs: &[Instruction]) -> Option<StageRuntimeState> {
    let mut stages = std::collections::HashMap::new();
    let mut current_alias = None;
    let mut state = None;
    for instruction in instrs {
        if instruction.instruction == "FROM" {
            let from = parse_from_arguments(&instruction.arguments)?;
            current_alias = from.alias.map(str::to_ascii_lowercase);
            state = Some(inherited_runtime_state(from, &stages));
        } else if let Some(current) = state.as_mut() {
            match instruction.instruction.as_str() {
                "USER" => {
                    current.effective_user =
                        Some((instruction.arguments.trim().to_string(), instruction.line));
                }
                "CMD" | "ENTRYPOINT" => current.has_command = true,
                "WORKDIR" => current.has_workdir = true,
                "SHELL" => current.has_explicit_shell = true,
                _ => {}
            }
        }
        if let (Some(alias), Some(current)) = (&current_alias, &state) {
            stages.insert(alias.clone(), current.clone());
        }
    }
    state
}

/// Parse `FROM [--flag=value ...] image [AS alias]` arguments.
///
/// Keeping this in one place prevents rules from mistaking options such as
/// `--platform=$BUILDPLATFORM` for the image or shifting the `AS` position.
fn parse_from_arguments(arguments: &str) -> Option<FromArguments<'_>> {
    let mut tokens = arguments.split_whitespace();
    let image = tokens.find(|token| !token.starts_with("--"))?;
    let alias = match (tokens.next(), tokens.next()) {
        (Some(keyword), Some(alias)) if keyword.eq_ignore_ascii_case("as") => Some(alias),
        _ => None,
    };
    Some(FromArguments { image, alias })
}

fn persistent_stage_indices(instrs: &[Instruction]) -> std::collections::HashSet<usize> {
    #[derive(Default)]
    struct Stage {
        parent: Option<usize>,
    }

    let mut stages = Vec::<Stage>::new();
    let mut aliases = std::collections::HashMap::<String, usize>::new();
    let mut instruction_stages = Vec::with_capacity(instrs.len());
    let mut current_stage = None;

    for instruction in instrs {
        if instruction.instruction == "FROM" {
            let from = parse_from_arguments(&instruction.arguments);
            let parent = from.and_then(|from| {
                aliases
                    .get(&from.image.to_ascii_lowercase())
                    .copied()
                    .or_else(|| {
                        from.image
                            .parse::<usize>()
                            .ok()
                            .filter(|index| *index < stages.len())
                    })
            });
            let index = stages.len();
            stages.push(Stage { parent });
            if let Some(alias) = from.and_then(|from| from.alias) {
                aliases.insert(alias.to_ascii_lowercase(), index);
            }
            current_stage = Some(index);
        }
        instruction_stages.push(current_stage);
    }

    let mut persistent = std::collections::HashSet::new();
    if !stages.is_empty() {
        persistent.insert(stages.len() - 1);
    }

    loop {
        let mut changed = false;
        for index in persistent.clone() {
            if let Some(parent) = stages[index].parent {
                changed |= persistent.insert(parent);
            }
        }
        for (instruction, stage) in instrs.iter().zip(&instruction_stages) {
            if instruction.instruction != "COPY"
                || !stage.is_some_and(|stage| persistent.contains(&stage))
            {
                continue;
            }
            let copies_root = matches!(
                instruction_operands(instruction).first(),
                Some(&"/" | &"/.")
            );
            if !copies_root {
                continue;
            }
            let source_stage = instruction
                .flags
                .iter()
                .find(|flag| flag.name.eq_ignore_ascii_case("from"))
                .and_then(|flag| flag.value.as_deref())
                .and_then(|source| {
                    aliases
                        .get(&source.to_ascii_lowercase())
                        .copied()
                        .or_else(|| {
                            source
                                .parse::<usize>()
                                .ok()
                                .filter(|index| *index < stages.len())
                        })
                });
            if let Some(source_stage) = source_stage {
                changed |= persistent.insert(source_stage);
            }
        }
        if !changed {
            break;
        }
    }

    persistent
}

fn layer_persistent_stage_indices(instrs: &[Instruction]) -> std::collections::HashSet<usize> {
    let mut parents = Vec::<Option<usize>>::new();
    let mut aliases = std::collections::HashMap::<String, usize>::new();

    for instruction in instrs_of(instrs, "FROM") {
        let from = parse_from_arguments(&instruction.arguments);
        let parent = from.and_then(|from| {
            aliases
                .get(&from.image.to_ascii_lowercase())
                .copied()
                .or_else(|| {
                    from.image
                        .parse::<usize>()
                        .ok()
                        .filter(|index| *index < parents.len())
                })
        });
        let index = parents.len();
        parents.push(parent);
        if let Some(alias) = from.and_then(|from| from.alias) {
            aliases.insert(alias.to_ascii_lowercase(), index);
        }
    }

    let mut persistent = std::collections::HashSet::new();
    let mut current = parents.len().checked_sub(1);
    while let Some(index) = current {
        if !persistent.insert(index) {
            break;
        }
        current = parents[index];
    }
    persistent
}

fn instruction_stage_indices(instrs: &[Instruction]) -> Vec<Option<usize>> {
    let mut stage = None;
    let mut next_stage = 0;
    instrs
        .iter()
        .map(|instruction| {
            if instruction.instruction == "FROM" {
                stage = Some(next_stage);
                next_stage += 1;
            }
            stage
        })
        .collect()
}

fn cache_reaches_final_image(
    instrs: &[Instruction],
    instruction_stages: &[Option<usize>],
    persistent_stages: &std::collections::HashSet<usize>,
    layer_stages: &std::collections::HashSet<usize>,
    instruction_index: usize,
    cleanup: fn(&str) -> bool,
) -> bool {
    let Some(stage) = instruction_stages[instruction_index] else {
        return false;
    };
    if !persistent_stages.contains(&stage) {
        return false;
    }
    if layer_stages.contains(&stage) {
        return true;
    }

    // A root COPY into a later stage copies the source stage's merged
    // filesystem, not its layer history. Cleanup performed before that
    // snapshot therefore prevents the cache from reaching the final image.
    !instrs[instruction_index + 1..]
        .iter()
        .zip(&instruction_stages[instruction_index + 1..])
        .take_while(|(_, candidate_stage)| **candidate_stage == Some(stage))
        .any(|(instruction, _)| instruction.instruction == "RUN" && cleanup(&instruction.arguments))
}

fn cleans_apt_cache(command: &str) -> bool {
    let apt_distclean =
        Regex::new(r"\bapt-get\s+dist-?clean\b").expect("valid apt dist-clean regex");
    removes_cache_path(command, "/var/lib/apt/lists")
        || apt_distclean.is_match(command)
        || removes_brace_expanded_apt_state(command)
}

fn cleans_dnf_cache(command: &str) -> bool {
    let clean =
        Regex::new(r"\b(?:microdnf|dnf|tdnf)\b[^;&|]*\bclean\b").expect("valid dnf cleanup regex");
    clean.is_match(command)
        || removes_cache_path(command, "/var/cache/dnf")
        || removes_cache_path(command, "/var/cache/tdnf")
        || removes_cache_path(command, "/var/cache/yum")
}

fn cleans_yum_cache(command: &str) -> bool {
    let clean = Regex::new(r"\byum\b[^;&|]*\bclean\b").expect("valid yum cleanup regex");
    clean.is_match(command) || removes_cache_path(command, "/var/cache/yum")
}

fn persistent_run_instructions(instrs: &[Instruction]) -> Vec<&Instruction> {
    let persistent = persistent_stage_indices(instrs);
    let mut stage = None;
    let mut next_stage = 0;
    instrs
        .iter()
        .filter(|instruction| {
            if instruction.instruction == "FROM" {
                stage = Some(next_stage);
                next_stage += 1;
                return false;
            }
            instruction.instruction == "RUN"
                && stage.is_some_and(|stage| persistent.contains(&stage))
        })
        .collect()
}

fn rule_latest_tag(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut stage_aliases = std::collections::HashSet::new();
    let global_args = global_arg_defaults(instrs);
    let mut findings = Vec::new();

    for instruction in instrs_of(instrs, "FROM") {
        let Some(from) = parse_from_arguments(&instruction.arguments) else {
            continue;
        };
        let unresolved_base = from.image;
        let resolved_base = expand_known_build_args(unresolved_base, &global_args);
        let base = resolved_base
            .as_deref()
            .unwrap_or(unresolved_base)
            .trim_matches(['\'', '"']);
        // A build argument can supply either a tagged image or a digest at
        // build time. Do not claim it is unpinned when that value is unknown.
        if base.contains('$') {
            if let Some(alias) = from.alias {
                stage_aliases.insert(alias.to_lowercase());
            }
            continue;
        }
        let is_previous_stage = stage_aliases.contains(&base.to_lowercase());
        if !is_previous_stage
            && !base.eq_ignore_ascii_case("scratch")
            && (image_uses_latest_tag(base) || (!image_has_tag(base) && !base.contains('@')))
        {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF001".into(),
                severity: Severity::Warning,
                line: instruction.line,
                message: format!("'{}' uses an unpinned image tag", base),
                roast: "Pinning to 'latest' is like ordering 'whatever' at a restaurant and then \
                        complaining when your image breaks in prod. Use a real tag."
                    .to_string(),
            });
        }
        if let Some(alias) = from.alias {
            stage_aliases.insert(alias.to_lowercase());
        }
    }

    findings
}

fn image_has_tag(image: &str) -> bool {
    image
        .rsplit_once('/')
        .map_or(image, |(_, name)| name)
        .contains(':')
}

fn image_uses_latest_tag(image: &str) -> bool {
    let name = image.rsplit_once('/').map_or(image, |(_, name)| name);
    let Some((_, tag)) = name.rsplit_once(':') else {
        return false;
    };
    tag.split(['-', '_', '.'])
        .any(|component| component.eq_ignore_ascii_case("latest"))
}

fn global_arg_defaults(instrs: &[Instruction]) -> std::collections::HashMap<String, String> {
    instrs
        .iter()
        .take_while(|instruction| instruction.instruction != "FROM")
        .filter(|instruction| instruction.instruction == "ARG")
        .filter_map(|instruction| instruction.words.first())
        .filter_map(|word| word.value.split_once('='))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn expand_known_build_args(
    value: &str,
    defaults: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let variable = Regex::new(
        r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))",
    )
    .expect("valid build argument regex");
    let mut expanded = value.to_string();
    for _ in 0..8 {
        let mut unresolved = false;
        let next = variable
            .replace_all(&expanded, |captures: &regex::Captures<'_>| {
                let name = captures
                    .name("braced")
                    .or_else(|| captures.name("plain"))
                    .expect("variable capture exists")
                    .as_str();
                defaults.get(name).cloned().unwrap_or_else(|| {
                    unresolved = true;
                    captures[0].to_string()
                })
            })
            .into_owned();
        if next == expanded {
            return (!unresolved).then_some(next);
        }
        expanded = next;
    }
    (!expanded.contains('$')).then_some(expanded)
}

fn rule_running_as_root(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    final_runtime_state(instrs)
        .and_then(|state| state.effective_user)
        .filter(|(user, _)| is_root_user(user))
        .map(|(_, line)| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF002".into(),
            severity: Severity::Error,
            line,
            message: "Container is explicitly set to run as root".to_string(),
            roast: "Congratulations, you're running as root. Your security team is crying, \
                    your CISO is drafting a strongly-worded email, and a hacker somewhere \
                    just smiled."
                .to_string(),
        })
        .into_iter()
        .collect()
}

fn is_root_user(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "root" | "0" | "0:0" | "root:root"
    )
}

fn rule_no_multistage(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let from_count = instrs_of(instrs, "FROM").len();
    if from_count > 1 {
        return vec![];
    }
    let first_from = match instrs_of(instrs, "FROM").into_iter().next() {
        Some(f) => f,
        None => return vec![],
    };
    let build_images = [
        "golang", "node", "rust", "maven", "gradle", "openjdk", "python", "dotnet", "gcc",
    ];
    let img = first_from.arguments.to_lowercase();
    if build_images.iter().any(|b| img.contains(b)) {
        return vec![Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF011".into(),
            severity: Severity::Info,
            line: first_from.line,
            message: "Single-stage build with a heavy build image — consider multi-stage builds"
                .to_string(),
            roast: "Shipping your entire build toolchain to production? Your 2GB Go image is \
                    basically a free gift to anyone who gets shell access. Multi-stage builds \
                    exist. They're fantastic. Use them."
                .to_string(),
        }];
    }
    vec![]
}

fn rule_many_run_layers(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut consecutive = 0usize;
    let mut start_line = 0usize;
    for i in instrs {
        if i.instruction == "RUN" {
            if consecutive == 0 {
                start_line = i.line;
            }
            consecutive += 1;
        } else if i.instruction == "FROM" {
            consecutive = 0;
        } else if consecutive > 0 {
            if consecutive >= 4 {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF003".into(),
                    severity: Severity::Info,
                    line: start_line,
                    message: format!(
                        "{} consecutive RUN instructions could be merged into one",
                        consecutive
                    ),
                    roast: format!(
                        "{} separate RUN layers? Your image has more layers than a mid-2000s emo \
                         band. Combine them with && and save everyone's bandwidth.",
                        consecutive
                    ),
                });
            }
            consecutive = 0;
        }
    }
    if consecutive >= 4 {
        findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF003".into(),
            severity: Severity::Info,
            line: start_line,
            message: format!("{} consecutive RUN instructions could be merged into one", consecutive),
            roast: format!(
                "{} separate RUN layers? Your image is basically an onion — except nobody's \
                 crying because it's beautiful; they're crying because it takes 10 minutes to pull.", consecutive
            ),
        });
    }
    findings
}

fn rule_add_instead_of_copy(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "ADD")
        .into_iter()
        .filter(|i| {
            // Skip --chown, --checksum and other flags to find the real source argument
            let source = match i
                .arguments
                .split_whitespace()
                .find(|t| !t.starts_with("--"))
            {
                Some(s) => s,
                None => return false,
            };
            let is_url = source.contains("://");
            let is_archive = source.ends_with(".tar.gz")
                || source.ends_with(".tgz")
                || source.ends_with(".tar.xz")
                || source.ends_with(".tar.bz2")
                || source.ends_with(".tar");
            !is_url && !is_archive
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF006".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "ADD used for local file — prefer COPY".to_string(),
            roast: "Using ADD to copy local files is like taking a helicopter to cross the \
                    street. COPY exists, it's right there, it's boring and correct — which is \
                    everything you want in infrastructure."
                .to_string(),
        })
        .collect()
}

fn rule_copy_all(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut direct_scratch_stage = false;
    let mut findings = Vec::new();
    for instruction in instrs {
        if instruction.instruction == "FROM" {
            direct_scratch_stage = parse_from_arguments(&instruction.arguments)
                .is_some_and(|from| from.image.eq_ignore_ascii_case("scratch"));
            continue;
        }
        if instruction.instruction != "COPY" {
            continue;
        }
        let arguments = instruction.arguments.trim();
        if !(arguments.starts_with(". ") || arguments == ".") {
            continue;
        }
        findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF007".into(),
            severity: if direct_scratch_stage {
                Severity::Info
            } else {
                Severity::Warning
            },
            line: instruction.line,
            message: "COPY . copies the entire build context — consider a .dockerignore file"
                .to_string(),
            roast: "COPY . — dumping your entire project including node_modules, .git history, \
                    and that .env file with the production database password into the image. \
                    Bold. Reckless. Very DevOps of you."
                .to_string(),
        });
    }
    findings
}

fn rule_cd_instead_of_workdir(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"\bcd\s+[^\s;|&]+").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&i.arguments))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF008".into(),
            severity: Severity::Info,
            line: i.line,
            message: "Using 'cd' in RUN — prefer WORKDIR instruction".to_string(),
            roast: "`cd` in a RUN instruction: not wrong, but every new RUN starts fresh anyway, \
                    so you're cosplaying as a shell script when you should be writing a Dockerfile. \
                    WORKDIR is your friend.".to_string(),
        })
        .collect()
}

fn rule_relative_workdir(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "WORKDIR")
        .into_iter()
        .filter(|i| {
            let path = i.arguments.trim().trim_matches(['\'', '"']);
            !is_absolute_container_path(path)
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF009".into(),
            severity: Severity::Warning,
            line: i.line,
            message: format!(
                "WORKDIR '{}' is relative — use an absolute path",
                i.arguments.trim()
            ),
            roast: "A relative WORKDIR? You're setting your working directory relative to... \
                    what, exactly? Hope? Dreams? Use an absolute path like a grown-up."
                .to_string(),
        })
        .collect()
}

fn rule_sudo_usage(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut stages = std::collections::HashMap::new();
    let mut current_alias = None;
    let mut state = StageRuntimeState::default();
    let mut findings = Vec::new();
    for instruction in instrs {
        match instruction.instruction.as_str() {
            "FROM" => {
                if let Some(from) = parse_from_arguments(&instruction.arguments) {
                    state = inherited_runtime_state(from, &stages);
                    current_alias = from.alias.map(str::to_ascii_lowercase);
                }
            }
            "USER" => {
                state.effective_user =
                    Some((instruction.arguments.trim().to_string(), instruction.line));
            }
            "RUN" if shell_invokes_command(&run_script(instruction), "sudo") => {
                let explicitly_non_root = state
                    .effective_user
                    .as_ref()
                    .is_some_and(|(user, _)| !is_root_user(user));
                if explicitly_non_root {
                    continue;
                }
                let metadata_unknown = state.effective_user.is_none() && !state.base_metadata_known;
                findings.push(finding_at_span(
                    "DF010",
                    if metadata_unknown {
                        Severity::Info
                    } else {
                        Severity::Warning
                    },
                    shell_command_span(raw, instruction, "sudo"),
                    if metadata_unknown {
                        "sudo use depends on the external base image's runtime user".to_string()
                    } else {
                        "sudo used while the build is already running as root".to_string()
                    },
                    "Use sudo only when the effective build user is non-root; otherwise invoke the command directly.",
                ));
            }
            _ => {}
        }
        if let Some(alias) = &current_alias {
            stages.insert(alias.clone(), state.clone());
        }
    }
    findings
}

fn rule_no_healthcheck(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    if has_instr(instrs, "HEALTHCHECK") {
        return vec![];
    }
    if !has_instr(instrs, "EXPOSE") && !has_instr(instrs, "CMD") {
        return vec![];
    }
    vec![Finding {
        column: 0,
        end_line: 0,
        end_column: 0,
        rule: "DF012".into(),
        severity: Severity::Info,
        line: 0,
        message: "No HEALTHCHECK defined".to_string(),
        roast: "No HEALTHCHECK? Your container is basically on the honor system. 'It's fine, \
                I'm sure it's fine.' Meanwhile Kubernetes is just restarting it every 30 seconds \
                wondering what went wrong."
            .to_string(),
    }]
}

fn rule_cmd_without_entrypoint(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    vec![]
}

fn rule_shell_form_entrypoint(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "ENTRYPOINT")
        .into_iter()
        .filter(|i| !i.arguments.trim().starts_with('['))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF018".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "ENTRYPOINT in shell form prevents signal propagation".to_string(),
            roast: "Shell-form ENTRYPOINT means your app runs as a child of /bin/sh. When \
                    Kubernetes sends SIGTERM, your app doesn't get it — /bin/sh does, and \
                    /bin/sh doesn't care. Use exec form: ENTRYPOINT [\"cmd\", \"arg\"]."
                .to_string(),
        })
        .collect()
}

fn rule_deprecated_maintainer(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "MAINTAINER")
        .into_iter()
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF019".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "MAINTAINER is deprecated".to_string(),
            roast: "MAINTAINER has been deprecated since Docker 1.13. That was 2017. \
                    Your Dockerfile is old enough to be in middle school. \
                    Use LABEL maintainer=\"...\" like the rest of us."
                .to_string(),
        })
        .collect()
}

fn rule_no_expose(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    if has_instr(instrs, "EXPOSE") {
        return vec![];
    }
    if !has_instr(instrs, "CMD") && !has_instr(instrs, "ENTRYPOINT") {
        return vec![];
    }
    vec![Finding {
        column: 0,
        end_line: 0,
        end_column: 0,
        rule: "DF022".into(),
        severity: Severity::Info,
        line: 0,
        message: "No EXPOSE instruction — consider documenting which ports this service uses"
            .to_string(),
        roast: "No EXPOSE? Your container is a mystery box. Is it a web server? A database? \
                A very slow random number generator? EXPOSE is documentation — it tells the \
                next developer which port to knock on."
            .to_string(),
    }]
}

fn rule_multiple_from_no_alias(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let froms: Vec<_> = instrs_of(instrs, "FROM");
    let stage_count = froms.len();
    if stage_count <= 1 {
        return vec![];
    }

    // A final stage cannot be referenced by a later COPY --from instruction, so
    // requiring it to have a stage name adds noise without improving safety.
    froms
        .into_iter()
        .take(stage_count - 1)
        .filter(|i| parse_from_arguments(&i.arguments).is_some_and(|from| from.alias.is_none()))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF023".into(),
            severity: Severity::Info,
            line: i.line,
            message: "Multi-stage FROM without AS alias — hard to reference later".to_string(),
            roast: "Multi-stage FROM without an alias. How will you COPY --from=... this? \
                    By index? \"--from=2\"? That's fragile. Give your stages names like \
                    a civilized person. FROM golang:1.21 AS builder."
                .to_string(),
        })
        .collect()
}

fn rule_from_latest_alias(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    vec![]
}

fn rule_shell_form_cmd(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "CMD")
        .into_iter()
        .filter(|i| !i.arguments.trim().starts_with('['))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF025".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "CMD in shell form — prefer exec form [\"executable\", \"arg\"]".to_string(),
            roast: "Shell-form CMD wraps your process in /bin/sh -c, which means PID 1 is the \
                    shell, not your app. Signal handling breaks, graceful shutdown breaks, and \
                    your ops team breaks (emotionally). Use exec form."
                .to_string(),
        })
        .collect()
}

fn rule_copy_root(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut direct_scratch_stage = false;
    let mut findings = Vec::new();

    for instruction in instrs {
        if instruction.instruction == "FROM" {
            direct_scratch_stage = parse_from_arguments(&instruction.arguments)
                .is_some_and(|from| from.image.eq_ignore_ascii_case("scratch"));
            continue;
        }
        if instruction.instruction != "COPY"
            || direct_scratch_stage
            || instruction
                .flags
                .iter()
                .any(|flag| flag.name.eq_ignore_ascii_case("from"))
            || !matches!(instruction_operands(instruction).last(), Some(&"/" | &"/."))
        {
            continue;
        }
        let operands = instruction_operands(instruction);
        let sources = &operands[..operands.len().saturating_sub(1)];
        let broad_source = sources.len() > 1
            || sources.first().is_some_and(|source| {
                matches!(*source, "." | "./" | "/" | "/.")
                    || source.ends_with('/')
                    || source.contains(['*', '?', '['])
            });
        if !broad_source {
            continue;
        }
        findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF026".into(),
            severity: Severity::Warning,
            line: instruction.line,
            message: "Broad COPY to filesystem root may overwrite system files".to_string(),
            roast: "Copying files directly to /? Brave. Reckless. Chaotic. You're one typo away \
                    from overwriting /bin/sh and creating a container that doesn't even boot. \
                    Use a dedicated app directory."
                .to_string(),
        });
    }

    findings
}

fn rule_pip_no_cache(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut stage_cache_settings = std::collections::HashMap::new();
    let mut stage_uv_cache_dirs = std::collections::HashMap::<String, Option<String>>::new();
    let mut current_stage = None;
    let mut pip_cache_disabled = false;
    let mut uv_cache_dir: Option<String> = None;
    let persistent_runs = persistent_run_instructions(instrs)
        .into_iter()
        .map(|instruction| instruction.span.start.offset)
        .collect::<std::collections::HashSet<_>>();
    let install = pip_install_regex();

    instrs
        .iter()
        .filter_map(|instruction| match instruction.instruction.as_str() {
            "FROM" => {
                let base = parse_from_arguments(&instruction.arguments).map(|from| from.image);
                pip_cache_disabled = base
                    .and_then(|base| stage_cache_settings.get(base))
                    .copied()
                    .unwrap_or(false);
                uv_cache_dir = base
                    .and_then(|base| stage_uv_cache_dirs.get(base))
                    .cloned()
                    .flatten();
                current_stage = instruction
                    .words
                    .iter()
                    .position(|word| word.value.eq_ignore_ascii_case("as"))
                    .and_then(|position| instruction.words.get(position + 1))
                    .map(|word| word.value.clone());
                if let Some(stage) = &current_stage {
                    stage_cache_settings.insert(stage.clone(), pip_cache_disabled);
                    stage_uv_cache_dirs.insert(stage.clone(), uv_cache_dir.clone());
                }
                None
            }
            "ENV" => {
                for (name, value, _) in instruction_assignments(instruction) {
                    if name == "PIP_NO_CACHE_DIR" {
                        pip_cache_disabled = pip_boolean(value);
                    } else if name == "UV_CACHE_DIR" {
                        uv_cache_dir = Some(value.trim_matches(['\'', '"']).to_string());
                    }
                    if let Some(stage) = &current_stage {
                        stage_cache_settings.insert(stage.clone(), pip_cache_disabled);
                        stage_uv_cache_dirs.insert(stage.clone(), uv_cache_dir.clone());
                    }
                }
                None
            }
            "RUN" => {
                if !persistent_runs.contains(&instruction.span.start.offset) {
                    return None;
                }
                pip_cache_violation(
                    instruction,
                    &install,
                    pip_cache_disabled,
                    uv_cache_dir.as_deref(),
                )
                .map(|(uv, ordinal)| (instruction, uv, ordinal))
            }
            _ => None,
        })
        .map(|(instruction, uv, ordinal)| {
            finding_at_span(
                "DF030",
                Severity::Info,
                pip_install_span(raw, instruction, &install, ordinal),
                if uv {
                    "uv pip install without --no-cache wastes space in the image layer".to_string()
                } else {
                    "pip install without --no-cache-dir wastes space in the image layer".to_string()
                },
                "pip install without --no-cache-dir? You're carrying around a pip cache in \
                 your production image like a tourist with a suitcase full of hotel shampoos. \
                 You don't need those. Add the installer-specific no-cache flag.",
            )
        })
        .collect()
}

fn pip_install_regex() -> Regex {
    Regex::new(
        r"(?i)(?:(?P<uv>\buv\b)\s+pip\s+install|(?P<pip>\bpip3?\b)\s+install|(?P<python>\bpython(?:[0-9]+(?:\.[0-9]+)?)?\b)[^;&|\n]*\s+-m\s+pip\s+install)",
    )
    .expect("valid pip install regex")
}

fn pip_cache_violation(
    instruction: &Instruction,
    install: &Regex,
    pip_cache_disabled: bool,
    uv_cache_dir: Option<&str>,
) -> Option<(bool, usize)> {
    let arguments = &instruction.arguments;
    let pip_cleanup = arguments.contains("pip cache purge")
        || removes_cache_path(arguments, "/root/.cache/pip")
        || removes_cache_path(arguments, "/root/.cache");
    let uv_cleanup = arguments.contains("uv cache clean");
    let segments = shell_command_segments(arguments);

    install
        .captures_iter(arguments)
        .enumerate()
        .find_map(|(ordinal, capture)| {
            let matched = capture.get(0)?;
            let segment = segments.iter().find(|segment| {
                segment.start <= matched.start() && matched.start() < segment.end
            })?;
            let invocation = &arguments[matched.start()..segment.end];
            let uv = capture.name("uv").is_some();
            let unsafe_cache = if uv {
                !invocation.contains("--no-cache")
                    && !uv_cleanup
                    && !has_language_cache_mount(instruction, "uv")
                    && !uv_cache_dir.is_some_and(|directory| {
                        has_ephemeral_mount_covering(instruction, directory)
                    })
            } else {
                !invocation.contains("--no-cache-dir")
                    && !pip_cleanup
                    && !pip_cache_disabled
                    && !has_language_cache_mount(instruction, "pip")
            };
            unsafe_cache.then_some((uv, ordinal))
        })
}

fn pip_install_span(
    source: &str,
    instruction: &Instruction,
    install: &Regex,
    ordinal: usize,
) -> SourceSpan {
    install
        .captures_iter(&instruction.raw)
        .nth(ordinal)
        .and_then(|capture| {
            ["uv", "pip", "python"]
                .iter()
                .find_map(|name| capture.name(name))
        })
        .map(|matched| instruction_match_span(source, instruction, matched.start(), matched.end()))
        .unwrap_or(instruction.span)
}

/// pip accepts the same truthy spellings as Python's boolean configuration
/// parser for environment-backed options.
fn pip_boolean(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn rule_npm_install(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let npm_install = Regex::new(r"\bnpm\s+install\b").expect("valid npm install regex");
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            npm_install.is_match(a)
                && !a.contains("--production")
                && !a.contains("--omit=dev")
                && !Regex::new(r"(?:^|\s)--global(?:\s|$)|(?:^|\s)-g(?:\s|$)")
                    .expect("valid npm global-install regex")
                    .is_match(a)
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF031".into(),
            severity: Severity::Info,
            line: i.line,
            message: "npm install used — consider npm ci for reproducible builds".to_string(),
            roast: "`npm install` in a Dockerfile: non-deterministic, slower than `npm ci`, \
                    and potentially installs different versions than your lockfile specifies. \
                    `npm ci` exists specifically for CI/CD and containers. Use it."
                .to_string(),
        })
        .collect()
}

fn rule_python_env_vars(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let first_from = match instrs_of(instrs, "FROM").into_iter().next() {
        Some(f) => f,
        None => return vec![],
    };
    if !first_from.arguments.to_lowercase().contains("python") {
        return vec![];
    }
    let env_args: String = instrs_of(instrs, "ENV")
        .iter()
        .map(|i| i.arguments.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let mut findings = Vec::new();
    if !env_args.contains("PYTHONDONTWRITEBYTECODE") {
        findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF032".into(),
            severity: Severity::Info,
            line: 0,
            message: "PYTHONDONTWRITEBYTECODE not set — Python will write .pyc files to the image"
                .to_string(),
            roast: "Python is quietly writing .pyc bytecode files all over your image. \
                    Set PYTHONDONTWRITEBYTECODE=1 and stop Python from hoarding compiled cache \
                    files in your container like a digital hoarder."
                .to_string(),
        });
    }
    if !env_args.contains("PYTHONUNBUFFERED") {
        findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF032".into(),
            severity: Severity::Info,
            line: 0,
            message: "PYTHONUNBUFFERED not set — Python output may not appear in logs".to_string(),
            roast: "PYTHONUNBUFFERED not set? Your Python app is buffering stdout, meaning \
                    logs disappear into the void and you won't see output until the buffer \
                    flushes — which is never, because your container crashed. Set PYTHONUNBUFFERED=1.".to_string(),
        });
    }
    findings
}

fn rule_no_dockerignore(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    vec![]
}

fn rule_chmod_777(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let re =
        Regex::new(r"\bchmod\b(?:\s+-[^\s]+)*\s+(?P<mode>0?777|(?:a|ugo|o)\+[rwxX]*w[rwxX]*)\b")
            .expect("valid world-writable chmod regex");
    let unsafe_mode = Regex::new(r"^(?:0?777|(?:a|ugo|o)\+[rwxX]*w[rwxX]*)$")
        .expect("valid world-writable mode regex");
    let mut findings = instrs_of(instrs, "RUN")
        .into_iter()
        .flat_map(|instruction| {
            re.captures_iter(&instruction.raw)
                .filter_map(|capture| {
                    let whole = capture.get(0)?;
                    let mode = capture.name("mode")?;
                    if chmod_is_removed_temporary_directory(
                        &instruction.raw,
                        whole.start(),
                        mode.end(),
                    ) {
                        return None;
                    }
                    Some(finding_at_span(
                        "DF034",
                        Severity::Error,
                        instruction_match_span(raw, instruction, mode.start(), mode.end()),
                        format!(
                            "chmod {} grants world-writable permissions — overly permissive",
                            mode.as_str()
                        ),
                        "chmod 777? Giving everyone read, write, and execute access is the filesystem equivalent of leaving your front door open with a sign that says 'free stuff inside'. Minimum permissions, please.",
                    ))
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    for instruction in instrs_of(instrs, "COPY") {
        for flag in &instruction.flags {
            let Some(mode) = flag
                .name
                .eq_ignore_ascii_case("chmod")
                .then_some(flag.value.as_deref())
                .flatten()
                .filter(|mode| unsafe_mode.is_match(mode))
            else {
                continue;
            };
            let relative_start = flag
                .span
                .start
                .offset
                .saturating_sub(instruction.span.start.offset);
            let flag_text = flag.span.text(raw);
            let mode_start = flag_text.find(mode).unwrap_or_default();
            findings.push(finding_at_span(
                "DF034",
                Severity::Error,
                instruction_match_span(
                    raw,
                    instruction,
                    relative_start + mode_start,
                    relative_start + mode_start + mode.len(),
                ),
                format!("COPY --chmod={mode} grants world-writable permissions — overly permissive"),
                "COPY creates this path with world-writable permissions in the image. Use the minimum mode required by the runtime user.",
            ));
        }
    }
    findings.sort_by_key(|finding| (finding.line, finding.column));
    findings
}

fn chmod_is_removed_temporary_directory(raw: &str, chmod_start: usize, mode_end: usize) -> bool {
    let assignment = Regex::new(
        r#"(?m)\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)=["']?\$\(mktemp\s+-d(?:\s+[^)]*)?\)["']?"#,
    )
    .expect("valid mktemp assignment regex");
    let target_end = raw[mode_end..]
        .find('\n')
        .map_or(raw.len(), |offset| mode_end + offset);
    let target = &raw[mode_end..target_end];
    let removed = assignment
        .captures_iter(&raw[..chmod_start])
        .any(|capture| {
            let name = &capture["name"];
            let reference = Regex::new(&format!(r#"["']?\$(?:\{{{name}\}}|{name})["']?"#))
                .expect("escaped variable creates a valid regex");
            if !reference.is_match(target) {
                return false;
            }
            let removal = Regex::new(&format!(r#"(?s)\brm\b[^;&|]*\$(?:\{{{name}\}}|{name}\b)"#))
                .expect("escaped variable creates a valid removal regex");
            removal.is_match(&raw[mode_end..])
        });
    removed
}

fn rule_curl_no_fail(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            let script = run_script(i);
            // only flag when curl is actually fetching something, not being installed as a package
            let has_url = a.contains("http://") || a.contains("https://") || a.contains("ftp://");
            has_url
                && shell_invokes_command(&script, "curl")
                && !executes_remote_script(&script)
                && !a.contains("--fail")
                && !a.contains("-fsSL")
                && !a.contains("-fsS")
                && !a.contains("-fL")
                && !a.contains("-fs ")
                && !{
                    let mut found = false;
                    for part in a.split_whitespace() {
                        if part.starts_with('-') && !part.starts_with("--") && part.contains('f') {
                            found = true;
                            break;
                        }
                    }
                    found
                }
        })
        .map(|i| {
            finding_at_span(
                "DF035",
                Severity::Info,
                shell_command_span(raw, i, "curl"),
                "curl without --fail — HTTP errors won't cause the RUN step to fail".to_string(),
                "curl without --fail means a 404 or 500 response silently succeeds. \
                    Your build will happily continue after downloading an error page and \
                    treating it as a binary. Add --fail and save yourself a 2am debugging session.",
            )
        })
        .collect()
}

fn rule_no_cmd_or_entrypoint(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let Some(state) = final_runtime_state(instrs) else {
        return vec![];
    };
    if state.has_command || instrs.len() < 3 {
        return vec![];
    }
    let (message, roast) = if state.base_metadata_known {
        (
            "No CMD or ENTRYPOINT defined — the container has no default command",
            "The final stage has no default process. Add one if this stage is intended to run.",
        )
    } else {
        (
            "No CMD or ENTRYPOINT declared in the final stage — the default command depends on the base image",
            "This stage inherits its default process from external image metadata. Declare it explicitly if that dependency is unintended.",
        )
    };
    vec![Finding {
        column: 0,
        end_line: 0,
        end_column: 0,
        rule: "DF036".into(),
        severity: Severity::Info,
        line: 0,
        message: message.to_string(),
        roast: roast.to_string(),
    }]
}

fn rule_uncleaned_package_cache(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let persistent_stages = persistent_stage_indices(instrs);
    let layer_stages = layer_persistent_stage_indices(instrs);
    let instruction_stages = instruction_stage_indices(instrs);
    let mut findings = Vec::new();
    for (instruction_index, i) in instrs.iter().enumerate() {
        if i.instruction != "RUN" {
            continue;
        }
        let arg = &i.arguments;
        let has_apt = arg.contains("apt-get install") || arg.contains("apt install");
        let has_apk = arg.contains("apk add") && !arg.contains("--no-cache");
        let apt_lists_are_ephemeral = has_ephemeral_mount_covering(i, "/var/lib/apt/lists");
        if has_apt
            && !cleans_apt_cache(arg)
            && !apt_lists_are_ephemeral
            && cache_reaches_final_image(
                instrs,
                &instruction_stages,
                &persistent_stages,
                &layer_stages,
                instruction_index,
                cleans_apt_cache,
            )
        {
            findings.push(finding_at_span(
                "DF004",
                Severity::Warning,
                instruction_substring_span(raw, i, &["apt-get install", "apt install"]),
                "apt cache not cleaned after install — adds unnecessary layer size".to_string(),
                "The package lists created by this install reach the final image. Remove /var/lib/apt/lists in the same RUN layer.",
            ));
        }
        if has_apk
            && !removes_cache_path(arg, "/var/cache/apk")
            && !has_ephemeral_mount_covering(i, "/var/cache/apk")
            && cache_reaches_final_image(
                instrs,
                &instruction_stages,
                &persistent_stages,
                &layer_stages,
                instruction_index,
                |command| removes_cache_path(command, "/var/cache/apk"),
            )
        {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF029".into(),
                severity: Severity::Warning,
                line: i.line,
                message: "apk add without --no-cache flag".to_string(),
                roast: "Using `apk add` without `--no-cache`? You chose Alpine to save space and \
                        then immediately gained it all back. That's impressive, in a bad way."
                    .to_string(),
            });
        }
    }
    findings
}

fn removes_brace_expanded_apt_state(command: &str) -> bool {
    command.split_whitespace().any(|token| {
        token.starts_with("/var/lib/{") && token.contains("apt") && token.contains('}')
    })
}

fn removes_cache_path(command: &str, path: &str) -> bool {
    command.split([';', '&', '|']).any(|segment| {
        let tokens = segment.split_whitespace().collect::<Vec<_>>();
        let Some(rm_index) = tokens
            .iter()
            .position(|token| token.rsplit('/').next() == Some("rm"))
        else {
            return false;
        };
        tokens[rm_index + 1..].iter().any(|token| {
            let token = token
                .trim_matches(['\'', '"'])
                .trim_end_matches(['\\', ',', ')']);
            token == path
                || token
                    .strip_prefix(path)
                    .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with('*'))
        })
    })
}

fn rule_unpinned_packages(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re_yum = Regex::new(r"yum install[^&|;]*").unwrap();
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "RUN") {
        if apt_install_commands(&i.arguments)
            .iter()
            .any(|(tokens, install_index)| apt_has_unpinned_package(tokens, *install_index))
        {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF005".into(),
                severity: Severity::Info,
                line: i.line,
                message: "apt-get install without pinned package versions".to_string(),
                roast: "Unpinned packages: a bold way to ensure your build is different \
                        every single time. 'It worked on my machine' is a lifestyle choice, \
                        not a deployment strategy."
                    .to_string(),
            });
        }
        if re_yum.find(&i.arguments).is_some() {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF005".into(),
                severity: Severity::Info,
                line: i.line,
                message: "yum install without pinned package versions".to_string(),
                roast: "Your yum packages are pinned to 'whatever yum feels like today'. \
                        Reproducibility called — it's going to voicemail."
                    .to_string(),
            });
        }
    }
    findings
}

fn apt_install_commands(arguments: &str) -> Vec<(Vec<&str>, usize)> {
    arguments
        .split(['&', '|', ';'])
        .filter_map(|segment| {
            let segment_tokens: Vec<_> = segment.split_whitespace().collect();
            let apt_index = segment_tokens
                .iter()
                .position(|token| matches!(*token, "apt" | "apt-get"))?;
            let tokens = segment_tokens[apt_index + 1..].to_vec();
            let install_index = tokens.iter().position(|token| *token == "install")?;
            Some((tokens, install_index))
        })
        .collect()
}

fn apt_has_unpinned_package(tokens: &[&str], install_index: usize) -> bool {
    if tokens.contains(&"--only-upgrade") {
        return false;
    }

    let options_with_values = [
        "-a",
        "--host-architecture",
        "-c",
        "--config-file",
        "-o",
        "--option",
        "-q",
        "--quiet",
        "-t",
        "--target-release",
    ];
    let mut skip_option_value = false;
    for token in tokens.iter().skip(install_index + 1) {
        if skip_option_value {
            skip_option_value = false;
            continue;
        }
        if options_with_values.contains(token) {
            skip_option_value = true;
            continue;
        }
        if token.starts_with('-') {
            continue;
        }
        if !token.contains('=') {
            return true;
        }
    }
    false
}

fn apt_assumes_yes(tokens: &[&str]) -> bool {
    for (index, token) in tokens.iter().enumerate() {
        if matches!(*token, "--yes" | "--assume-yes") {
            return true;
        }
        if let Some(short_options) = token.strip_prefix('-').filter(|_| !token.starts_with("--")) {
            if short_options.contains('y')
                || short_options.chars().filter(|c| *c == 'q').count() >= 2
            {
                return true;
            }
            if short_options
                .strip_prefix("q=")
                .and_then(|level| level.parse::<u8>().ok())
                .is_some_and(|level| level >= 2)
            {
                return true;
            }
        }
        if token
            .strip_prefix("--quiet=")
            .and_then(|level| level.parse::<u8>().ok())
            .is_some_and(|level| level >= 2)
        {
            return true;
        }
        if matches!(*token, "-q" | "--quiet")
            && tokens
                .get(index + 1)
                .and_then(|level| level.parse::<u8>().ok())
                .is_some_and(|level| level >= 2)
        {
            return true;
        }
    }
    false
}

fn rule_apt_no_y(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut stage_settings = std::collections::HashMap::new();
    let mut current_alias = None;
    let mut assumes_yes = false;
    let mut findings = Vec::new();

    for instruction in instrs {
        if instruction.instruction == "FROM" {
            let Some(from) = parse_from_arguments(&instruction.arguments) else {
                continue;
            };
            assumes_yes = stage_settings
                .get(&from.image.to_ascii_lowercase())
                .copied()
                .unwrap_or(false);
            current_alias = from.alias.map(str::to_ascii_lowercase);
        } else if instruction.instruction == "RUN" {
            let command_setting = apt_assume_yes_setting(&instruction.arguments);
            let effective_assumes_yes = command_setting.unwrap_or(assumes_yes);
            if !effective_assumes_yes
                && apt_install_commands(&instruction.arguments)
                    .iter()
                    .any(|(tokens, _)| !apt_assumes_yes(tokens))
                && !instruction
                    .arguments
                    .contains("DEBIAN_FRONTEND=noninteractive")
            {
                findings.push(finding_at_span(
                    "DF015",
                    Severity::Error,
                    apt_install_without_yes_span(raw, instruction),
                    "apt-get install without -y flag will hang waiting for user input".to_string(),
                    "apt-get install without -y? Your build is going to sit there, patiently \
                     waiting for a 'yes' that will never come, like a golden retriever waiting \
                     for an owner who's on a cruise ship.",
                ));
            }
            if let Some(setting) = command_setting {
                assumes_yes = setting;
            }
        }
        if let Some(alias) = &current_alias {
            stage_settings.insert(alias.clone(), assumes_yes);
        }
    }

    findings
}

fn apt_install_without_yes_span(source: &str, instruction: &Instruction) -> SourceSpan {
    let command = Regex::new(r"(?i)(?P<apt>\bapt(?:-get)?\b)(?P<body>[^;&|]*\binstall\b[^;&|]*)")
        .expect("valid apt install regex");
    let span = command
        .captures_iter(&instruction.raw)
        .find(|capture| {
            let tokens = capture[0].split_whitespace().collect::<Vec<_>>();
            !apt_assumes_yes(&tokens)
        })
        .and_then(|capture| capture.name("apt"))
        .map(|matched| instruction_match_span(source, instruction, matched.start(), matched.end()))
        .unwrap_or(instruction.span);
    span
}

fn apt_assume_yes_setting(command: &str) -> Option<bool> {
    let setting = Regex::new(r#"(?i)APT::Get::Assume-Yes[\s=\"']+(true|false|1|0)"#)
        .expect("valid apt assume-yes regex");
    setting
        .captures(command)
        .map(|capture| matches!(&capture[1].to_ascii_lowercase()[..], "true" | "1"))
}

fn rule_apt_recommends(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let apt = Regex::new(r"(?i)\b(?:apt-get|apt)\b(?P<body>[^;&|\n]*)")
        .expect("valid apt invocation regex");
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let script = run_script(i);
            subcommand_arguments(
                &script,
                &apt,
                "install",
                &["-c", "--config-file", "-o", "--option"],
            )
            .into_iter()
            .any(|arguments| !arguments.contains("--no-install-recommends"))
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF016".into(),
            severity: Severity::Info,
            line: i.line,
            message: "apt-get install without --no-install-recommends installs extra packages"
                .to_string(),
            roast: "Installing without --no-install-recommends? apt is now installing packages \
                    you didn't ask for, like a waiter who brings you a full bread basket when \
                    you said you're gluten-free. `--no-install-recommends` is right there."
                .to_string(),
        })
        .collect()
}

fn rule_yum_no_y(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("yum install") || a.contains("dnf install"))
                && !a.contains("-y")
                && !a.contains("--assumeyes")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF027".into(),
            severity: Severity::Error,
            line: i.line,
            message: "yum/dnf install without -y flag will hang waiting for user input".to_string(),
            roast: "yum install without -y. Your build will hang indefinitely, \
                    waiting for input in a non-interactive environment. \
                    It's not coming. Add -y and move on."
                .to_string(),
        })
        .collect()
}

fn rule_apt_get_update_alone(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut prev_was_update = false;
    let mut update_line = 0;
    for i in instrs {
        if i.instruction == "RUN" {
            let a = &i.arguments;
            let has_update = a.contains("apt-get update") || a.contains("apt update");
            let has_install = a.contains("apt-get install") || a.contains("apt install");
            if has_update && !has_install {
                prev_was_update = true;
                update_line = i.line;
            } else if has_install && !has_update && prev_was_update {
                findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
                    rule: "DF028".into(),
                    severity: Severity::Warning,
                    line: update_line,
                    message: "apt-get update in a separate RUN from apt-get install causes cache poisoning".to_string(),
                    roast: "Splitting `apt-get update` and `apt-get install` into separate RUN \
                            layers is a classic mistake. Docker caches the update layer and \
                            your install may use a stale index. Combine them with && or enjoy \
                            mysterious 404 errors.".to_string(),
                });
                prev_was_update = false;
            } else {
                prev_was_update = false;
            }
        }
    }
    findings
}

fn rule_apk_no_cache(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    // handled inside rule_uncleaned_package_cache to avoid duplicate findings
    vec![]
}

fn rule_hardcoded_run_secrets(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let patterns = [
        Regex::new(r#"(?i)\bwith\s+password\s+'(?P<value>[^']+)'"#)
            .expect("valid SQL password regex"),
        Regex::new(r#"(?i)\bwith\s+password\s+\"(?P<value>[^\"]+)\""#)
            .expect("valid SQL password regex"),
        Regex::new(r#"(?i)(?:^|\s)--(?:so-)?pin(?:=|\s+)(?P<value>\"[^\"]*\"|'[^']*'|[^\s;&|]+)"#)
            .expect("valid command-line PIN regex"),
    ];

    instrs_of(instrs, "RUN")
        .into_iter()
        .flat_map(|instruction| {
            patterns
                .iter()
                .flat_map(|pattern| pattern.captures_iter(&instruction.raw))
                .filter_map(|capture| {
                    let value = capture.name("value")?;
                    hardcoded_secret_value(value.as_str()).then(|| {
                        finding_at_span(
                            "DF013",
                            Severity::Error,
                            instruction_match_span(raw, instruction, value.start(), value.end()),
                            "Hardcoded credential detected in RUN command".to_string(),
                            "This RUN command embeds a credential directly in an image layer. Use a build secret or runtime injection instead.",
                        )
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn rule_hardcoded_secrets(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for i in instrs
        .iter()
        .filter(|i| i.instruction == "ARG" || i.instruction == "ENV")
    {
        for (name, value, span) in instruction_assignments(i) {
            let value = value.trim();
            if sensitive_variable_pattern(name).is_some()
                && hardcoded_secret_value(value)
                && !known_public_credential(name, value)
            {
                findings.push(finding_at_span(
                    "DF014",
                    Severity::Error,
                    span,
                    format!("Hardcoded secret value detected in {}", name),
                    "A hardcoded secret is preserved in source and image metadata. Use build secrets or runtime injection instead.",
                ));
            }
        }
    }
    findings
}

fn hardcoded_secret_value(value: &str) -> bool {
    let value = value.trim().trim_matches(['\'', '"']);
    !value.is_empty() && !value.contains('$')
}

fn instruction_assignments(instruction: &Instruction) -> Vec<(&str, &str, SourceSpan)> {
    if instruction
        .words
        .first()
        .is_some_and(|word| word.value.contains('='))
    {
        return instruction
            .words
            .iter()
            .filter_map(|word| {
                word.value
                    .split_once('=')
                    .map(|(name, value)| (name, value, word.span))
            })
            .collect();
    }
    match instruction.words.as_slice() {
        [name, value, ..] => vec![(name.value.as_str(), value.value.as_str(), value.span)],
        _ => Vec::new(),
    }
}

fn sensitive_variable_pattern(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with("_file") || lower.ends_with("_name") || lower.ends_with("_label") {
        return None;
    }
    let words = lower
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let has = |word: &str| words.contains(&word);
    if has("password") || has("passwd") || has("secret") || has("token") || has("apikey") {
        return Some("credential");
    }
    [
        (["api", "key"], "api_key"),
        (["private", "key"], "private_key"),
        (["access", "key"], "access_key"),
        (["encryption", "key"], "encryption_key"),
        (["db", "pass"], "db_pass"),
        (["database", "password"], "database_password"),
        (["hsm", "pin"], "hsm_pin"),
        (["so", "pin"], "so_pin"),
    ]
    .into_iter()
    .find_map(|(required, label)| required.into_iter().all(has).then_some(label))
}

fn known_public_credential(name: &str, value: &str) -> bool {
    name.eq_ignore_ascii_case("POSTHOG_TOKEN")
        && value.trim().trim_matches(['\'', '"']).starts_with("phc_")
}

fn rule_curl_pipe_sh(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut stages = Vec::<std::collections::HashMap<String, SourceSpan>>::new();
    let mut aliases = std::collections::HashMap::<String, usize>::new();
    let mut current_stage = None;

    for instruction in instrs {
        match instruction.instruction.as_str() {
            "FROM" => {
                let inherited = parse_from_arguments(&instruction.arguments)
                    .and_then(|from| aliases.get(&from.image.to_ascii_lowercase()).copied())
                    .and_then(|index| stages.get(index).cloned())
                    .unwrap_or_default();
                let index = stages.len();
                stages.push(inherited);
                current_stage = Some(index);
                if let Some(alias) =
                    parse_from_arguments(&instruction.arguments).and_then(|from| from.alias)
                {
                    aliases.insert(alias.to_ascii_lowercase(), index);
                }
            }
            "COPY" => {
                let Some(stage) = current_stage else { continue };
                let source_stage = instruction
                    .flags
                    .iter()
                    .find(|flag| flag.name.eq_ignore_ascii_case("from"))
                    .and_then(|flag| flag.value.as_deref())
                    .and_then(|source| {
                        aliases
                            .get(&source.to_ascii_lowercase())
                            .copied()
                            .or_else(|| source.parse::<usize>().ok())
                    });
                let Some(source_stage) = source_stage else {
                    continue;
                };
                let operands = instruction_operands(instruction);
                let Some(destination) = operands.last() else {
                    continue;
                };
                let copied = operands[..operands.len().saturating_sub(1)]
                    .iter()
                    .filter_map(|source| {
                        let basename = script_basename(source);
                        stages
                            .get(source_stage)?
                            .get(*source)
                            .or_else(|| stages.get(source_stage)?.get(basename))
                            .copied()
                            .map(|span| (basename.to_string(), span))
                    })
                    .collect::<Vec<_>>();
                for (basename, span) in copied {
                    let target = if matches!(*destination, "." | "./") || destination.ends_with('/')
                    {
                        basename
                    } else {
                        destination.to_string()
                    };
                    stages[stage].insert(target.clone(), span);
                    stages[stage].insert(script_basename(&target).to_string(), span);
                }
            }
            "RUN" => {
                for matched in remote_script_matches(&instruction.raw) {
                    findings.push(df021_finding(instruction_match_span(
                        raw,
                        instruction,
                        matched.start,
                        matched.end,
                    )));
                }

                let Some(stage) = current_stage else { continue };
                for (path, range) in downloaded_script_matches(&instruction.raw) {
                    let span = instruction_match_span(raw, instruction, range.start, range.end);
                    stages[stage].insert(path.clone(), span);
                    stages[stage].insert(script_basename(&path).to_string(), span);
                }

                let downloads = stages[stage]
                    .iter()
                    .map(|(path, span)| (path.clone(), *span))
                    .collect::<Vec<_>>();
                let mut consumed = Vec::new();
                for (path, span) in downloads {
                    let Some(execution) = script_execution_offset(&instruction.raw, &path) else {
                        continue;
                    };
                    if script_is_verified_before(&instruction.raw, &path, execution) {
                        consumed.push(path);
                        continue;
                    }
                    findings.push(df021_finding(span));
                    consumed.push(path);
                }
                for path in consumed {
                    stages[stage].remove(&path);
                }
            }
            _ => {}
        }
    }
    findings.sort_by_key(|finding| (finding.line, finding.column));
    findings.dedup_by(|left, right| {
        left.line == right.line && left.column == right.column && left.rule == right.rule
    });
    findings
}

fn df021_finding(span: SourceSpan) -> Finding {
    finding_at_span(
        "DF021",
        Severity::Error,
        span,
        "Executing a remotely downloaded script without verifying it".to_string(),
        "Executing a remote script directly: the technical equivalent of 'hold my beer'. You're downloading code from the internet and executing it blind, inside your container, and shipping it to prod. Your threat model is vibes.",
    )
}

fn executes_remote_script(command: &str) -> bool {
    !remote_script_matches(command).is_empty()
        || downloaded_script_matches(command).iter().any(|(path, _)| {
            script_execution_offset(command, path)
                .is_some_and(|execution| !script_is_verified_before(command, path, execution))
        })
}

fn remote_script_matches(command: &str) -> Vec<std::ops::Range<usize>> {
    let pipe = Regex::new(
        r"(?i)(?:\b(?:curl|wget)\b|(?:^|[\s;&|])(?:[./A-Za-z0-9_-]+/)?scurl\b)[^|;]*\|\s*(?:\\\r?\n\s*)*(?:sudo(?:\s+-\S+)*\s+)?(?:(?:/usr/bin/)?env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:(?:/[^\s]*/)?(?:ba|a|z|fi)?sh\b|(?:/[^\s]*/)?python(?:[0-9]+(?:\.[0-9]+)?)?\b|(?:/[^\s]*/)?php(?:[0-9]+(?:\.[0-9]+)?)?\b|\$\{?(?:PYTHON|PYTHON_BIN|PYTHON_EXECUTABLE)\}?)",
    )
    .expect("valid remote script pipeline regex");
    let downloader = Regex::new(r"(?i)\b(?:curl|wget|scurl)\b").expect("valid downloader regex");
    let mut matches = pipe
        .find_iter(command)
        .map(|matched| {
            let pipeline = matched.as_str();
            let pipe_offset = pipeline.find('|').unwrap_or(pipeline.len());
            let downloader_offset = downloader
                .find_iter(&pipeline[..pipe_offset])
                .last()
                .map_or(0, |download| download.start());
            matched.start() + downloader_offset..matched.end()
        })
        .collect::<Vec<_>>();

    let command_substitution =
        Regex::new(r"(?i)\$\(\s*(?:(?:[./A-Za-z0-9_-]+/)?scurl|curl|wget)\b")
            .expect("valid download substitution regex");
    let shell_c = Regex::new(r"(?i)(?:^|\s)(?:/[^\s]*/)?(?:ba|a|z|fi)?sh\s+(?:[^;]*\s)?-c\b")
        .expect("valid shell command regex");
    if shell_c.is_match(command) {
        matches.extend(
            command_substitution
                .find_iter(command)
                .map(|matched| matched.start()..matched.end()),
        );
    }
    matches.sort_by_key(|matched| matched.start);
    matches.dedup();
    matches
}

fn downloaded_script_matches(command: &str) -> Vec<(String, std::ops::Range<usize>)> {
    let invocation = Regex::new(
        r"(?i)(?:^|\s)(?P<tool>(?:[./A-Za-z0-9_-]+/)?(?:scurl|curl|wget))\b(?P<body>.*)",
    )
    .expect("valid downloader invocation regex");
    let output = Regex::new(
        r#"(?i)(?:^|\s)(?:-o|--output(?:=|\s+)|-O|--output-document(?:=|\s+))\s*["']?(?P<path>[^\s"']+)"#,
    )
    .expect("valid downloader output regex");
    let redirect =
        Regex::new(r#">\s*["']?(?P<path>[^\s"']+)"#).expect("valid downloader redirect regex");
    let url = Regex::new(r#"https?://[^\s"']+"#).expect("valid URL regex");
    shell_command_segments(command)
        .into_iter()
        .filter_map(|segment| {
            let capture = invocation.captures(&command[segment.clone()])?;
            let whole = capture.get(0)?;
            let body = capture.name("body")?.as_str();
            let mut path = output
                .captures(body)
                .and_then(|capture| capture.name("path"))
                .map(|path| path.as_str().to_string())
                .or_else(|| {
                    redirect
                        .captures(body)
                        .and_then(|capture| capture.name("path"))
                        .map(|path| path.as_str().to_string())
                });
            if path.as_deref() == Some("-") {
                path = None;
            }
            if path.is_none() {
                path = url.find(body).and_then(|url| {
                    let path = url.as_str().split(['?', '#']).next().unwrap_or_default();
                    path.rsplit('/').next().map(str::to_string)
                });
            }
            let path = path?
                .trim_end_matches(['\\', ';'])
                .trim_matches(['\'', '"'])
                .to_string();
            Some((
                path,
                segment.start + whole.start()
                    ..segment.start + whole.start() + capture["tool"].len(),
            ))
        })
        .collect()
}

fn shell_command_segments(command: &str) -> Vec<std::ops::Range<usize>> {
    let bytes = command.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' && quote != Some(b'\'') {
            escaped = true;
        } else if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
        } else if quote.is_none() && matches!(byte, b';' | b'&' | b'|') {
            if start < index {
                segments.push(start..index);
            }
            while index + 1 < bytes.len() && matches!(bytes[index + 1], b';' | b'&' | b'|') {
                index += 1;
            }
            start = index + 1;
        }
        index += 1;
    }
    if start < bytes.len() {
        segments.push(start..bytes.len());
    }
    segments
}

fn script_basename(path: &str) -> &str {
    path.trim_matches(['\'', '"'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
}

fn script_execution_offset(command: &str, path: &str) -> Option<usize> {
    let basename = regex::escape(script_basename(path));
    let interpreter = Regex::new(&format!(
        r#"(?im)(?:^\s*RUN\s+|[;&|]\s*|\n\s*)(?:sudo(?:\s+-\S+)*\s+)?(?:(?:/usr/bin/)?env(?:\s+(?:-\S+|[A-Za-z_][A-Za-z0-9_]*=\S+))*\s+)?(?:(?:/[^\s]*/)?(?:ba|a|z|fi)?sh|(?:/[^\s]*/)?python(?:[0-9]+(?:\.[0-9]+)?)?|(?:/[^\s]*/)?php(?:[0-9]+(?:\.[0-9]+)?)?|(?:/[^\s]*/)?(?:perl|ruby)|\$\{{?(?:PYTHON|PYTHON_BIN|PYTHON_EXECUTABLE)\}}?)(?:\s+-\S+)*\s+["']?(?:[^\s"']*/)?{basename}["']?"#
    ))
    .expect("escaped script name creates a valid interpreter execution regex");
    if let Some(matched) = interpreter.find(command) {
        return Some(matched.start());
    }
    let regex = Regex::new(&format!(
        r#"(?im)(?:^\s*RUN\s+|[;&|]\s*|\n\s*)["']?(?:\./|[^\s"']*/){basename}["']?(?:\s|$)"#
    ))
    .expect("escaped script name creates a valid direct execution regex");
    let execution = regex
        .find_iter(command)
        .find(|matched| !matched.as_str().contains("://"))
        .map(|matched| matched.start());
    execution
}

fn script_is_verified_before(command: &str, path: &str, execution: usize) -> bool {
    let before = &command[..execution];
    let basename = script_basename(path);
    before.contains(basename)
        && (before.contains("sha256sum -c")
            || before.contains("sha256sum --check")
            || before.contains("shasum -a 256"))
}

fn rule_apt_instead_of_apt_get(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let re = Regex::new(
        r"(?im)(?:^\s*RUN(?:\s+--[^\s]+)*\s+|[;&|]\s*|^\s*|\bsudo\s+)apt\s+(?:install|remove|update|upgrade|list|search|show|purge)\b",
    )
    .expect("valid apt command regex");
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&mask_shell_comments(&i.raw)))
        .map(|i| {
            finding_at_span(
                "DF059",
                Severity::Warning,
                shell_command_span(raw, i, "apt"),
                "apt used instead of apt-get — apt is an end-user tool, not suited for scripts"
                    .to_string(),
                "`apt` is designed for humans: it has progress bars, color output, and a \
                    warning that says 'do not use in scripts'. You are in a script. \
                    Use apt-get or apt-cache instead.",
            )
        })
        .collect()
}

fn rule_useless_commands(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let useless = [
        "ssh",
        "vim",
        "nano",
        "emacs",
        "shutdown",
        "reboot",
        "service",
        "systemctl",
        "ifconfig",
        "iwconfig",
        "free",
        "top",
        "htop",
        "mount",
        "umount",
    ];
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "RUN") {
        let script = run_script(i);
        for cmd in &useless {
            if shell_invokes_command(&script, cmd)
                && !meaningful_system_service_command(&script, cmd)
            {
                findings.push(finding_at_span(
                    "DF060",
                    Severity::Info,
                    shell_command_span(raw, i, cmd),
                    format!("Command '{}' makes little sense inside a container", cmd),
                    &format!(
                        "`{}` in a Dockerfile: you're running a command that assumes a full \
                         interactive OS environment inside a container. It doesn't apply here. \
                         Containers are not VMs.",
                        cmd
                    ),
                ));
                break;
            }
        }
    }
    findings
}

fn meaningful_system_service_command(script: &str, command: &str) -> bool {
    if command == "systemctl" {
        let offline_configuration =
            Regex::new(r"\bsystemctl\s+(?:--[^\s]+\s+)*(?:enable|disable|mask|unmask|preset)\b")
                .expect("valid systemctl configuration regex");
        return offline_configuration.is_match(script);
    }
    if command == "service" {
        let starts_database =
            Regex::new(r"\bservice\s+(?:postgres|postgresql|mysql|mariadb)\s+start\b")
                .expect("valid service initialization regex");
        let initializes_database = Regex::new(r"\b(?:psql|mysql|mariadb|createdb)\b")
            .expect("valid database initialization regex");
        return starts_database.is_match(script) && initializes_database.is_match(script);
    }
    false
}

fn rule_from_platform_flag(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let froms = instrs_of(instrs, "FROM");
    let final_stage = froms.len().saturating_sub(1);

    froms
        .into_iter()
        .enumerate()
        .filter(|(index, instruction)| {
            let has_platform_flag = instruction
                .flags
                .iter()
                .any(|flag| flag.name.eq_ignore_ascii_case("platform"));
            let is_native_builder = *index < final_stage
                && instruction.flags.iter().any(|flag| {
                    flag.name.eq_ignore_ascii_case("platform")
                        && matches!(flag.value.as_deref(), Some("$BUILDPLATFORM" | "${BUILDPLATFORM}"))
                });
            has_platform_flag && !is_native_builder
        })
        .map(|(_, i)| i)
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF061".into(),
            severity: Severity::Info,
            line: i.line,
            message: "FROM uses --platform flag — consider whether cross-platform targeting is intentional".to_string(),
            roast: "--platform in FROM forces a specific architecture. If you're building for \
                    amd64 but deploying on arm64, your image will be slow or broken. \
                    Make sure this is intentional and documented.".to_string(),
        })
        .collect()
}

fn rule_env_self_reference(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    // Docker resolves ENV references against the image configuration inherited
    // from the base image and prior instructions, so this cannot be diagnosed
    // reliably from a Dockerfile alone.
    vec![]
}

fn rule_copy_relative_no_workdir(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut stages = std::collections::HashMap::new();
    let mut current_alias: Option<String> = None;
    let mut state = StageRuntimeState::default();
    let mut reported_unknown_workdir_dependency = false;
    let mut findings = Vec::new();
    for i in instrs {
        if i.instruction == "FROM" {
            reported_unknown_workdir_dependency = false;
            if let Some(from) = parse_from_arguments(&i.arguments) {
                state = inherited_runtime_state(from, &stages);
                current_alias = from.alias.map(str::to_lowercase);
            } else {
                state = StageRuntimeState::default();
                current_alias = None;
            }
        } else if i.instruction == "WORKDIR" {
            state.has_workdir = true;
        } else if i.instruction == "COPY" {
            let args = instruction_operands(i);
            if let Some(dest) = args.last() {
                if !is_absolute_container_path(dest) && !state.has_workdir {
                    if !state.base_metadata_known && reported_unknown_workdir_dependency {
                        continue;
                    }
                    let (message, roast) = if state.base_metadata_known {
                        (
                            format!(
                                "COPY to relative destination '{}' but no WORKDIR has been set",
                                dest
                            ),
                            format!(
                                "COPY to '{}' with no WORKDIR set. Set WORKDIR explicitly before using relative paths.",
                                dest
                            ),
                        )
                    } else {
                        (
                            format!(
                                "COPY to relative destination '{}' relies on the base image WORKDIR",
                                dest
                            ),
                            format!(
                                "COPY to '{}' inherits an external base image's working directory. Set WORKDIR explicitly if that dependency is unintended.",
                                dest
                            ),
                        )
                    };
                    findings.push(Finding {
                        column: 0,
                        end_line: 0,
                        end_column: 0,
                        rule: "DF063".into(),
                        severity: if state.base_metadata_known {
                            Severity::Warning
                        } else {
                            Severity::Info
                        },
                        line: i.line,
                        message,
                        roast,
                    });
                    reported_unknown_workdir_dependency = !state.base_metadata_known;
                }
            }
        }
        if let Some(alias) = &current_alias {
            stages.insert(alias.clone(), state.clone());
        }
    }
    findings
}

fn rule_useradd_no_l(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| useradd_with_high_uid_without_no_log_init(&i.arguments))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF064".into(),
            severity: Severity::Warning,
            line: i.line,
            message:
                "useradd without -l flag — high UIDs create oversized /var/log/lastlog entries"
                    .to_string(),
            roast: "useradd without -l (--no-log-init): with a high UID, this creates a sparse \
                    file in /var/log/lastlog that can balloon your image size by gigabytes. \
                    Add -l or use --no-log-init."
                .to_string(),
        })
        .collect()
}

fn useradd_with_high_uid_without_no_log_init(command: &str) -> bool {
    const HIGH_UID_THRESHOLD: u64 = 100_000;
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.rsplit('/').next() == Some("useradd"))
        .any(|(useradd_index, _)| {
            let arguments = tokens[useradd_index + 1..]
                .iter()
                .take_while(|token| !matches!(**token, "&&" | "||" | ";" | "|"))
                .copied()
                .collect::<Vec<_>>();
            if arguments
                .iter()
                .any(|argument| matches!(*argument, "-l" | "--no-log-init"))
            {
                return false;
            }

            arguments.iter().enumerate().any(|(index, argument)| {
                let value = if matches!(*argument, "-u" | "--uid") {
                    arguments.get(index + 1).copied()
                } else {
                    argument.strip_prefix("--uid=").or_else(|| {
                        argument
                            .strip_prefix("-u")
                            .filter(|value| !value.is_empty())
                    })
                };
                value
                    .and_then(|uid| uid.parse::<u64>().ok())
                    .is_some_and(|uid| uid >= HIGH_UID_THRESHOLD)
            })
        })
}

fn rule_copy_archive_use_add(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    // Whether ADD is safe depends on verification, destination layout,
    // --strip-components, and whether the archive should remain compressed.
    // Recommending it from the filename alone changes build semantics.
    Vec::new()
}

fn rule_onbuild_forbidden(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    const FORBIDDEN: &[&str] = &["FROM", "ONBUILD", "MAINTAINER"];
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "ONBUILD") {
        let triggered = i
            .arguments
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_uppercase();
        if FORBIDDEN.contains(&triggered.as_str()) {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF068".into(),
                severity: Severity::Error,
                line: i.line,
                message: format!(
                    "ONBUILD {} is forbidden — {} cannot be used as an ONBUILD trigger",
                    triggered, triggered
                ),
                roast: format!(
                    "ONBUILD {} is explicitly prohibited by Docker. \
                     FROM would create a recursive inheritance loop, \
                     ONBUILD ONBUILD is a depth-2 trap nobody asked for, \
                     and MAINTAINER is deprecated everywhere, including here. \
                     This fails at build time.",
                    triggered
                ),
            });
        }
    }
    findings
}

fn rule_bash_syntax_no_shell(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    // Patterns that are valid bash but not POSIX sh — meaningless or broken on /bin/sh
    const BASH_COMMANDS: &[(&str, &str)] = &[
        ("[[", "double-bracket conditional"),
        ("source", "source builtin (use '.' in POSIX sh)"),
        ("declare", "declare builtin"),
        ("mapfile", "mapfile builtin"),
        ("readarray", "readarray builtin"),
    ];
    let mut stages = std::collections::HashMap::new();
    let mut shell_capability_stages = std::collections::HashMap::new();
    let mut current_alias = None;
    let mut state = StageRuntimeState::default();
    let mut shell_capabilities = ShellSyntaxCapabilities::default();
    let mut findings = Vec::new();
    for i in instrs {
        if i.instruction == "FROM" {
            if let Some(from) = parse_from_arguments(&i.arguments) {
                state = inherited_runtime_state(from, &stages);
                shell_capabilities = shell_capability_stages
                    .get(&from.image.to_ascii_lowercase())
                    .copied()
                    .unwrap_or_else(|| ShellSyntaxCapabilities::for_base_image(from.image));
                current_alias = from.alias.map(str::to_ascii_lowercase);
            }
        } else if i.instruction == "SHELL" {
            state.has_explicit_shell = true;
            shell_capabilities = ShellSyntaxCapabilities::for_shell_instruction(i);
        } else if i.instruction == "RUN"
            && !state.has_explicit_shell
            && !heredoc_has_bash_interpreter(i)
        {
            // `RUN` itself uses /bin/sh, but an explicit `bash -c` owns the quoted
            // command that follows it. Ignore bash-only syntax inside that command
            // while continuing to inspect the rest of the RUN instruction.
            let command = command_without_bash_c_scripts(&run_script(i));
            let mut reported = false;
            for (command_name, label) in BASH_COMMANDS {
                if shell_capabilities.supports(command_name) {
                    continue;
                }
                if shell_invokes_command(&command, command_name) {
                    let (message, roast) = if state.base_metadata_known {
                        (
                            format!(
                                "RUN uses bash-specific syntax ({}) but no SHELL instruction is set",
                                label
                            ),
                            format!(
                                "'{}' is bash syntax, but this stage has no Bash SHELL. Set `SHELL [\"/bin/bash\", \"-c\"]` before this RUN.",
                                command_name
                            ),
                        )
                    } else {
                        (
                            format!(
                                "RUN uses bash-specific syntax ({}) without an explicit SHELL in this stage",
                                label
                            ),
                            format!(
                                "'{}' requires Bash, but shell behavior currently depends on external base-image metadata. Declare the Bash SHELL explicitly.",
                                command_name
                            ),
                        )
                    };
                    findings.push(finding_at_span(
                        "DF066",
                        Severity::Warning,
                        shell_command_span(raw, i, command_name),
                        message,
                        &roast,
                    ));
                    reported = true;
                    break;
                }
            }
            if !reported && command.contains("${!") {
                let message = if state.base_metadata_known {
                    "RUN uses bash-specific syntax (indirect variable expansion) but no SHELL instruction is set"
                } else {
                    "RUN uses bash-specific syntax (indirect variable expansion) without an explicit SHELL in this stage"
                };
                findings.push(finding_at_span(
                    "DF066",
                    Severity::Warning,
                    instruction_substring_span(raw, i, &["${!"]),
                    message.to_string(),
                    "'${!' is bash syntax. Set an explicit Bash SHELL before using it.",
                ));
            } else if !reported
                && !shell_capabilities.supports("&>")
                && contains_unquoted_operator(&command, "&>")
            {
                let message = if state.base_metadata_known {
                    "RUN uses bash-specific syntax (combined stdout/stderr redirection) but no SHELL instruction is set"
                } else {
                    "RUN uses bash-specific syntax (combined stdout/stderr redirection) without an explicit SHELL in this stage"
                };
                findings.push(finding_at_span(
                    "DF066",
                    Severity::Warning,
                    instruction_substring_span(raw, i, &["&>"]),
                    message.to_string(),
                    "'&>' is not portable POSIX redirection. Declare a shell that supports it, or use `>file 2>&1`.",
                ));
            }
        }
        if let Some(alias) = &current_alias {
            stages.insert(alias.clone(), state.clone());
            shell_capability_stages.insert(alias.clone(), shell_capabilities);
        }
    }
    findings
}

#[derive(Clone, Copy, Debug, Default)]
struct ShellSyntaxCapabilities {
    source: bool,
    double_bracket: bool,
    combined_redirect: bool,
}

impl ShellSyntaxCapabilities {
    fn for_base_image(image: &str) -> Self {
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
        if matches!(
            image_name.to_ascii_lowercase().as_str(),
            "alpine" | "busybox"
        ) {
            Self {
                source: true,
                double_bracket: true,
                combined_redirect: true,
            }
        } else {
            Self::default()
        }
    }

    fn for_shell_instruction(instruction: &Instruction) -> Self {
        let InstructionForm::Json(arguments) = &instruction.form else {
            return Self::default();
        };
        let executable = arguments
            .first()
            .and_then(|argument| argument.rsplit(['/', '\\']).next())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(executable.as_str(), "bash" | "ash") {
            Self {
                source: true,
                double_bracket: true,
                combined_redirect: true,
            }
        } else {
            Self::default()
        }
    }

    fn supports(self, command: &str) -> bool {
        match command {
            "source" => self.source,
            "[[" => self.double_bracket,
            "&>" => self.combined_redirect,
            _ => false,
        }
    }
}

fn contains_unquoted_operator(script: &str, operator: &str) -> bool {
    let bytes = script.as_bytes();
    let operator = operator.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index + operator.len() <= bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' && quote != Some(b'\'') {
            escaped = true;
        } else if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
        } else if quote.is_none() && bytes[index..].starts_with(operator) {
            return true;
        }
        index += 1;
    }
    false
}

fn heredoc_has_bash_interpreter(instruction: &Instruction) -> bool {
    instruction.heredocs.iter().any(|heredoc| {
        heredoc.content.lines().next().is_some_and(|line| {
            let shebang = line.trim();
            shebang == "#!/bin/bash"
                || shebang == "#!/usr/bin/bash"
                || shebang.starts_with("#!/usr/bin/env bash")
        })
    })
}

/// Detect a command word at the start of a shell command or immediately after
/// a shell control operator/keyword. This deliberately does not match package
/// names, path components, option values, or group names containing the word.
fn shell_invokes_command(script: &str, command: &str) -> bool {
    let script = mask_shell_array_bodies(script);
    let command = regex::escape(command);
    let pattern =
        format!(r"(?:^|[;&|(\n]\s*|\b(?:then|do|if|elif|while|until)\s+|!\s*){command}(?:\s|$)");
    Regex::new(&pattern)
        .expect("escaped command creates a valid regex")
        .is_match(&script)
}

fn mask_shell_array_bodies(script: &str) -> String {
    let array = Regex::new(r"(?ms)\b[A-Za-z_][A-Za-z0-9_]*=\(\s*.*?^\s*\)")
        .expect("valid shell array regex");
    let mut masked = script.as_bytes().to_vec();
    for matched in array.find_iter(script) {
        for byte in &mut masked[matched.start()..matched.end()] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(masked).expect("masking preserves UTF-8")
}

fn command_without_bash_c_scripts(command: &str) -> String {
    let mut masked = command.as_bytes().to_vec();
    let mut cursor = 0;

    while let Some((_, bash_end, bash)) = next_shell_token(command, cursor) {
        cursor = bash_end;
        if script_basename(bash) != "bash" {
            continue;
        }

        let mut option_cursor = bash_end;
        let mut command_option = false;
        while let Some((_, option_end, option)) = next_shell_token(command, option_cursor) {
            option_cursor = option_end;
            if option == "--command"
                || (option.starts_with('-')
                    && !option.starts_with("--")
                    && option[1..].contains('c'))
            {
                command_option = true;
                break;
            }
            if !option.starts_with('-') {
                break;
            }
        }

        if !command_option {
            continue;
        }
        if let Some((script_start, script_end, _)) = next_shell_token(command, option_cursor) {
            masked[script_start..script_end].fill(b' ');
            cursor = script_end;
        }
    }

    String::from_utf8(masked).expect("masking preserves UTF-8")
}

fn next_shell_token(command: &str, offset: usize) -> Option<(usize, usize, &str)> {
    let bytes = command.as_bytes();
    let mut start = offset;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    if start == bytes.len() {
        return None;
    }

    let mut end = start;
    let mut quote = None;
    while end < bytes.len() {
        match (quote, bytes[end]) {
            (None, b'\'' | b'\"') => quote = Some(bytes[end]),
            (Some(current), byte) if byte == current => quote = None,
            (_, b'\\') if quote == Some(b'\"') && end + 1 < bytes.len() => end += 1,
            (None, byte) if byte.is_ascii_whitespace() => break,
            _ => {}
        }
        end += 1;
    }
    Some((start, end, &command[start..end]))
}

fn rule_untrusted_registry(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    // DF065 is emitted by policy::configured_findings only when the user
    // supplies approved-registries. There is no universal trusted-registry set.
    Vec::new()
}

#[derive(Clone, Copy)]
enum ShellPipelineBehavior {
    Unknown,
    Posix { pipefail: bool },
    NonPosix,
}

fn rule_pipefail_missing(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut stages = std::collections::HashMap::new();
    let mut current_alias = None;
    let mut shell = ShellPipelineBehavior::Unknown;
    let mut findings = Vec::new();

    for instruction in instrs {
        match instruction.instruction.as_str() {
            "FROM" => {
                if let Some(from) = parse_from_arguments(&instruction.arguments) {
                    shell = stages
                        .get(&from.image.to_ascii_lowercase())
                        .copied()
                        .unwrap_or_else(|| {
                            if from.image.eq_ignore_ascii_case("scratch") {
                                ShellPipelineBehavior::Posix { pipefail: false }
                            } else {
                                ShellPipelineBehavior::Unknown
                            }
                        });
                    current_alias = from.alias.map(str::to_ascii_lowercase);
                } else {
                    shell = ShellPipelineBehavior::Unknown;
                    current_alias = None;
                }
            }
            "SHELL" => {
                shell = match &instruction.form {
                    InstructionForm::Json(arguments)
                        if arguments.first().is_some_and(|executable| {
                            let executable = executable.to_ascii_lowercase();
                            executable.ends_with("powershell")
                                || executable.ends_with("powershell.exe")
                                || executable.ends_with("pwsh")
                                || executable.ends_with("pwsh.exe")
                                || executable.ends_with("cmd")
                                || executable.ends_with("cmd.exe")
                        }) =>
                    {
                        ShellPipelineBehavior::NonPosix
                    }
                    InstructionForm::Json(arguments) => ShellPipelineBehavior::Posix {
                        pipefail: arguments
                            .windows(2)
                            .any(|pair| pair[0] == "-o" && pair[1] == "pipefail")
                            || arguments.iter().any(|argument| argument == "-opipefail"),
                    },
                    _ => ShellPipelineBehavior::Unknown,
                };
            }
            "RUN" if !executes_remote_script(&instruction.command) => {
                if matches!(shell, ShellPipelineBehavior::Unknown)
                    && (looks_like_powershell(&instruction.command)
                        || invokes_non_posix_shell(&instruction.command))
                {
                    continue;
                }
                let (initial_pipefail, metadata_known) = match shell {
                    ShellPipelineBehavior::Unknown => (false, false),
                    ShellPipelineBehavior::Posix { pipefail } => (pipefail, true),
                    ShellPipelineBehavior::NonPosix => continue,
                };
                let Some(pipe_offset) =
                    unprotected_pipeline_offset(&instruction.command, initial_pipefail)
                else {
                    continue;
                };
                let message = if metadata_known {
                    "RUN with pipe but no pipefail — failed commands in the pipe are silently ignored"
                } else {
                    "RUN with pipe relies on external base-image SHELL behavior — declare pipefail explicitly"
                };
                findings.push(finding_at_span(
                    "DF057",
                    Severity::Warning,
                    instruction_character_span(raw, instruction, &instruction.command, pipe_offset, '|'),
                    message.to_string(),
                    "This pipeline can hide a failure from an earlier command. Enable pipefail before the pipeline.",
                ));
            }
            _ => {}
        }
        if let Some(alias) = &current_alias {
            stages.insert(alias.clone(), shell);
        }
    }

    findings
}

/// Return whether a shell-form RUN has a pipeline while pipefail is disabled.
///
/// This is intentionally a small shell lexer rather than a substring match: it
/// distinguishes `|` from `||` and quoted or escaped literal pipes, and follows
/// `set` commands in their execution order. It is not a full shell parser, but
/// covers the syntax relevant to enabling and disabling pipefail.
fn unprotected_pipeline_offset(script: &str, initial_pipefail_enabled: bool) -> Option<usize> {
    let mut pipefail_enabled = initial_pipefail_enabled;
    let mut words = Vec::new();
    let mut current_word = String::new();
    let mut quote = None;
    let mut chars = script.char_indices().peekable();

    while let Some((index, character)) = chars.next() {
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else if active_quote == '"'
                && character == '|'
                && unclosed_command_substitution(&script[..index])
                && command_substitution_pipe_is_operator(script, index)
            {
                if chars.peek().is_some_and(|(_, next)| *next == '|') {
                    chars.next();
                    current_word.push_str("||");
                    continue;
                }
                let producer = command_substitution_producer(&script[..index]);
                let low_value = matches!(
                    producer,
                    Some("yes" | "echo" | "uname" | "dpkg" | "readlink")
                ) || matches!(
                    next_pipeline_executable(&script[index + 1..]),
                    Some(":" | "sha256sum" | "shasum")
                ) || pipeline_matches_low_value_pattern(script, index);
                if !pipefail_enabled && !low_value {
                    return Some(index);
                }
            } else if character == '\\' && active_quote == '"' {
                if let Some((_, escaped)) = chars.next() {
                    current_word.push(escaped);
                }
            } else {
                current_word.push(character);
            }
            continue;
        }

        match character {
            '\\' => {
                if let Some((_, escaped)) = chars.next() {
                    current_word.push(escaped);
                }
            }
            '\'' | '"' => quote = Some(character),
            character if character.is_whitespace() => {
                flush_shell_word(&mut current_word, &mut words)
            }
            '#' if current_word.is_empty() => break,
            ';' => finish_shell_command(&mut current_word, &mut words, &mut pipefail_enabled),
            '&' => {
                if chars.peek().is_some_and(|(_, character)| *character == '&') {
                    chars.next();
                }
                finish_shell_command(&mut current_word, &mut words, &mut pipefail_enabled);
            }
            '|' => {
                if chars.peek().is_some_and(|(_, character)| *character == '|') {
                    chars.next();
                    finish_shell_command(&mut current_word, &mut words, &mut pipefail_enabled);
                } else if case_pattern_separator(script, index) {
                    current_word.clear();
                    words.clear();
                } else {
                    // `set -o pipefail | command` runs `set` in a pipeline
                    // subshell, so it does not protect this pipeline.
                    flush_shell_word(&mut current_word, &mut words);
                    let low_value_pipeline = pipeline_has_low_value_producer(script, index, &words);
                    if !pipefail_enabled && !low_value_pipeline {
                        return Some(index);
                    }
                    current_word.clear();
                    words.clear();
                }
            }
            _ => current_word.push(character),
        }
    }

    None
}

fn instruction_character_span(
    source: &str,
    instruction: &Instruction,
    logical: &str,
    logical_offset: usize,
    character: char,
) -> SourceSpan {
    if character == '|' {
        let ordinal = shell_pipeline_offsets(logical)
            .iter()
            .position(|offset| *offset == logical_offset);
        return ordinal
            .and_then(|ordinal| {
                shell_pipeline_offsets(&instruction.raw)
                    .get(ordinal)
                    .copied()
            })
            .map(|offset| instruction_match_span(source, instruction, offset, offset + 1))
            .unwrap_or(instruction.span);
    }
    instruction
        .raw
        .match_indices(character)
        .next()
        .map_or(instruction.span, |(offset, matched)| {
            instruction_match_span(source, instruction, offset, offset + matched.len())
        })
}

fn shell_pipeline_offsets(script: &str) -> Vec<usize> {
    let bytes = script.as_bytes();
    let mut offsets = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' && quote != Some(b'\'') {
            escaped = true;
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
            continue;
        }
        if byte == b'|'
            && (quote.is_none()
                || (quote == Some(b'"') && command_substitution_pipe_is_operator(script, index)))
            && bytes.get(index.wrapping_sub(1)) != Some(&b'|')
            && bytes.get(index + 1) != Some(&b'|')
        {
            offsets.push(index);
        }
    }
    offsets
}

fn looks_like_powershell(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod")
        || lower.contains("out-file")
        || lower.contains("write-host")
        || lower.contains("$env:")
        || lower.contains("$erroractionpreference")
}

fn invokes_non_posix_shell(command: &str) -> bool {
    [
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "cmd",
        "cmd.exe",
    ]
    .iter()
    .any(|shell| shell_invokes_command(command, shell))
}

fn unclosed_command_substitution(before: &str) -> bool {
    before
        .rfind("$(")
        .is_some_and(|open| before.rfind(')').is_none_or(|close| close < open))
}

fn command_substitution_pipe_is_operator(script: &str, pipe: usize) -> bool {
    let before = &script[..pipe];
    let Some(open) = before.rfind("$(") else {
        return false;
    };
    if before.rfind(')').is_some_and(|close| close > open) {
        return false;
    }

    let mut quote = None;
    let mut escaped = false;
    for byte in before[open + 2..].bytes() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' && quote != Some(b'\'') {
            escaped = true;
        } else if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
        }
    }
    quote.is_none()
}

fn command_substitution_producer(before: &str) -> Option<&str> {
    let open = before.rfind("$(")? + 2;
    before[open..]
        .split([';', '&', '|'])
        .next()?
        .split_whitespace()
        .find(|word| !word.contains('='))
}

fn case_pattern_separator(script: &str, pipe: usize) -> bool {
    let before = &script[..pipe];
    let case_start = before.rfind("case ");
    if case_start.is_none()
        || before
            .rfind("esac")
            .is_some_and(|esac| Some(esac) > case_start)
    {
        return false;
    }
    let pattern_start = before
        .rfind(";;")
        .map(|position| position + 2)
        .or_else(|| before.rfind(" in ").map(|position| position + 4))
        .unwrap_or_else(|| before.rfind('\n').map_or(0, |position| position + 1));
    if before[pattern_start..].contains(')') {
        return false;
    }
    script[pipe + 1..]
        .split(['\n', ';'])
        .next()
        .is_some_and(|remainder| remainder.contains(')'))
}

fn pipeline_has_low_value_producer(script: &str, pipe: usize, words: &[String]) -> bool {
    if pipeline_matches_low_value_pattern(script, pipe) {
        return true;
    }
    if matches!(
        command_substitution_producer(&script[..pipe]),
        Some("yes" | "echo" | "uname" | "dpkg" | "readlink")
    ) {
        return true;
    }
    if matches!(
        shell_executable(words),
        Some("yes" | "echo" | "uname" | "dpkg" | "readlink")
    ) {
        return true;
    }
    if matches!(
        next_pipeline_executable(&script[pipe + 1..]),
        Some(":" | "sha256sum" | "shasum")
    ) {
        return true;
    }
    if words.last().is_some_and(|word| word == "}") {
        let group = script[..pipe].rsplit_once('{').map(|(_, group)| group);
        return group.is_some_and(|group| {
            group
                .split(';')
                .map(str::trim)
                .filter(|command| !command.is_empty() && *command != "}")
                .all(|command| command.starts_with("echo ") || command == "echo")
        });
    }
    false
}

fn pipeline_matches_low_value_pattern(script: &str, pipe: usize) -> bool {
    const PATTERNS: &[&str] = &[
        r"(?is)\bfind\b[^;&|\n]*\|\s*head\b[^;&|\n]*(?:\|\s*xargs\b[^;&|\n]*)?",
        r"(?is)\b(?:pip|pip3|uv\s+pip)\s+freeze\s*\|\s*grep\b[^;&\n]*",
        r"(?is)\bif\s+apt\s+list\b[^;&|\n]*\|\s*grep\b[^;&\n]*",
        r"(?is)[`$]\(?\s*getent\s+group\b[^;&|\n]*\|\s*cut\b[^;&\n]*",
        r"(?is)\becho\b[^;&|\n]*\|\s*debconf-set-selections\b[^;&\n]*",
        r"(?is)\$\(\s*cat\b[^;&|\n]*\|\s*xargs\b[^;&\n]*\)",
        r"(?is)\bls\s+-v\b[^;&|\n]*\|\s*tail\b[^;&\n]*",
        r"(?is)\$\(\s*ls\b[^;&|\n]*\|\s*grep\b[^;&\n]*\)",
        r"(?is)\$\(\s*ls\b[^;&|\n]*\|\s*sed\b[^;&\n]*\)",
        r"(?is)\$\(\s*tar\b[^;&|\n]*\|\s*tail\b[^;&|\n]*\|\s*cut\b[^;&\n]*\)",
        r"(?is)\becho\s+[^;&\n]*\|\s*tee\b[^;&\n]*\|\s*tee\b[^;&\n]*",
    ];
    PATTERNS.iter().any(|pattern| {
        Regex::new(pattern)
            .expect("valid low-value pipeline regex")
            .find_iter(script)
            .any(|matched| matched.start() <= pipe && pipe < matched.end())
    })
}

fn next_pipeline_executable(script: &str) -> Option<&str> {
    script
        .trim_start_matches(|character: char| character.is_whitespace() || character == '\\')
        .split_whitespace()
        .next()
}

fn shell_executable(words: &[String]) -> Option<&str> {
    words
        .iter()
        .find(|word| {
            (!word.contains('=') || word.starts_with('='))
                && !matches!(
                    word.as_str(),
                    "if" | "then" | "elif" | "while" | "until" | "do" | "!" | "{" | "}"
                )
        })
        .map(String::as_str)
}

fn flush_shell_word(current_word: &mut String, words: &mut Vec<String>) {
    if !current_word.is_empty() {
        words.push(std::mem::take(current_word));
    }
}

fn finish_shell_command(
    current_word: &mut String,
    words: &mut Vec<String>,
    pipefail_enabled: &mut bool,
) {
    flush_shell_word(current_word, words);
    if words.first().is_some_and(|word| word == "set") {
        let mut arguments = words[1..].iter();
        while let Some(argument) = arguments.next() {
            if (argument == "-o" || argument == "+o")
                && arguments.next().is_some_and(|value| value == "pipefail")
            {
                *pipefail_enabled = argument == "-o";
                words.clear();
                return;
            }
            if argument.starts_with('-')
                && argument[1..].contains('o')
                && arguments.next().is_some_and(|value| value == "pipefail")
            {
                *pipefail_enabled = true;
                words.clear();
                return;
            }
        }
    }
    words.clear();
}

fn rule_wget_and_curl(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let uses_wget = instrs_of(instrs, "RUN")
        .iter()
        .any(|i| shell_invokes_command(&run_script(i), "wget"));
    let uses_curl = instrs_of(instrs, "RUN")
        .iter()
        .any(|i| shell_invokes_command(&run_script(i), "curl"));
    if uses_wget && uses_curl {
        return vec![Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF058".into(),
            severity: Severity::Info,
            line: 0,
            message: "Both wget and curl are used — pick one and use it consistently".to_string(),
            roast: "You're using both wget and curl in the same Dockerfile. They do the same \
                    thing. Pick one. Commit to it. Your image doesn't need two download tools \
                    any more than it needs two fire extinguishers."
                .to_string(),
        }];
    }
    vec![]
}

fn rule_yarn_cache_clean(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    persistent_run_instructions(instrs)
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("yarn install") || a.contains("yarn add"))
                && !a.contains("yarn cache clean")
                && !has_language_cache_mount(i, "yarn")
                && !shell_assignment_value(a, "YARN_CACHE_FOLDER")
                    .is_some_and(|directory| has_ephemeral_mount_covering(i, &directory))
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF055".into(),
            severity: Severity::Info,
            line: i.line,
            message: "yarn install without yarn cache clean — yarn cache is left in the image"
                .to_string(),
            roast: "yarn install without cleaning the cache. Yarn dutifully stores downloaded \
                    packages in a cache that you are now shipping to production. \
                    Add `&& yarn cache clean` after install."
                .to_string(),
        })
        .collect()
}

fn shell_assignment_value(command: &str, name: &str) -> Option<String> {
    Regex::new(&format!(
        r#"(?:^|\s){}=["']?(?P<value>[^\s"']+)"#,
        regex::escape(name)
    ))
    .expect("escaped variable name creates a valid assignment regex")
    .captures(command)
    .and_then(|capture| capture.name("value"))
    .map(|value| value.as_str().trim_end_matches([';', '\\']).to_string())
}

fn rule_wget_no_progress(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            let script = run_script(i);
            shell_invokes_command(&script, "wget")
                && !executes_remote_script(&script)
                && !a.contains("--progress")
                && !a.contains("-q")
                && !a.contains("--quiet")
                && !a
                    .split_whitespace()
                    .any(|token| token == "-nv" || token == "--no-verbose")
                && (a.contains("http://") || a.contains("https://") || a.contains("ftp://"))
        })
        .map(|i| {
            finding_at_span(
                "DF056",
                Severity::Info,
                shell_command_span(raw, i, "wget"),
                "wget without --progress flag produces verbose progress output in build logs"
                    .to_string(),
                "wget without --progress=dot:giga will spam your build logs with a progress \
                    bar that looks great locally and fills 50MB of CI log storage. \
                    Use --progress=dot:giga or -q to stay quiet.",
            )
        })
        .collect()
}

fn rule_pip_version_pinning(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("pip install") || a.contains("pip3 install"))
                && !a.contains("-r ")
                && !a.contains("--requirement")
                && !a.contains("==")
                && !a.contains(">=")
                && !a.contains("<=")
                && !a.contains("~=")
                && !a.contains(".txt")
                && !is_local_pip_install(a)
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF051".into(),
            severity: Severity::Warning,
            line: i.line,
            message:
                "pip install without version pinning — use package==version for reproducibility"
                    .to_string(),
            roast: "pip install with no version pins. Every build pulls 'latest' and \
                    one day something breaks and you spend three hours bisecting which \
                    transitive dependency changed. Use package==version."
                .to_string(),
        })
        .collect()
}

fn is_local_pip_install(command: &str) -> bool {
    let Some(arguments) = pip_install_arguments(command) else {
        return false;
    };
    let words = arguments
        .split(['&', '|', ';'])
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    let mut targets = Vec::new();
    let mut skip_option_value = false;
    let mut dynamic_target = false;
    for word in words {
        if skip_option_value {
            skip_option_value = false;
            continue;
        }
        let argument = word.trim_matches(['\'', '"', '(', ')']);
        if matches!(argument, "-e" | "--editable") {
            continue;
        }
        if argument.starts_with('$') && !argument.contains('/') {
            dynamic_target = true;
            continue;
        }
        if argument.starts_with("$(") || argument == "realpath" {
            continue;
        }
        if matches!(
            argument,
            "-f" | "--find-links"
                | "-i"
                | "--trusted-host"
                | "--python"
                | "--target"
                | "--prefix"
                | "--root"
        ) {
            skip_option_value = true;
            continue;
        }
        if argument == "--extra-index-url" || argument == "--index-url" {
            break;
        }
        if argument.starts_with('-') || argument.contains('=') && !argument.contains('/') {
            continue;
        }
        targets.push(argument);
    }
    (dynamic_target || !targets.is_empty())
        && targets.iter().all(|argument| {
            matches!(*argument, "." | "./")
                || argument.starts_with("./")
                || argument.starts_with("../")
                || argument.starts_with('/')
                || argument.starts_with("~/")
                || argument.starts_with("file:")
                || (!argument.contains("://")
                    && (argument.contains('/')
                        || argument.contains('*')
                        || argument.ends_with(".whl")
                        || argument.ends_with(".tar.gz")
                        || argument.ends_with(".tgz")
                        || argument.ends_with(".zip")))
        })
}

fn pip_install_arguments(command: &str) -> Option<&str> {
    ["pip install", "pip3 install"]
        .into_iter()
        .find_map(|install| {
            command
                .find(install)
                .map(|position| &command[position + install.len()..])
        })
}

fn rule_apk_version_pinning(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let apk = Regex::new(r"(?i)\bapk\b(?P<body>[^;&|\n]*)").expect("valid apk invocation regex");
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let script = run_script(i);
            subcommand_arguments(
                &script,
                &apk,
                "add",
                &[
                    "--arch",
                    "--cache-dir",
                    "--keys-dir",
                    "--repositories-file",
                    "--repository",
                    "--root",
                    "-X",
                ],
            )
            .into_iter()
            .any(apk_add_has_unpinned_package)
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF052".into(),
            severity: Severity::Info,
            line: i.line,
            message: "apk add without version pinning — use package=version for reproducibility"
                .to_string(),
            roast: "apk add with no version? You chose Alpine to be minimal and fast, then \
                    immediately added unpinned packages. Your builds are non-deterministic \
                    by design now. Use package=version."
                .to_string(),
        })
        .collect()
}

/// Return arguments following a package-manager subcommand while accepting
/// global options between the executable and subcommand. Shell control
/// operators bound each regex match, so a later unrelated command cannot be
/// mistaken for the requested subcommand.
fn subcommand_arguments<'a>(
    script: &'a str,
    invocation: &Regex,
    subcommand: &str,
    options_with_values: &[&str],
) -> Vec<&'a str> {
    invocation
        .captures_iter(script)
        .filter_map(|capture| {
            let body = capture.name("body")?;
            let mut cursor = 0;
            let mut skip_value = false;
            while let Some((_, end, token)) = next_shell_token(body.as_str(), cursor) {
                cursor = end;
                let token = token.trim_matches(['\'', '"']);
                if skip_value {
                    skip_value = false;
                    continue;
                }
                if token.eq_ignore_ascii_case(subcommand) {
                    return Some(&script[body.start() + end..body.end()]);
                }
                if options_with_values
                    .iter()
                    .any(|option| token.eq_ignore_ascii_case(option))
                {
                    skip_value = true;
                    continue;
                }
                if token.starts_with('-') {
                    continue;
                }
                break;
            }
            None
        })
        .collect()
}

fn apk_add_has_unpinned_package(arguments: &str) -> bool {
    let mut skip_next = false;
    for token in arguments.split_whitespace() {
        if matches!(token, "&&" | "||" | ";" | "|") {
            break;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if matches!(
            token,
            "--repository"
                | "-X"
                | "--virtual"
                | "-t"
                | "--arch"
                | "--root"
                | "--keys-dir"
                | "--repositories-file"
        ) {
            skip_next = true;
            continue;
        }
        if token.starts_with('-') || token.is_empty() {
            continue;
        }
        if !token.contains('=') && !token.contains('>') && !token.contains('<') {
            return true;
        }
    }
    false
}

fn rule_gem_version_pinning(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            a.contains("gem install")
                && !a.contains(" -v ")
                && !a.contains("--version")
                && !a.contains(':')
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF053".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "gem install without version pinning — use gem install <gem>:<version>"
                .to_string(),
            roast: "gem install with no version. RubyGems will grab whatever's latest today. \
                    Next week it grabs something else. Your builds are a dice roll. \
                    Use gem install name:version."
                .to_string(),
        })
        .collect()
}

fn rule_go_install_version(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut stage_modules = std::collections::HashMap::new();
    let mut current_alias = None;
    let mut module_managed = false;
    let mut findings = Vec::new();
    let go_module = Regex::new(r"(?:^|[;&|]\s*)go\s+mod\s+(?:download|tidy|vendor)\b")
        .expect("valid go module command regex");

    for instruction in instrs {
        match instruction.instruction.as_str() {
            "FROM" => {
                if let Some(from) = parse_from_arguments(&instruction.arguments) {
                    module_managed = stage_modules
                        .get(&from.image.to_ascii_lowercase())
                        .copied()
                        .unwrap_or(false);
                    current_alias = from.alias.map(str::to_ascii_lowercase);
                }
            }
            "COPY" | "ADD" => {
                module_managed |= instruction_operands(instruction)
                    .iter()
                    .any(|operand| matches!(script_basename(operand), "go.mod" | "go.sum"));
            }
            "RUN" => {
                module_managed |= go_module.is_match(&instruction.arguments);
                if instruction
                    .arguments
                    .split(['&', '|', ';'])
                    .any(|segment| go_install_needs_version(segment, module_managed))
                {
                    findings.push(finding_at_span(
                        "DF054",
                        Severity::Warning,
                        shell_command_span(raw, instruction, "go"),
                        "go install without @version — use go install package@version".to_string(),
                        "This external Go package is not governed by the current module. Add an explicit @version for reproducibility.",
                    ));
                }
            }
            _ => {}
        }
        if let Some(alias) = &current_alias {
            stage_modules.insert(alias.clone(), module_managed);
        }
    }
    findings
}

fn go_install_needs_version(segment: &str, module_managed: bool) -> bool {
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while let Some((_, end, token)) = next_shell_token(segment, cursor) {
        tokens.push(token);
        cursor = end;
    }
    let mut words = tokens.into_iter();
    let executable = loop {
        match words.next() {
            Some(word) if word.contains('=') && !word.starts_with('=') && !word.contains('/') => {}
            word => break word,
        }
    };
    if executable != Some("go") || words.next() != Some("install") {
        return false;
    }
    let arguments = words.collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|argument| *argument == "tool")
    {
        return false;
    }

    let options_with_values = [
        "-C",
        "-mod",
        "-modfile",
        "-overlay",
        "-pgo",
        "-tags",
        "-ldflags",
        "-gcflags",
        "-asmflags",
        "-pkgdir",
        "-toolexec",
    ];
    let mut skip_value = false;
    let mut packages = Vec::new();
    for argument in arguments {
        if skip_value {
            skip_value = false;
            continue;
        }
        if options_with_values.contains(&argument) {
            skip_value = true;
        } else if !argument.starts_with('-') {
            packages.push(argument);
        }
    }
    if packages.is_empty() {
        return false;
    }
    if packages.iter().any(|package| {
        package
            .rsplit_once('@')
            .is_some_and(|(_, version)| version.eq_ignore_ascii_case("latest"))
    }) {
        return true;
    }
    if packages.iter().all(|package| package.contains('@')) {
        return false;
    }
    !module_managed
}

fn rule_copy_multi_arg_slash(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "COPY")
        .into_iter()
        .filter(|i| {
            let args = instruction_operands(i);
            if args.len() > 2 {
                let dest = args.last().unwrap_or(&"");
                !dest.ends_with('/') && !matches!(*dest, "." | "./")
            } else {
                false
            }
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF048".into(),
            severity: Severity::Error,
            line: i.line,
            message: "COPY with multiple sources requires the destination to end with /"
                .to_string(),
            roast: "COPY with multiple sources and a destination that doesn't end with /? \
                    Docker will complain. Or worse, silently do something weird. \
                    Add a trailing slash to the destination."
                .to_string(),
        })
        .collect()
}

fn rule_copy_from_undefined_stage(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut aliases = Vec::<String>::new();
    let mut findings = Vec::new();
    for instruction in instrs {
        if instruction.instruction == "FROM" {
            if let Some(alias) =
                parse_from_arguments(&instruction.arguments).and_then(|from| from.alias)
            {
                aliases.push(alias.to_ascii_lowercase());
            }
            continue;
        }
        if instruction.instruction != "COPY" {
            continue;
        }
        let Some(flag) = instruction
            .flags
            .iter()
            .find(|flag| flag.name.eq_ignore_ascii_case("from"))
        else {
            continue;
        };
        let Some(reference) = flag.value.as_deref() else {
            continue;
        };
        let reference_lower = reference.to_ascii_lowercase();
        if reference.parse::<usize>().is_ok()
            || aliases.iter().any(|alias| alias == &reference_lower)
            || reference.contains(['/', ':', '@', '$'])
        {
            continue;
        }
        let candidates = aliases
            .iter()
            .filter(|alias| stage_alias_resembles(&reference_lower, alias))
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            continue;
        }
        let candidate = candidates[0];
        findings.push(finding_at_span(
            "DF049",
            Severity::Info,
            flag.span,
            format!(
                "COPY --from={reference} is unresolved and resembles declared stage '{candidate}'"
            ),
            "This may be an intentional external image or named context, but it also looks like a stage-alias typo. Verify the reference before Docker tries to pull it.",
        ));
    }
    findings
}

fn stage_alias_resembles(reference: &str, alias: &str) -> bool {
    if reference.len() >= 3
        && (alias
            .strip_suffix(reference)
            .is_some_and(|prefix| prefix.ends_with('-'))
            || alias
                .strip_prefix(reference)
                .is_some_and(|suffix| suffix.starts_with('-')))
    {
        return true;
    }
    reference.len() >= 4
        && alias.len() >= 4
        && reference.len().abs_diff(alias.len()) <= 1
        && edit_distance_at_most_one(reference.as_bytes(), alias.as_bytes())
}

fn edit_distance_at_most_one(left: &[u8], right: &[u8]) -> bool {
    if left.len().abs_diff(right.len()) > 1 {
        return false;
    }
    if left.len() == right.len() {
        let differences = left
            .iter()
            .zip(right)
            .enumerate()
            .filter_map(|(index, (left, right))| (left != right).then_some(index))
            .collect::<Vec<_>>();
        if differences.len() == 2
            && differences[1] == differences[0] + 1
            && left[differences[0]] == right[differences[1]]
            && left[differences[1]] == right[differences[0]]
        {
            return true;
        }
    }
    let (shorter, longer) = if left.len() <= right.len() {
        (left, right)
    } else {
        (right, left)
    };
    let mut short = 0;
    let mut long = 0;
    let mut edits = 0;
    while short < shorter.len() && long < longer.len() {
        if shorter[short] == longer[long] {
            short += 1;
            long += 1;
            continue;
        }
        edits += 1;
        if edits > 1 {
            return false;
        }
        if shorter.len() == longer.len() {
            short += 1;
        }
        long += 1;
    }
    edits + usize::from(long < longer.len()) <= 1
}

fn rule_copy_from_self(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re_from = Regex::new(r"(?i)--from=(\S+)").unwrap();
    let mut current_alias: Option<String> = None;
    let mut findings = Vec::new();
    for i in instrs {
        if i.instruction == "FROM" {
            current_alias = parse_from_arguments(&i.arguments)
                .and_then(|from| from.alias)
                .map(str::to_lowercase);
        } else if i.instruction == "COPY" {
            if let Some(cap) = re_from.captures(&i.arguments) {
                let from_ref = cap[1].to_lowercase();
                if let Some(ref alias) = current_alias {
                    if &from_ref == alias {
                        findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
                            rule: "DF050".into(),
                            severity: Severity::Error,
                            line: i.line,
                            message: format!(
                                "COPY --from={} references the current build stage — circular dependency",
                                &cap[1]
                            ),
                            roast: format!(
                                "COPY --from={} inside the same stage named {}. \
                                 That's a circular reference. Docker cannot copy from itself. \
                                 This will fail at build time.",
                                &cap[1], &cap[1]
                            ),
                        });
                    }
                }
            }
        }
    }
    findings
}

fn rule_dnf_clean(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let persistent_stages = persistent_stage_indices(instrs);
    let layer_stages = layer_persistent_stage_indices(instrs);
    let instruction_stages = instruction_stage_indices(instrs);
    let install = Regex::new(r"\b(?P<manager>microdnf|dnf|tdnf)\s+install\b")
        .expect("valid dnf-family install regex");
    instrs
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            let manager = (instruction.instruction == "RUN")
                .then(|| install.captures(&instruction.arguments))
                .flatten()
                .and_then(|capture| capture.name("manager"))?;
            let cache_is_ephemeral = ["/var/cache/dnf", "/var/cache/tdnf", "/var/cache/yum"]
                .iter()
                .any(|path| has_ephemeral_mount_covering(instruction, path));
            (!cleans_dnf_cache(&instruction.arguments)
                && !cache_is_ephemeral
                && cache_reaches_final_image(
                    instrs,
                    &instruction_stages,
                    &persistent_stages,
                    &layer_stages,
                    index,
                    cleans_dnf_cache,
                ))
            .then_some((instruction, manager.as_str()))
        })
        .map(|(instruction, manager)| {
            finding_at_span(
                "DF046",
                Severity::Warning,
                instruction_substring_span(
                    raw,
                    instruction,
                    &["microdnf install", "tdnf install", "dnf install"],
                ),
                format!(
                    "{manager} clean all missing after {manager} install — RPM cache bloats the image"
                ),
                "The RPM package cache reaches the final image. Clean it in the install layer, or before copying a stage filesystem snapshot.",
            )
        })
        .collect()
}

fn rule_yum_clean(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let persistent_stages = persistent_stage_indices(instrs);
    let layer_stages = layer_persistent_stage_indices(instrs);
    let instruction_stages = instruction_stage_indices(instrs);
    instrs
        .iter()
        .enumerate()
        .filter(|(index, instruction)| {
            instruction.instruction == "RUN"
                && instruction.arguments.contains("yum install")
                && !cleans_yum_cache(&instruction.arguments)
                && !has_ephemeral_mount_covering(instruction, "/var/cache/yum")
                && cache_reaches_final_image(
                    instrs,
                    &instruction_stages,
                    &persistent_stages,
                    &layer_stages,
                    *index,
                    cleans_yum_cache,
                )
        })
        .map(|(_, instruction)| {
            finding_at_span(
                "DF047",
                Severity::Warning,
                instruction_substring_span(raw, instruction, &["yum install"]),
                "yum clean all missing after yum install — cache stays in the image".to_string(),
                "The Yum cache reaches the final image. Clean it in the install layer, or before copying a stage filesystem snapshot.",
            )
        })
        .collect()
}

fn rule_zypper_no_y(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("zypper install") || a.contains("zypper in "))
                && !a.contains("-y")
                && !a.contains("--non-interactive")
                && !a.contains(" -n ")
                && !a.contains(" -n\n")
                && !a.starts_with("-n ")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF043".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "zypper install without non-interactive flag (-y) will hang in a build"
                .to_string(),
            roast: "zypper install without -y in a container build? It'll wait for input that \
                    will never arrive, like a chatbot asking for emotional validation."
                .to_string(),
        })
        .collect()
}

fn rule_zypper_dist_upgrade(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            i.arguments.contains("zypper dist-upgrade") || i.arguments.contains("zypper dup")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF044".into(),
            severity: Severity::Warning,
            line: i.line,
            message:
                "zypper dist-upgrade upgrades all packages unpredictably — avoid in Dockerfiles"
                    .to_string(),
            roast: "zypper dist-upgrade: the 'nuke everything and hope for the best' approach to \
                    package management. Your image will be different every single build. Congrats."
                .to_string(),
        })
        .collect()
}

fn rule_zypper_clean(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("zypper install") || a.contains("zypper in "))
                && !a.contains("zypper clean")
                && !a.contains("zypper cc")
                && !removes_cache_path(a, "/var/cache/zypp")
                && !removes_cache_path(a, "/var/cache/zypper")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF045".into(),
            severity: Severity::Info,
            line: i.line,
            message: "zypper cache not cleaned after install — adds unnecessary image bloat"
                .to_string(),
            roast:
                "zypper install without `zypper clean --all` afterwards. You're hoarding package \
                    metadata in your image. Clean it up."
                    .to_string(),
        })
        .collect()
}

fn rule_expose_port_range(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "EXPOSE") {
        for port_spec in i.arguments.split_whitespace() {
            let port_str = port_spec.split('/').next().unwrap_or(port_spec);
            if let Ok(port) = port_str.parse::<u32>() {
                if port > 65535 {
                    findings.push(Finding {
                        column: 0,
                        end_line: 0,
                        end_column: 0,
                        rule: "DF040".into(),
                        severity: Severity::Error,
                        line: i.line,
                        message: format!("EXPOSE port {} is out of valid range (0-65535)", port),
                        roast: format!(
                            "Port {}? That's not a port, that's a zip code. \
                             Valid UNIX ports are 0-65535. Pick a real one.",
                            port
                        ),
                    });
                }
            }
        }
    }
    findings
}

fn rule_multiple_healthcheck(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let checks: Vec<_> = instrs_of(instrs, "HEALTHCHECK");
    if checks.len() <= 1 {
        return vec![];
    }
    checks[1..]
        .iter()
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF041".into(),
            severity: Severity::Error,
            line: i.line,
            message: "Multiple HEALTHCHECK instructions — only the last one applies".to_string(),
            roast: "Multiple HEALTHCHECKs but only the last one counts. The earlier ones are \
                haunting your image for no reason. One health check, one truth."
                .to_string(),
        })
        .collect()
}

fn rule_unique_stage_aliases(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "FROM") {
        if let Some(original_alias) = parse_from_arguments(&i.arguments).and_then(|from| from.alias)
        {
            let alias = original_alias.to_lowercase();
            if let Some(&prev_line) = seen.get(&alias) {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF042".into(),
                    severity: Severity::Error,
                    line: i.line,
                    message: format!(
                        "FROM alias '{}' is already defined on line {}",
                        original_alias, prev_line
                    ),
                    roast: format!(
                        "Two stages named '{}'. Docker uses the last one; the first is dead code. \
                         Give your stages unique names.",
                        original_alias
                    ),
                });
            } else {
                seen.insert(alias, i.line);
            }
        }
    }
    findings
}

fn rule_invalid_instruction_order(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    if instrs.is_empty() {
        return vec![];
    }
    let first = &instrs[0];
    if first.instruction != "FROM" && first.instruction != "ARG" {
        return vec![Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF037".into(),
            severity: Severity::Error,
            line: first.line,
            message: format!(
                "'{}' before FROM — Dockerfile must begin with FROM, ARG, or a comment",
                first.instruction
            ),
            roast: "Your Dockerfile doesn't start with FROM. That's like starting a recipe with \
                    'season to taste' before listing any ingredients. Docker is confused. So am I."
                .to_string(),
        }];
    }
    vec![]
}

fn rule_multiple_cmd(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut cmds = Vec::new();
    let mut report_duplicates = |cmds: &mut Vec<&Instruction>| {
        if cmds.len() > 1 {
            findings.extend(cmds.iter().skip(1).map(|i| Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF038".into(),
                severity: Severity::Warning,
                line: i.line,
                message: "Multiple CMD instructions — only the last one takes effect".to_string(),
                roast:
                    "Multiple CMDs and only the last one counts. The others are ghosts haunting your \
                    Dockerfile, contributing nothing except confusion. Pick one."
                        .to_string(),
            }));
        }
        cmds.clear();
    };
    for instruction in instrs {
        if instruction.instruction == "FROM" {
            report_duplicates(&mut cmds);
        }
        if instruction.instruction == "CMD" {
            cmds.push(instruction);
        }
    }
    report_duplicates(&mut cmds);
    findings
}

fn rule_multiple_entrypoint(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut seen_in_stage = false;
    let mut findings = Vec::new();
    for instruction in instrs {
        if instruction.instruction == "FROM" {
            seen_in_stage = false;
        } else if instruction.instruction == "ENTRYPOINT" {
            if seen_in_stage {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF039".into(),
                    severity: Severity::Error,
                    line: instruction.line,
                    message: "Multiple ENTRYPOINT instructions — only the last one takes effect"
                        .to_string(),
                    roast: "Two ENTRYPOINTs. Bold. Only the last one runs; the first is just expensive \
                        furniture. Delete it."
                        .to_string(),
                });
            }
            seen_in_stage = true;
        }
    }
    findings
}

fn rule_no_user_instruction(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let Some(state) = final_runtime_state(instrs) else {
        return vec![];
    };
    if state.effective_user.is_some() || (!state.has_command && state.base_metadata_known) {
        return vec![];
    }
    let (message, roast) = if state.base_metadata_known {
        (
            "No USER instruction found — container will run as root by default",
            "The final stage has no USER, so its process runs as root. Declare the intended runtime identity explicitly.",
        )
    } else {
        (
            "No USER declared in the final stage — the runtime user depends on the base image",
            "The runtime identity comes from external image metadata. Declare USER explicitly if that dependency is unintended.",
        )
    };
    vec![Finding {
        column: 0,
        end_line: 0,
        end_column: 0,
        rule: "DF020".into(),
        severity: Severity::Info,
        line: 0,
        message: message.to_string(),
        roast: roast.to_string(),
    }]
}

fn rule_apt_upgrade(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"\bapt(-get)?\s+(dist-upgrade|upgrade)\b").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&i.arguments))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF069".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "apt-get upgrade/dist-upgrade makes builds non-reproducible".to_string(),
            roast:
                "apt-get upgrade: 'let's upgrade everything and see what breaks in six months'. \
                    Your image will be different every time you build it. \
                    Pin the packages you actually need instead of upgrading everything blindly."
                    .to_string(),
        })
        .collect()
}

fn rule_copy_before_install(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    const PKG_CMDS: &[&str] = &[
        "npm install",
        "npm ci",
        "pip install",
        "pip3 install",
        "yarn install",
        "yarn add",
        "bundle install",
        "composer install",
        "pnpm install",
        "bun install",
    ];
    let mut findings = Vec::new();
    let mut broad_copy_line: Option<usize> = None;

    for i in instrs {
        match i.instruction.as_str() {
            "FROM" => {
                broad_copy_line = None;
            }
            "COPY" => {
                let tokens: Vec<&str> = i
                    .arguments
                    .split_whitespace()
                    .filter(|t| !t.starts_with("--"))
                    .collect();
                if tokens.len() >= 2 && (tokens[0] == "." || tokens[0].ends_with("/.")) {
                    broad_copy_line = Some(i.line);
                }
            }
            "RUN" => {
                if let Some(copy_line) = broad_copy_line {
                    if PKG_CMDS.iter().any(|cmd| i.arguments.contains(cmd))
                        && !is_local_pip_install(&i.arguments)
                    {
                        findings.push(Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
                            rule: "DF070".into(),
                            severity: Severity::Warning,
                            line: copy_line,
                            message: "COPY . before package install — invalidates Docker layer cache on every source change".to_string(),
                            roast: "COPY . . before npm/pip install means every code change rebuilds \
                                    dependencies from scratch. Copy just the manifest first \
                                    (e.g. COPY package.json ./), run the install, then COPY . . — \
                                    now the install layer is cached between source changes.".to_string(),
                        });
                        broad_copy_line = None;
                    }
                }
            }
            _ => {}
        }
    }
    findings
}
