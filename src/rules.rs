use crate::parser::{
    parse_document, DiagnosticSeverity, Instruction, InstructionForm, SourceSpan,
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
            severity: Severity::Warning,
            description: "Use multi-stage builds to reduce image size",
            func: rule_no_multistage,
        },
        Rule {
            id: "DF013",
            severity: Severity::Error,
            description: "Avoid storing secrets in ENV variables",
            func: rule_secrets_in_env,
        },
        Rule {
            id: "DF014",
            severity: Severity::Error,
            description: "Avoid hardcoding passwords or tokens in ARG/ENV",
            func: rule_hardcoded_secrets,
        },
        Rule {
            id: "DF020",
            severity: Severity::Warning,
            description: "Set explicit non-root USER",
            func: rule_no_user_instruction,
        },
        Rule {
            id: "DF003",
            severity: Severity::Warning,
            description: "Combine RUN commands to reduce layers",
            func: rule_many_run_layers,
        },
        Rule {
            id: "DF004",
            severity: Severity::Warning,
            description: "Clean apt/yum/apk cache in the same RUN layer",
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
            severity: Severity::Warning,
            description: "Avoid multiple FROM without aliases (unintended multistage)",
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
            description: "Avoid recursive COPY from root",
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
            description: "Avoid chmod 777 — overly permissive",
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
            severity: Severity::Warning,
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
            description: "Avoid wget|sh pipe patterns (execute remote code)",
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
            severity: Severity::Warning,
            description: "Reserved for invalid COPY --from references",
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
            severity: Severity::Warning,
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
            severity: Severity::Warning,
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
            severity: Severity::Warning,
            description: "Do not use --platform in FROM unless required",
            func: rule_from_platform_flag,
        },
        Rule {
            id: "DF062",
            severity: Severity::Error,
            description: "ENV variable must not reference itself in the same statement",
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
            description: "useradd without -l flag may create excessively large images",
            func: rule_useradd_no_l,
        },
        Rule {
            id: "DF065",
            severity: Severity::Warning,
            description: "FROM uses an unrecognised image registry",
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
            description: "COPY of a local archive — ADD auto-extracts tarballs",
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
            severity: Severity::Warning,
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
            severity: Severity::Error,
            description: "Do not use reserved Dockerfile stage names",
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

fn finding_at_span(rule: &str, severity: Severity, span: SourceSpan, message: String, roast: &str) -> Finding {
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

fn rule_consistent_instruction_casing(instrs: &[Instruction], raw: &str) -> Vec<Finding> {
    let mut expected_uppercase = None;
    let mut findings = Vec::new();
    for instruction in instrs {
        let spelling = instruction.keyword_span.text(raw);
        let is_uppercase = spelling.bytes().all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
        let is_lowercase = spelling.bytes().all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase());
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
    instrs_of(instrs, "FROM").into_iter().filter_map(|instruction| {
        let from_spelling = instruction.keyword_span.text(raw);
        let expected_uppercase = from_spelling.bytes().all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
        instruction.words.iter().find(|word| word.value.eq_ignore_ascii_case("as")).and_then(|word| {
            let is_uppercase = word.raw.bytes().all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_uppercase());
            (expected_uppercase != is_uppercase).then(|| finding_at_span("DF079", Severity::Warning, word.span,
                format!("'{}' should use the same casing as '{}'", word.raw, from_spelling),
                "FROM and AS are on the same team. Give them matching uniforms."))
        })
    }).collect()
}

fn rule_legacy_key_value_format(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs.iter().filter(|instruction| matches!(instruction.instruction.as_str(), "ENV" | "LABEL"))
        .filter_map(|instruction| {
            let words = &instruction.words;
            (words.len() >= 2 && !words[0].value.contains('='))
                .then(|| finding_at_span("DF082", Severity::Warning, words[0].span,
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
            finding_at_span("DF084", Severity::Error, word.span, "Stage name 'scratch' is reserved".into(),
                "Calling a stage scratch is asking Docker to confuse your named stage with its special empty image."))).flatten()
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
    instrs.iter().take_while(|instruction| instruction.instruction != "FROM")
        .filter(|instruction| instruction.instruction == "ARG")
        .filter_map(|instruction| instruction.words.first())
        .map(|word| word.value.split('=').next().unwrap_or(&word.value).to_string())
        .collect()
}

fn known_build_variable(name: &str) -> bool {
    matches!(name, "BUILDPLATFORM" | "BUILDOS" | "BUILDARCH" | "BUILDVARIANT" | "TARGETPLATFORM" | "TARGETOS" | "TARGETARCH" | "TARGETVARIANT" | "HTTP_PROXY" | "HTTPS_PROXY" | "FTP_PROXY" | "NO_PROXY" | "ALL_PROXY")
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
    let mut declared = global_args(instrs);
    let mut findings = Vec::new();
    for instruction in instrs {
        if instruction.instruction == "ARG" || instruction.instruction == "ENV" {
            for word in &instruction.words {
                declared.insert(word.value.split('=').next().unwrap_or(&word.value).to_string());
            }
            continue;
        }
        if instruction.instruction == "RUN" { continue; }
        for variable in &instruction.variables {
            if !declared.contains(&variable.name) && !known_build_variable(&variable.name) {
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

fn has_instr(instrs: &[Instruction], name: &str) -> bool {
    instrs.iter().any(|i| i.instruction == name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FromArguments<'a> {
    image: &'a str,
    alias: Option<&'a str>,
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

fn rule_latest_tag(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut stage_aliases = std::collections::HashSet::new();
    let mut findings = Vec::new();

    for instruction in instrs_of(instrs, "FROM") {
        let Some(from) = parse_from_arguments(&instruction.arguments) else {
            continue;
        };
        let base = from.image;
        let is_previous_stage = stage_aliases.contains(&base.to_lowercase());
        if !is_previous_stage
            && !base.eq_ignore_ascii_case("scratch")
            && (base.ends_with(":latest") || (!base.contains(':') && !base.contains('@')))
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

fn rule_running_as_root(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut effective_user: Option<&Instruction> = None;
    let mut report_root_user = |user: Option<&Instruction>| {
        if let Some(u) = user.filter(|user| is_root_user(&user.arguments)) {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF002".into(),
                severity: Severity::Error,
                line: u.line,
                message: "Container is explicitly set to run as root".to_string(),
                roast: "Congratulations, you're running as root. Your security team is crying, \
                        your CISO is drafting a strongly-worded email, and a hacker somewhere \
                        just smiled."
                    .to_string(),
            });
        }
    };
    for instruction in instrs {
        match instruction.instruction.as_str() {
            "FROM" => {
                report_root_user(effective_user);
                effective_user = None;
            }
            "USER" => effective_user = Some(instruction),
            _ => {}
        }
    }
    report_root_user(effective_user);
    findings
}

fn is_root_user(value: &str) -> bool {
    matches!(value.trim().to_lowercase().as_str(), "root" | "0" | "0:0" | "root:root")
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
            severity: Severity::Warning,
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
                    severity: Severity::Warning,
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
            severity: Severity::Warning,
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
    instrs_of(instrs, "COPY")
        .into_iter()
        .filter(|i| {
            let a = i.arguments.trim();
            a.starts_with(". ") || a == "."
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF007".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "COPY . copies the entire build context — consider a .dockerignore file"
                .to_string(),
            roast: "COPY . — dumping your entire project including node_modules, .git history, \
                    and that .env file with the production database password into the image. \
                    Bold. Reckless. Very DevOps of you."
                .to_string(),
        })
        .collect()
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
        .filter(|i| !i.arguments.trim().starts_with('/') && !i.arguments.trim().starts_with('$'))
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

fn rule_sudo_usage(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"\bsudo\b").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&i.arguments))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF010".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "sudo used inside a container — likely unnecessary".to_string(),
            roast: "sudo inside a Docker container? You're already root (probably). sudo is \
                    just a formality at this point, like putting a 'Wet Floor' sign in the ocean."
                .to_string(),
        })
        .collect()
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
    if froms.len() <= 1 {
        return vec![];
    }
    froms
        .into_iter()
        .skip(1)
        .filter(|i| parse_from_arguments(&i.arguments).is_some_and(|from| from.alias.is_none()))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF023".into(),
            severity: Severity::Warning,
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
    instrs_of(instrs, "COPY")
        .into_iter()
        .filter(|i| {
            let a = i.arguments.trim();
            a.ends_with(" /") || a.contains(" / ") || a.ends_with("/.")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF026".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "COPY to filesystem root — this may overwrite system files".to_string(),
            roast: "Copying files directly to /? Brave. Reckless. Chaotic. You're one typo away \
                    from overwriting /bin/sh and creating a container that doesn't even boot. \
                    Use a dedicated app directory."
                .to_string(),
        })
        .collect()
}

fn rule_pip_no_cache(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            if is_uv_pip_install(a) {
                !a.contains("--no-cache")
            } else {
                (a.contains("pip install") || a.contains("pip3 install"))
                    && !a.contains("--no-cache-dir")
            }
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF030".into(),
            severity: Severity::Info,
            line: i.line,
            message: if is_uv_pip_install(&i.arguments) {
                "uv pip install without --no-cache wastes space in the image layer".to_string()
            } else {
                "pip install without --no-cache-dir wastes space in the image layer".to_string()
            },
            roast: "pip install without --no-cache-dir? You're carrying around a pip cache in \
                    your production image like a tourist with a suitcase full of hotel shampoos. \
                    You don't need those. Add the installer-specific no-cache flag."
                .to_string(),
        })
        .collect()
}

fn is_uv_pip_install(command: &str) -> bool {
    Regex::new(r"(?:^|\s)uv\s+pip\s+install(?:\s|$)")
        .expect("valid uv pip install regex")
        .is_match(command)
}

fn rule_npm_install(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let npm_install = Regex::new(r"\bnpm\s+install\b").expect("valid npm install regex");
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            npm_install.is_match(a) && !a.contains("--production") && !a.contains("--omit=dev")
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

fn rule_chmod_777(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"chmod\s+([-R\s]*)777").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&i.arguments))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF034".into(),
            severity: Severity::Error,
            line: i.line,
            message: "chmod 777 grants world-writable permissions — overly permissive".to_string(),
            roast: "chmod 777? Giving everyone read, write, and execute access is the filesystem \
                    equivalent of leaving your front door open with a sign that says \
                    'free stuff inside'. Minimum permissions, please."
                .to_string(),
        })
        .collect()
}

fn rule_curl_no_fail(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            // only flag when curl is actually fetching something, not being installed as a package
            let has_url = a.contains("http://") || a.contains("https://") || a.contains("ftp://");
            has_url
                && a.contains("curl")
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
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF035".into(),
            severity: Severity::Info,
            line: i.line,
            message: "curl without --fail — HTTP errors won't cause the RUN step to fail"
                .to_string(),
            roast: "curl without --fail means a 404 or 500 response silently succeeds. \
                    Your build will happily continue after downloading an error page and \
                    treating it as a binary. Add --fail and save yourself a 2am debugging session."
                .to_string(),
        })
        .collect()
}

fn rule_no_cmd_or_entrypoint(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    if has_instr(instrs, "CMD") || has_instr(instrs, "ENTRYPOINT") {
        return vec![];
    }
    if instrs.len() < 3 {
        return vec![];
    }
    vec![Finding {
        column: 0,
        end_line: 0,
        end_column: 0,
        rule: "DF036".into(),
        severity: Severity::Warning,
        line: 0,
        message: "No CMD or ENTRYPOINT defined — the container has no default command".to_string(),
        roast: "No CMD or ENTRYPOINT? This container starts, does nothing, and immediately exits \
                like an intern on their first day who didn't read the onboarding docs. \
                Tell it what to run."
            .to_string(),
    }]
}

fn rule_uncleaned_package_cache(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let apt_distclean = Regex::new(r"\bapt-get\s+distclean\b").expect("valid apt distclean regex");
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "RUN") {
        let arg = &i.arguments;
        let has_apt = arg.contains("apt-get install") || arg.contains("apt install");
        let has_yum = arg.contains("yum install") || arg.contains("dnf install");
        let has_apk = arg.contains("apk add") && !arg.contains("--no-cache");
        let cleans_apt_lists =
            arg.contains("rm -rf /var/lib/apt/lists") || apt_distclean.is_match(arg);
        if has_apt && !cleans_apt_lists {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF004".into(),
                severity: Severity::Warning,
                line: i.line,
                message: "apt cache not cleaned after install — adds unnecessary layer size"
                    .to_string(),
                roast: "Not cleaning the apt cache is like finishing a meal and leaving all the \
                        wrappers in the container. Your image is now a trash can. A very expensive \
                        trash can stored in ECR."
                    .to_string(),
            });
        }
        if has_yum && !arg.contains("yum clean all") && !arg.contains("dnf clean all") {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF004".into(),
                severity: Severity::Warning,
                line: i.line,
                message: "yum/dnf cache not cleaned after install".to_string(),
                roast: "You installed packages with yum but didn't clean up. Every megabyte of \
                        cache you leave is a megabyte of shame floating in your registry."
                    .to_string(),
            });
        }
        if has_apk {
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

fn rule_apt_no_y(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            apt_install_commands(a)
                .iter()
                .any(|(tokens, _)| !apt_assumes_yes(tokens))
                && !a.contains("DEBIAN_FRONTEND=noninteractive")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF015".into(),
            severity: Severity::Error,
            line: i.line,
            message: "apt-get install without -y flag will hang waiting for user input".to_string(),
            roast: "apt-get install without -y? Your build is going to sit there, patiently \
                    waiting for a 'yes' that will never come, like a golden retriever waiting \
                    for an owner who's on a cruise ship."
                .to_string(),
        })
        .collect()
}

fn rule_apt_recommends(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("apt-get install") || a.contains("apt install"))
                && !a.contains("--no-install-recommends")
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

fn rule_secrets_in_env(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let secret_patterns = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "auth_token",
        "access_key",
        "secret_key",
        "db_pass",
        "database_password",
    ];
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "ENV") {
        let lower = i.arguments.to_lowercase();
        for pat in &secret_patterns {
            if lower.contains(pat) {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF013".into(),
                    severity: Severity::Error,
                    line: i.line,
                    message: format!("Potential secret in ENV variable (matched: '{}')", pat),
                    roast: format!(
                        "You put a '{}' in an ENV instruction. Congratulations — it's now \
                         immortalized in your image layers, your registry, your CI logs, \
                         and probably a security audit finding. Use Docker secrets or a vault.",
                        pat
                    ),
                });
                break;
            }
        }
    }
    findings
}

fn rule_hardcoded_secrets(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"(?i)(password|secret|token|key|passwd)\s*=\s*\S+").unwrap();
    let mut findings = Vec::new();
    for i in instrs
        .iter()
        .filter(|i| i.instruction == "ARG" || i.instruction == "ENV")
    {
        if let Some(cap) = re.find(&i.arguments) {
            let parts: Vec<&str> = cap.as_str().splitn(2, '=').collect();
            if parts.len() == 2 {
                let val = parts[1].trim();
                if !val.is_empty() && !val.starts_with('$') && val != "\"\"" && val != "''" {
                    findings.push(Finding {
                        column: 0,
                        end_line: 0,
                        end_column: 0,
                        rule: "DF014".into(),
                        severity: Severity::Error,
                        line: i.line,
                        message: "Hardcoded secret value detected in ARG/ENV".to_string(),
                        roast: "A hardcoded secret! How delightfully naive. It's in your git \
                                history forever now. Have fun rotating that. Maybe consider \
                                build secrets or runtime injection next time?"
                            .to_string(),
                    });
                }
            }
        }
    }
    findings
}

fn rule_curl_pipe_sh(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"(curl|wget)[^|]*\|\s*(bash|sh|ash|zsh|fish)\b").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&i.arguments))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF021".into(),
            severity: Severity::Error,
            line: i.line,
            message: "Piping remote script directly to shell (curl/wget | sh)".to_string(),
            roast: "curl | sh: the technical equivalent of 'hold my beer'. You're downloading \
                    code from the internet and executing it blind, inside your container, \
                    and shipping it to prod. Your threat model is vibes."
                .to_string(),
        })
        .collect()
}

fn rule_apt_instead_of_apt_get(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re =
        Regex::new(r"\bapt\s+(install|remove|update|upgrade|list|search|show|purge)\b").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| re.is_match(&i.arguments))
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF059".into(),
            severity: Severity::Warning,
            line: i.line,
            message:
                "apt used instead of apt-get — apt is an end-user tool, not suited for scripts"
                    .to_string(),
            roast: "`apt` is designed for humans: it has progress bars, color output, and a \
                    warning that says 'do not use in scripts'. You are in a script. \
                    Use apt-get or apt-cache instead."
                .to_string(),
        })
        .collect()
}

fn rule_useless_commands(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let useless = [
        "ssh ",
        "vim ",
        "nano ",
        "emacs ",
        "shutdown",
        "reboot",
        "service ",
        "systemctl ",
        "ifconfig ",
        "iwconfig",
        "free ",
        "top ",
        "htop ",
        "mount ",
        "umount ",
    ];
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "RUN") {
        for cmd in &useless {
            if i.arguments.contains(cmd) {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF060".into(),
                    severity: Severity::Info,
                    line: i.line,
                    message: format!(
                        "Command '{}' makes little sense inside a container",
                        cmd.trim()
                    ),
                    roast: format!(
                        "`{}` in a Dockerfile: you're running a command that assumes a full \
                         interactive OS environment inside a container. It doesn't apply here. \
                         Containers are not VMs.",
                        cmd.trim()
                    ),
                });
                break;
            }
        }
    }
    findings
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
            severity: Severity::Warning,
            line: i.line,
            message: "FROM uses --platform flag — consider whether cross-platform targeting is intentional".to_string(),
            roast: "--platform in FROM forces a specific architecture. If you're building for \
                    amd64 but deploying on arm64, your image will be slow or broken. \
                    Make sure this is intentional and documented.".to_string(),
        })
        .collect()
}

fn rule_env_self_reference(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"(\w+)=\s*[\x22\x27]?\$\{?(\w+)\}?").unwrap();
    let mut findings = Vec::new();
    let mut stage_args = std::collections::HashSet::new();
    for i in instrs {
        if i.instruction == "FROM" {
            stage_args.clear();
            continue;
        }
        if i.instruction == "ARG" {
            if let Some(name) = i.arguments.split('=').next().and_then(|arg| arg.split_whitespace().next()) {
                stage_args.insert(name.to_string());
            }
            continue;
        }
        if i.instruction != "ENV" {
            continue;
        }
        for cap in re.captures_iter(&i.arguments) {
            let defined = &cap[1];
            let referenced = &cap[2];
            if defined == referenced && !stage_args.contains(referenced) {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF062".into(),
                    severity: Severity::Error,
                    line: i.line,
                    message: format!(
                        "ENV variable '{}' references itself in the same statement",
                        defined
                    ),
                    roast: format!(
                        "ENV {}=${{{}}} — you're defining a variable using itself. \
                         It hasn't been set yet at this point in the same ENV instruction. \
                         The result will be an empty string. Split it into two ENV statements.",
                        defined, referenced
                    ),
                });
                break;
            }
        }
    }
    findings
}

fn rule_copy_relative_no_workdir(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut stage_workdirs: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    let mut current_alias: Option<String> = None;
    let mut workdir_set = false;
    let mut findings = Vec::new();
    for i in instrs {
        if i.instruction == "FROM" {
            if let Some(from) = parse_from_arguments(&i.arguments) {
                workdir_set = stage_workdirs
                    .get(&from.image.to_lowercase())
                    .copied()
                    .unwrap_or(false);
                current_alias = from.alias.map(str::to_lowercase);
                if let Some(alias) = &current_alias {
                    stage_workdirs.insert(alias.clone(), workdir_set);
                }
            } else {
                workdir_set = false;
                current_alias = None;
            }
        } else if i.instruction == "WORKDIR" {
            workdir_set = true;
            if let Some(alias) = &current_alias {
                stage_workdirs.insert(alias.clone(), true);
            }
        } else if i.instruction == "COPY" {
            let args: Vec<&str> = i
                .arguments
                .split_whitespace()
                .filter(|t| !t.starts_with("--"))
                .collect();
            if let Some(dest) = args.last() {
                if !dest.starts_with('/') && !dest.starts_with('$') && !workdir_set {
                    findings.push(Finding {
                        column: 0,
                        end_line: 0,
                        end_column: 0,
                        rule: "DF063".into(),
                        severity: Severity::Warning,
                        line: i.line,
                        message: format!(
                            "COPY to relative destination '{}' but no WORKDIR has been set",
                            dest
                        ),
                        roast: format!(
                            "COPY to '{}' with no WORKDIR set. Relative destinations depend on \
                             the working directory, which defaults to /. \
                             Set WORKDIR explicitly before using relative paths.",
                            dest
                        ),
                    });
                }
            }
        }
    }
    findings
}

fn rule_useradd_no_l(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let re = Regex::new(r"\buseradd\b").unwrap();
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            re.is_match(&i.arguments)
                && !i.arguments.contains(" -l")
                && !i.arguments.contains("--no-log-init")
        })
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

fn rule_copy_archive_use_add(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    const ARCHIVE_EXTS: &[&str] = &[".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar"];
    instrs_of(instrs, "COPY")
        .into_iter()
        .filter(|i| {
            // Ignore multi-stage COPY --from=... (the source is a container path, not a local file)
            if i.arguments.contains("--from=") || i.arguments.contains("--from =") {
                return false;
            }
            let sources: Vec<&str> = i
                .arguments
                .split_whitespace()
                .filter(|t| !t.starts_with("--"))
                .collect();
            // Need at least one source and one destination
            if sources.len() < 2 {
                return false;
            }
            // Check if any source (all but last) is an archive
            sources[..sources.len() - 1]
                .iter()
                .any(|s| ARCHIVE_EXTS.iter().any(|ext| s.ends_with(ext)))
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF067".into(),
            severity: Severity::Info,
            line: i.line,
            message: "COPY of archive file — consider ADD which auto-extracts local tarballs"
                .to_string(),
            roast: "COPY drops the compressed archive as-is; you'll need a separate \
                    RUN tar -xzf layer to unpack it. ADD auto-extracts local tarballs into \
                    the destination directory and saves you the extra layer. \
                    Yes, this is the one situation where ADD is actually the right choice."
                .to_string(),
        })
        .collect()
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

fn rule_bash_syntax_no_shell(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    // If an explicit SHELL instruction is present, the developer knows what they're doing
    if has_instr(instrs, "SHELL") {
        return vec![];
    }
    // Patterns that are valid bash but not POSIX sh — meaningless or broken on /bin/sh
    const BASH_ONLY: &[(&str, &str)] = &[
        ("[[ ", "double-bracket conditional"),
        ("source ", "source builtin (use '.' in POSIX sh)"),
        ("declare ", "declare builtin"),
        ("mapfile ", "mapfile builtin"),
        ("readarray ", "readarray builtin"),
        ("${!", "indirect variable expansion"),
    ];
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "RUN") {
        for (pattern, label) in BASH_ONLY {
            if i.arguments.contains(pattern) {
                findings.push(Finding {
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    rule: "DF066".into(),
                    severity: Severity::Warning,
                    line: i.line,
                    message: format!(
                        "RUN uses bash-specific syntax ({}) but no SHELL instruction is set",
                        label
                    ),
                    roast: format!(
                        "'{}' is bash syntax. The default shell is /bin/sh, which on Alpine, \
                         Debian-slim, and distroless is NOT bash. Add \
                         `SHELL [\"/bin/bash\", \"-c\"]` before this RUN or your build \
                         will fail in ways that are confusing to debug.",
                        pattern.trim()
                    ),
                });
                break;
            }
        }
    }
    findings
}

fn rule_untrusted_registry(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    const TRUSTED: &[&str] = &[
        "docker.io",
        "registry-1.docker.io",
        "ghcr.io",
        "gcr.io",
        "quay.io",
        "mcr.microsoft.com",
        "registry.access.redhat.com",
        "public.ecr.aws",
        "registry.k8s.io",
        "k8s.gcr.io",
    ];
    let mut findings = Vec::new();
    for i in instrs_of(instrs, "FROM") {
        // Skip --platform=... flags to find the actual image reference
        let image = match i
            .arguments
            .split_whitespace()
            .find(|t| !t.starts_with("--"))
        {
            Some(img) => img,
            None => continue,
        };
        if image.eq_ignore_ascii_case("scratch") {
            continue;
        }
        // The registry is the first path component when it contains a dot or colon,
        // or is the literal "localhost". Plain names like "ubuntu" or "ubuntu:22.04"
        // with no slash imply docker.io — the colon there is the tag separator, not a port.
        if !image.contains('/') {
            continue;
        }
        let first = image
            .split('@')
            .next()
            .unwrap_or(image)
            .split('/')
            .next()
            .unwrap_or("");
        if (first.contains('.') || first.contains(':') || first == "localhost")
            && !TRUSTED.iter().any(|t| first.eq_ignore_ascii_case(t))
        {
            findings.push(Finding {
                column: 0,
                end_line: 0,
                end_column: 0,
                rule: "DF065".into(),
                severity: Severity::Warning,
                line: i.line,
                message: format!("FROM pulls from unrecognised registry '{}'", first),
                roast: format!(
                    "Pulling base images from '{}' — a registry you don't hear about at \
                     KubeCon. Supply-chain attacks love Dockerfiles that blindly trust \
                     random registries. Verify this is intentional and pin to a digest.",
                    first
                ),
            });
        }
    }
    findings
}

fn rule_pipefail_missing(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let mut shell_has_pipefail = false;
    let mut findings = Vec::new();

    for instruction in instrs {
        match instruction.instruction.as_str() {
            "FROM" => shell_has_pipefail = false,
            "SHELL" => {
                shell_has_pipefail = match &instruction.form {
                    InstructionForm::Json(arguments) => {
                        arguments
                            .windows(2)
                            .any(|pair| pair[0] == "-o" && pair[1] == "pipefail")
                            || arguments.iter().any(|argument| argument == "-opipefail")
                    }
                    _ => false,
                };
            }
            "RUN" => {
                let a = &instruction.arguments;
                // has a pipe that isn't curl|sh (that's covered separately) and isn't pipefail already set
                if a.contains(" | ")
                    && !shell_has_pipefail
                    && !a.contains("pipefail")
                    && !a.contains("set -o pipefail")
                    && !a.contains("set -eo pipefail")
                    && !a.contains("set -euo pipefail")
                    // only flag if it's not a trivial pipe to tee/grep/wc for log filtering
                    && !a.trim_start().starts_with("set ")
                {
                    findings.push(Finding {
                        column: 0,
                        end_line: 0,
                        end_column: 0,
                        rule: "DF057".into(),
                        severity: Severity::Warning,
                        line: instruction.line,
                        message: "RUN with pipe but no pipefail — failed commands in the pipe are silently ignored"
                            .to_string(),
                        roast: "A pipe in RUN without `set -o pipefail`. If the left side of that pipe fails, \
                                bash shrugs and moves on. The exit code is whatever the last command returns. \
                                Add `set -o pipefail` at the start of the RUN."
                            .to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    findings
}

fn rule_wget_and_curl(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    let uses_wget = instrs_of(instrs, "RUN")
        .iter()
        .any(|i| i.arguments.contains("wget "));
    let uses_curl = instrs_of(instrs, "RUN")
        .iter()
        .any(|i| i.arguments.contains("curl "));
    if uses_wget && uses_curl {
        return vec![Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF058".into(),
            severity: Severity::Warning,
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
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            (a.contains("yarn install") || a.contains("yarn add"))
                && !a.contains("yarn cache clean")
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

fn rule_wget_no_progress(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            a.contains("wget ")
                && !a.contains("--progress")
                && !a.contains("-q")
                && !a.contains("--quiet")
                && (a.contains("http://") || a.contains("https://") || a.contains("ftp://"))
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF056".into(),
            severity: Severity::Info,
            line: i.line,
            message: "wget without --progress flag produces verbose progress output in build logs"
                .to_string(),
            roast: "wget without --progress=dot:giga will spam your build logs with a progress \
                    bar that looks great locally and fills 50MB of CI log storage. \
                    Use --progress=dot:giga or -q to stay quiet."
                .to_string(),
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
    let Some(install) = command.find("pip install") else {
        return false;
    };
    command[install + "pip install".len()..]
        .split_whitespace()
        .filter(|argument| !argument.starts_with('-'))
        .any(|argument| {
            matches!(argument, "." | "./")
                || argument.starts_with("./")
                || argument.starts_with("../")
                || argument.starts_with("file:")
        })
}

fn rule_apk_version_pinning(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            if !a.contains("apk add") {
                return false;
            }
            // check if any non-flag arg after "add" has no = for version pinning
            let after_add = match a.find("apk add") {
                Some(pos) => &a[pos + 7..],
                None => return false,
            };
            after_add
                .split_whitespace()
                .filter(|t| !t.starts_with('-') && !t.is_empty())
                .any(|t| !t.contains('=') && !t.contains('>') && !t.contains('<'))
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF052".into(),
            severity: Severity::Warning,
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

fn rule_go_install_version(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            i.arguments
                .split(['&', '|', ';'])
                .any(|segment| {
                    let mut words = segment.split_whitespace();

                    // Environment assignments may precede the command, but the
                    // executable itself must be `go`; a substring match would
                    // mistake `cargo install` for `go install`.
                    let executable = loop {
                        match words.next() {
                            Some(word)
                                if word.contains('=')
                                    && !word.starts_with('=')
                                    && !word.contains('/') => continue,
                            word => break word,
                        }
                    };

                    executable == Some("go")
                        && words.next() == Some("install")
                        && !segment.contains('@')
                })
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF054".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "go install without @version — use go install package@version".to_string(),
            roast: "go install without @version. The Go toolchain requires a version suffix \
                    in module-aware mode. Use `go install pkg@v1.2.3` or at minimum `@latest` \
                    if you enjoy living dangerously."
                .to_string(),
        })
        .collect()
}

fn rule_copy_multi_arg_slash(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "COPY")
        .into_iter()
        .filter(|i| {
            let args: Vec<&str> = i
                .arguments
                .split_whitespace()
                .filter(|t| !t.starts_with("--"))
                .collect();
            if args.len() > 2 {
                let dest = args.last().unwrap_or(&"");
                !dest.ends_with('/')
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

fn rule_copy_from_undefined_stage(_instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    // An unresolved non-numeric reference is a valid external image (or a
    // BuildKit named context), so it cannot be diagnosed as an undefined
    // stage. Image allowlists are enforced by DF073 instead.
    Vec::new()
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

fn rule_dnf_clean(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            a.contains("dnf install") && !a.contains("dnf clean all") && !a.contains("dnf clean")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF046".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "dnf clean all missing after dnf install — RPM cache bloats the image"
                .to_string(),
            roast: "dnf install without `dnf clean all` afterwards? You're shipping RPM cache \
                    metadata to production. That's not a feature. Add `&& dnf clean all`."
                .to_string(),
        })
        .collect()
}

fn rule_yum_clean(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    instrs_of(instrs, "RUN")
        .into_iter()
        .filter(|i| {
            let a = &i.arguments;
            a.contains("yum install") && !a.contains("yum clean all") && !a.contains("yum clean")
        })
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF047".into(),
            severity: Severity::Warning,
            line: i.line,
            message: "yum clean all missing after yum install — cache stays in the image"
                .to_string(),
            roast: "yum install without cleanup is just permanently housing the package cache in \
                    your image. Every MB of yum cache is a MB of shame in your registry."
                .to_string(),
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
    let eps: Vec<_> = instrs_of(instrs, "ENTRYPOINT");
    if eps.len() <= 1 {
        return vec![];
    }
    eps[1..]
        .iter()
        .map(|i| Finding {
            column: 0,
            end_line: 0,
            end_column: 0,
            rule: "DF039".into(),
            severity: Severity::Error,
            line: i.line,
            message: "Multiple ENTRYPOINT instructions — only the last one takes effect"
                .to_string(),
            roast: "Two ENTRYPOINTs. Bold. Only the last one runs; the first is just expensive \
                furniture. Delete it."
                .to_string(),
        })
        .collect()
}

fn rule_no_user_instruction(instrs: &[Instruction], _raw: &str) -> Vec<Finding> {
    if has_instr(instrs, "USER") {
        return vec![];
    }
    if !has_instr(instrs, "CMD") && !has_instr(instrs, "ENTRYPOINT") {
        return vec![];
    }
    vec![Finding {
        column: 0,
        end_line: 0,
        end_column: 0,
        rule: "DF020".into(),
        severity: Severity::Warning,
        line: 0,
        message: "No USER instruction found — container will run as root by default".to_string(),
        roast: "No USER set? Bold strategy. Running everything as root in prod is a great way \
                to ensure job security — for your incident response team."
            .to_string(),
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
