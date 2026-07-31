use dockerfile_roast::{config, hadolint, linter, messages, output, repository, rules, shellcheck};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use colored::*;

use config::{DroastConfig, PolicySettings};
use linter::LintOptions;
use output::{print_findings, OutputFormat};
use rules::Severity;

const HELP_BANNER: &str = concat!(
    "\n\n",
    "  ██████╗ ██████╗  ██████╗  █████╗ ███████╗████████╗\n",
    "  ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝\n",
    "  ██║  ██║██████╔╝██║   ██║███████║███████╗   ██║\n",
    "  ██║  ██║██╔══██╗██║   ██║██╔══██║╚════██║   ██║\n",
    "  ██████╔╝██║  ██║╚██████╔╝██║  ██║███████║   ██║\n",
    "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝\n",
    "  Dockerfile linter with personality\n",
);
const HELP_BANNER_STYLE: &str = "\x1b[1;31m";
const RESET_STYLE: &str = "\x1b[0m";

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SeverityArg {
    Error,
    Warning,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Error => Severity::Error,
            SeverityArg::Warning => Severity::Warning,
            SeverityArg::Info => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Terminal,
    Json,
    Github,
    Compact,
    Sarif,
}

impl From<FormatArg> for OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Terminal => OutputFormat::Terminal,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Github => OutputFormat::Github,
            FormatArg::Compact => OutputFormat::Compact,
            FormatArg::Sarif => OutputFormat::Sarif,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ShellArg {
    Bash,
    Fish,
    Zsh,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ShellcheckModeArg {
    Off,
    Auto,
    Required,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EngineArg {
    Docker,
    Podman,
}

impl From<EngineArg> for repository::ContainerEngine {
    fn from(engine: EngineArg) -> Self {
        match engine {
            EngineArg::Docker => Self::Docker,
            EngineArg::Podman => Self::Podman,
        }
    }
}

impl From<ShellcheckModeArg> for shellcheck::Mode {
    fn from(mode: ShellcheckModeArg) -> Self {
        match mode {
            ShellcheckModeArg::Off => Self::Off,
            ShellcheckModeArg::Auto => Self::Auto,
            ShellcheckModeArg::Required => Self::Required,
        }
    }
}

impl From<ShellArg> for Shell {
    fn from(s: ShellArg) -> Self {
        match s {
            ShellArg::Bash => Shell::Bash,
            ShellArg::Fish => Shell::Fish,
            ShellArg::Zsh => Shell::Zsh,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate shell completion scripts
    ///
    /// Usage examples:
    ///
    ///   bash:  source <(droast completion bash)
    ///   zsh:   droast completion zsh > ~/.zfunc/_droast
    ///   fish:  droast completion fish | source
    Completion {
        #[arg(value_enum)]
        shell: ShellArg,
    },

    /// Create a droast.toml config file in the current directory
    ///
    /// Generates a fully-commented template — every setting is present but
    /// disabled so the file has no effect until you uncomment what you need.
    /// Aborts if droast.toml already exists.
    Init {
        /// Import settings from Hadolint YAML; without PATH uses .hadolint.yaml
        #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = ".hadolint.yaml")]
        from_hadolint: Option<PathBuf>,
    },

    /// Customize optional terminal messages for your user account or repository
    Messages {
        #[command(subcommand)]
        command: MessageCommands,
    },
}

#[derive(Subcommand, Debug)]
enum MessageCommands {
    /// Create a small, editable message override file
    Init {
        /// Create .droast/messages.yaml in the current repository
        #[arg(long)]
        project: bool,
        /// Starter content: friendly or onboarding
        #[arg(long, value_name = "NAME")]
        preset: Option<String>,
    },
    /// Show the effective message and help link for one rule
    Show {
        #[arg(value_name = "RULE")]
        rule: String,
    },
    /// Print a complete YAML reference catalog to stdout
    Dump {
        /// Required to avoid accidentally printing a large catalog
        #[arg(long)]
        all: bool,
    },
    /// Validate a message override YAML file
    Validate {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

#[derive(Parser, Debug)]
#[command(
    name = "droast",
    about = "Dockerfile linter with personality",
    long_about = "A Dockerfile linter that catches bad practices and roasts you about them.\n\
                  Think of it as a very opinionated senior engineer doing a code review.\n\n\
                  Project-level defaults can be set in droast.toml (all fields optional):\n\n  \
                  skip = [\"DF012\", \"DF022\"]\n  \
                  min-severity = \"warning\"\n  \
                  no-roast = false\n  \
                  no-fail  = false\n  \
                  format   = \"terminal\"",
    version = env!("DROAST_VERSION"),
    author
)]
struct Cli {
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Load project configuration from this path instead of discovering droast.toml
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Load optional terminal message overrides from this YAML file
    #[arg(long, global = true, value_name = "PATH")]
    messages: Option<PathBuf>,

    /// Apply a built-in preset: minimal, security, performance, production, or strict
    #[arg(long, value_name = "NAME")]
    preset: Option<String>,

    /// Run rules in these categories (comma-separated)
    #[arg(long, value_delimiter = ',', value_name = "CATEGORY")]
    category: Vec<String>,

    /// Skip rules in these categories (comma-separated)
    #[arg(long, value_delimiter = ',', value_name = "CATEGORY")]
    skip_category: Vec<String>,

    /// Output format: terminal, json, github, compact, or sarif
    #[arg(short, long, value_enum)]
    format: Option<FormatArg>,

    /// Minimum severity to report [default: info] [possible values: info, warning, error]
    #[arg(short = 's', long, value_enum)]
    min_severity: Option<SeverityArg>,

    /// Exit unsuccessfully when a finding reaches this severity
    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,

    /// Skip these comma-separated rule IDs
    #[arg(long, value_delimiter = ',', value_name = "RULE")]
    skip: Vec<String>,

    /// Run only these comma-separated rule IDs
    #[arg(long, value_delimiter = ',', value_name = "RULE")]
    only: Vec<String>,

    /// Show technical messages without roast text
    #[arg(long)]
    no_roast: bool,

    /// Check the effective build-context ignore file for every build context
    #[arg(long = "check-ignorefile", alias = "check-dockerignore", default_value_t = true, action = clap::ArgAction::Set)]
    check_dockerignore: bool,

    /// Build-context conventions to use: docker or podman
    #[arg(long, value_enum)]
    engine: Option<EngineArg>,

    /// ShellCheck integration: off, auto, or required
    #[arg(long, value_enum)]
    shellcheck: Option<ShellcheckModeArg>,

    /// Always exit successfully after linting
    #[arg(long)]
    no_fail: bool,

    /// JSON baseline used to distinguish existing findings from new findings
    #[arg(long, value_name = "PATH")]
    baseline: Option<PathBuf>,

    /// Write all current findings to --baseline in the deterministic baseline format
    #[arg(long, requires = "baseline")]
    write_baseline: bool,

    /// Report only findings absent from --baseline
    #[arg(long, requires = "baseline", conflicts_with = "write_baseline")]
    only_new: bool,

    /// List rule IDs, severities, categories, and descriptions
    #[arg(long)]
    list_rules: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

fn main() -> Result<()> {
    let command = cli_command();
    let cli = Cli::from_arg_matches(&mut command.get_matches())?;

    match cli.command {
        Some(Commands::Completion { shell }) => {
            let mut completion_command = cli_command();
            generate(
                Shell::from(shell),
                &mut completion_command,
                "droast",
                &mut io::stdout(),
            );
            return Ok(());
        }
        Some(Commands::Init { from_hadolint }) => {
            return cmd_init(from_hadolint.as_deref());
        }
        Some(Commands::Messages { command }) => return cmd_messages(command, cli.messages.as_deref()),
        None => {}
    }

    if cli.list_rules {
        if matches!(cli.format, Some(FormatArg::Json)) {
            print_rule_list_json();
        } else {
            print_rule_list();
        }
        return Ok(());
    }

    // Load project config (droast.toml), then merge CLI on top.
    // Priority: CLI flag > droast.toml > built-in default.
    let cfg = match &cli.config {
        Some(path) => DroastConfig::load_from(path)?,
        None => DroastConfig::try_load()?,
    };
    let shellcheck_mode = cli
        .shellcheck
        .map(Into::into)
        .unwrap_or(shellcheck::Mode::parse(cfg.shellcheck.mode.as_deref())?);
    let engine = cli
        .engine
        .map(Into::into)
        .unwrap_or(repository::ContainerEngine::parse(cfg.workflow.engine.as_deref())?);

    let mut global_settings = cfg.settings.clone();
    if cli.preset.is_some() {
        global_settings.merge(config::preset_settings(cli.preset.as_deref())?);
    }

    let format: OutputFormat = cli
        .format
        .map(Into::into)
        .or_else(|| parse_format(global_settings.format.as_deref()))
        .unwrap_or(OutputFormat::Terminal);

    // --no-roast on CLI always wins; config can also enable it.
    let no_roast = cli.no_roast || global_settings.no_roast.unwrap_or(false);

    // --no-fail on CLI always wins; config can also enable it.
    let no_fail = cli.no_fail || global_settings.no_fail.unwrap_or(false);
    // Message overrides are deliberately presentation-only. Machine formats
    // remain canonical and never load or render them.
    let message_overrides = if matches!(format, OutputFormat::Terminal | OutputFormat::Compact) {
        messages::MessageOverrides::load(cli.messages.as_deref())?
    } else {
        messages::MessageOverrides::default()
    };
    let baseline = if cli.write_baseline {
        None
    } else if let Some(path) = &cli.baseline {
        Some(dockerfile_roast::baseline::load(path)?)
    } else {
        None
    };

    let discovery = repository::discover(&cli.files, engine);
    for warning in &discovery.warnings {
        eprintln!("{} {}", "!".yellow(), warning);
    }
    let files = discovery.inputs;
    if files.is_empty() {
        eprintln!(
            "{} No Dockerfile(s) found. Pass a path or run in a directory that contains a Dockerfile.",
            "x".red().bold()
        );
        exit(1);
    }

    let mut any_error = false;
    let mut total_findings = 0usize;

    if matches!(format, OutputFormat::Sarif | OutputFormat::Json) {
        // Document formats collect all results and emit exactly one valid document.
        let mut all_results: Vec<linter::LintResult> = Vec::new();
        for file in &files {
            let settings = effective_settings(&cfg, &cli, &file.dockerfile)?;
            let opts = lint_options(&settings, &cli, shellcheck_mode, &cfg.shellcheck.exclude, engine)?;
            let file_no_fail = cli.no_fail || settings.no_fail.unwrap_or(no_fail);
            match lint_one(file, &opts) {
                Ok(mut result) => {
                    let has_blocking_finding = result.findings.iter().any(|finding| {
                        finding.severity >= fail_on_threshold(&settings, &cli)
                            && is_new_finding(baseline.as_ref(), &result.file, finding)
                    });
                    if has_blocking_finding && !file_no_fail {
                        any_error = true;
                    }
                    if cli.only_new {
                        result.findings.retain(|finding| {
                            is_new_finding(baseline.as_ref(), &result.file, finding)
                        });
                    }
                    all_results.push(result);
                }
                Err(e) => {
                    eprintln!("{} {}", "x".red().bold(), e);
                    any_error = true;
                }
            }
        }
        let pairs: Vec<(&str, &[rules::Finding])> = all_results
            .iter()
            .map(|r| (r.file.as_str(), r.findings.as_slice()))
            .collect();
        if cli.write_baseline {
            dockerfile_roast::baseline::write(cli.baseline.as_ref().expect("clap requires --baseline"), &pairs)?;
        }
        if format == OutputFormat::Sarif {
            output::print_sarif(&pairs);
        } else {
            output::print_json_results(&pairs);
        }
    } else {
        for file in &files {
            let settings = effective_settings(&cfg, &cli, &file.dockerfile)?;
            let opts = lint_options(&settings, &cli, shellcheck_mode, &cfg.shellcheck.exclude, engine)?;
            let file_no_roast = cli.no_roast || settings.no_roast.unwrap_or(no_roast);
            let file_no_fail = cli.no_fail || settings.no_fail.unwrap_or(no_fail);
            match lint_one(file, &opts) {
                Ok(mut result) => {
                    let finding_count_before_filtering = result.findings.len();
                    let has_blocking_finding = result.findings.iter().any(|finding| {
                        finding.severity >= fail_on_threshold(&settings, &cli)
                            && is_new_finding(baseline.as_ref(), &result.file, finding)
                    });
                    if has_blocking_finding && !file_no_fail {
                        any_error = true;
                    }
                    if cli.only_new {
                        result.findings.retain(|finding| {
                            is_new_finding(baseline.as_ref(), &result.file, finding)
                        });
                    }
                    total_findings += result.findings.len();
                    if cli.only_new && finding_count_before_filtering > 0 && result.findings.is_empty() && format == OutputFormat::Terminal {
                        output::print_no_new_findings(&result.file);
                    } else {
                        print_findings(&result.file, &result.findings, format, file_no_roast, &message_overrides);
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "x".red().bold(), e);
                    any_error = true;
                }
            }
        }
        if cli.write_baseline {
            // Terminal output is streamed, so lint once more only when writing a
            // baseline is explicitly requested in this output mode.
            let mut baseline_results = Vec::new();
            for file in &files {
                let settings = effective_settings(&cfg, &cli, &file.dockerfile)?;
                let opts = lint_options(&settings, &cli, shellcheck_mode, &cfg.shellcheck.exclude, engine)?;
                let result = lint_one(file, &opts)?;
                baseline_results.push(result);
            }
            let pairs = baseline_results.iter().map(|result| (result.file.as_str(), result.findings.as_slice())).collect::<Vec<_>>();
            dockerfile_roast::baseline::write(cli.baseline.as_ref().expect("clap requires --baseline"), &pairs)?;
        }
        if files.len() > 1 && format == OutputFormat::Terminal {
            println!(
                "  {} Linted {} file(s), {} total finding(s)\n",
                "-".dimmed(),
                files.len(),
                total_findings
            );
        }
    }

    if any_error && !no_fail {
        exit(1);
    }
    Ok(())
}

fn cli_command() -> clap::Command {
    Cli::command()
        .color(clap::ColorChoice::Always)
        .before_long_help(format!("{HELP_BANNER_STYLE}{HELP_BANNER}{RESET_STYLE}"))
}

fn is_new_finding(
    baseline: Option<&std::collections::BTreeSet<String>>,
    file: &str,
    finding: &rules::Finding,
) -> bool {
    !baseline.is_some_and(|known| dockerfile_roast::baseline::contains(known, file, finding))
}

fn effective_settings(
    config: &DroastConfig,
    cli: &Cli,
    path: &std::path::Path,
) -> anyhow::Result<PolicySettings> {
    let mut settings = config.effective_for(path)?;
    if cli.preset.is_some() {
        settings.merge(config::preset_settings(cli.preset.as_deref())?);
    }
    if !cli.category.is_empty() {
        settings.categories = Some(cli.category.clone());
    }
    if !cli.skip_category.is_empty() {
        let mut categories = settings.skip_categories.take().unwrap_or_default();
        for category in &cli.skip_category {
            if !categories
                .iter()
                .any(|current| current.eq_ignore_ascii_case(category))
            {
                categories.push(category.clone());
            }
        }
        settings.skip_categories = Some(categories);
    }
    settings.validate("effective CLI configuration")?;
    Ok(settings)
}

fn lint_options(
    settings: &PolicySettings,
    cli: &Cli,
    shellcheck_mode: shellcheck::Mode,
    shellcheck_exclude: &[String],
    engine: repository::ContainerEngine,
) -> anyhow::Result<LintOptions> {
    let known_rules = rules::all_rules()
        .into_iter()
        .map(|rule| rule.id)
        .collect::<std::collections::HashSet<_>>();
    for rule in cli.skip.iter().chain(&cli.only) {
        let normalized = rule.to_ascii_uppercase();
        if !known_rules.contains(normalized.as_str()) {
            anyhow::bail!("Unknown rule ID '{}' on the command line", rule);
        }
    }
    let mut skip = settings.skip.clone().unwrap_or_default();
    for rule in &cli.skip {
        if !skip
            .iter()
            .any(|current| current.eq_ignore_ascii_case(rule))
        {
            skip.push(rule.to_ascii_uppercase());
        }
    }
    let severity_overrides = settings
        .severity_overrides
        .iter()
        .map(|(rule, severity)| {
            parse_severity(Some(severity))
                .map(|severity| (rule.to_ascii_uppercase(), severity))
                .ok_or_else(|| anyhow::anyhow!("Invalid severity override for {rule}"))
        })
        .collect::<anyhow::Result<std::collections::BTreeMap<_, _>>>()?;

    Ok(LintOptions {
        skip_rules: skip,
        only_rules: cli
            .only
            .iter()
            .map(|rule| rule.to_ascii_uppercase())
            .collect(),
        min_severity: cli
            .min_severity
            .map(Into::into)
            .or_else(|| parse_severity(settings.min_severity.as_deref()))
            .unwrap_or(Severity::Info),
        check_dockerignore: cli.check_dockerignore,
        engine,
        severity_overrides,
        categories: settings.categories.clone().unwrap_or_default(),
        skip_categories: settings.skip_categories.clone().unwrap_or_default(),
        inline_suppressions: settings.inline_suppressions.unwrap_or(true),
        require_suppression_reason: settings.require_suppression_reason.unwrap_or(false),
        suppression_reason_pattern: settings.suppression_reason_pattern.clone(),
        require_suppression_expiration: settings.require_suppression_expiration.unwrap_or(false),
        max_suppression_days: settings.max_suppression_days,
        report_unused_suppressions: settings.report_unused_suppressions.unwrap_or(false),
        approved_registries: settings.approved_registries.clone(),
        approved_base_images: settings.approved_base_images.clone(),
        required_labels: settings.required_labels.clone(),
        strict_labels: settings.strict_labels.unwrap_or(false),
        shellcheck_mode,
        shellcheck_exclude: shellcheck_exclude
            .iter()
            .map(|code| code.to_ascii_uppercase())
            .collect(),
    })
}

fn cmd_init(from_hadolint: Option<&std::path::Path>) -> Result<()> {
    let path = std::path::Path::new("droast.toml");
    if path.exists() {
        eprintln!(
            "{} droast.toml already exists. Remove it first if you want a fresh template.",
            "x".red().bold()
        );
        exit(1);
    }
    if let Some(source) = from_hadolint {
        let imported = hadolint::import_config(source)?;
        std::fs::write(path, imported.config)?;
        println!(
            "{} Created droast.toml from {}",
            "✓".green().bold(),
            source.display()
        );
        println!(
            "  Imported {} Hadolint rule alias(es).",
            imported.imported_rules
        );
        if !imported.unmapped_rules.is_empty() {
            eprintln!(
                "! No droast alias for Hadolint rule(s): {}",
                imported.unmapped_rules.join(", ")
            );
        }
        if !imported.unmapped_settings.is_empty() {
            eprintln!(
                "! No equivalent droast setting for: {}",
                imported.unmapped_settings.join(", ")
            );
        }
    } else {
        std::fs::write(path, CONFIG_TEMPLATE)?;
        println!("{} Created droast.toml", "✓".green().bold());
        println!("  All settings are commented out — uncomment what you need.");
    }
    Ok(())
}

fn cmd_messages(command: MessageCommands, explicit: Option<&std::path::Path>) -> Result<()> {
    match command {
        MessageCommands::Init { project, preset } => {
            let path = if project {
                messages::project_init_path()?
            } else {
                messages::user_messages_path()
            };
            if path.exists() {
                anyhow::bail!(
                    "{} already exists. Edit it, or choose a different location with --messages.",
                    path.display()
                );
            }
            let template = messages::template(preset.as_deref())?;
            let parent = path.parent().expect("message path has a parent");
            std::fs::create_dir_all(parent)?;
            std::fs::write(&path, template)?;
            println!("{} Created {}", "✓".green().bold(), path.display());
            println!("  Edit it, then run droast again. Changes apply on every invocation.");
        }
        MessageCommands::Show { rule } => {
            let id = rule.to_ascii_uppercase();
            let rule = rules::all_rules()
                .into_iter()
                .find(|candidate| candidate.id == id)
                .ok_or_else(|| anyhow::anyhow!("Unknown rule ID '{}'", rule))?;
            let overrides = messages::MessageOverrides::load(explicit)?;
            println!("{} {} — {}", rule.id.bold(), rule.severity, rule.description);
            println!("Mode: {}", overrides.mode);
            if let Some(custom) = overrides.get(rule.id) {
                println!("Message: {}", custom.message);
                if let Some(help) = &custom.help {
                    println!("Help: {help}");
                }
            } else {
                println!("No custom message is active for {}.", rule.id);
            }
        }
        MessageCommands::Dump { all } => {
            if !all {
                anyhow::bail!("Use `droast messages dump --all` to print the reference catalog.");
            }
            print!("{}", messages::reference_yaml());
        }
        MessageCommands::Validate { path } => {
            let overrides = messages::MessageOverrides::load_file(&path)?;
            println!(
                "{} {} is valid ({} rule override(s), {} mode).",
                "✓".green().bold(),
                path.display(),
                overrides.rules.len(),
                overrides.mode
            );
        }
    }
    Ok(())
}

const CONFIG_TEMPLATE: &str = r#"# droast.toml - optional project and organization policy
# https://github.com/immanuwell/dockerfile-roast
#
# All settings are optional and commented out by default.
# This file has no effect until you uncomment a line.
# CLI flags always take precedence over values set here.

# Inherit one or more local policy files. Relative paths start here.
# extends = [".config/company-droast.toml"]

# Built-in presets: minimal | security | performance | production | strict
# Explicit settings below override preset defaults.
# preset = "production"

# Rules and severity
# skip = ["DF012", "DF022"]
# min-severity = "info"
# fail-on = "error" # info | warning | error
# categories = ["security", "supply-chain"]
# skip-categories = ["maintainability"]

# Optional ShellCheck bridge. `auto` runs an installed `shellcheck` when it is
# available; `required` turns a missing or failed executable into SC0000.
# [shellcheck]
# mode = "auto" # off | auto | required
# exclude = ["SC2086"]

# Build-context conventions. Podman mode prefers .containerignore over
# .dockerignore and enables Quadlet and kube-play Containerfile discovery.
# [workflow]
# engine = "podman" # docker (default) | podman

# Governed inline suppressions
# Syntax:
#   # droast ignore=DF001 reason="migration" expires=2026-09-30
#   # droast global ignore=DF020 reason="runtime user" expires=2026-09-30
# inline-suppressions = true
# require-suppression-reason = false
# suppression-reason-pattern = "^(SEC|PLAT)-[0-9]+ .+$"
# require-suppression-expiration = false
# max-suppression-days = 90
# report-unused-suppressions = false

# Supply-chain allowlists support glob patterns.
# approved-registries = ["docker.io", "ghcr.io", "registry.example.com"]
# extend-approved-registries = ["mirror.example.com"]
# approved-base-images = ["alpine:3.*", "ghcr.io/example/runtime@sha256:*"]
# extend-approved-base-images = ["ghcr.io/example/extra-runtime@sha256:*"]

# Output and behavior
# format = "terminal"
# no-roast = false
# no-fail = false

# Image label schema
# strict-labels = false
#
# [severity-overrides]
# DF013 = "error"
# DF033 = "warning"
#
# [required-labels]
# "org.opencontainers.image.source" = "url"
# "org.opencontainers.image.version" = "semver"
# "org.opencontainers.image.revision" = "hash"
# "org.opencontainers.image.licenses" = "spdx"

# Path-specific policy. Matching blocks are applied in order.
# [[overrides]]
# paths = ["services/**/Dockerfile", "services/**/*.Dockerfile"]
# preset = "strict"
# skip = ["DF012"]
#
# [overrides.severity-overrides]
# DF020 = "error"
"#;

fn parse_format(s: Option<&str>) -> Option<OutputFormat> {
    match s? {
        "terminal" => Some(OutputFormat::Terminal),
        "json" => Some(OutputFormat::Json),
        "github" => Some(OutputFormat::Github),
        "compact" => Some(OutputFormat::Compact),
        "sarif" => Some(OutputFormat::Sarif),
        other => {
            eprintln!(
                "{} droast.toml: unknown format {:?}, ignoring",
                "!".yellow(),
                other
            );
            None
        }
    }
}

fn parse_severity(s: Option<&str>) -> Option<Severity> {
    match s? {
        "info" => Some(Severity::Info),
        "warning" => Some(Severity::Warning),
        "error" => Some(Severity::Error),
        other => {
            eprintln!(
                "{} droast.toml: unknown min-severity {:?}, ignoring",
                "!".yellow(),
                other
            );
            None
        }
    }
}

fn fail_on_threshold(settings: &PolicySettings, cli: &Cli) -> Severity {
    cli.fail_on
        .map(Into::into)
        .or_else(|| parse_severity(settings.fail_on.as_deref()))
        .unwrap_or(Severity::Error)
}

/// Flush stdout+stderr then exit.
/// `process::exit()` is a hard exit that skips destructors — including the
/// `BufWriter` that wraps stdout — so any buffered output (e.g. JSON) would
/// be silently discarded without this flush.
fn exit(code: i32) -> ! {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    process::exit(code);
}

/// Lint a single file path or `-` (stdin).
fn lint_one(
    input: &repository::BuildInput,
    opts: &linter::LintOptions,
) -> anyhow::Result<linter::LintResult> {
    if input.dockerfile == std::path::Path::new("-") {
        let mut content = String::new();
        std::io::stdin()
            .read_to_string(&mut content)
            .map_err(|e| anyhow::anyhow!("Failed to read stdin: {e}"))?;
        Ok(linter::lint_content(&content, "<stdin>", opts))
    } else {
        linter::lint_file_with_context(&input.dockerfile, &input.context, opts)
    }
}

fn print_rule_list() {
    println!("\n  {}\n", "Available Rules".bold().underline());
    println!(
        "  {:<8} {:<8} {:<34} {}",
        "ID".bold(),
        "SEVERITY".bold(),
        "CATEGORIES".bold(),
        "DESCRIPTION".bold()
    );
    println!("  {}", "─".repeat(118));
    for rule in rules::all_rules() {
        let sev = match rule.severity {
            rules::Severity::Error => "ERROR".red().bold(),
            rules::Severity::Warning => "WARN ".yellow().bold(),
            rules::Severity::Info => "INFO ".cyan(),
        };
        println!(
            "  {:<8} {} {:<34} {}",
            rule.id.cyan(),
            sev,
            rule.categories().join(","),
            rule.description
        );
    }
    println!();
    println!("  Use --skip DF001,DF002 to suppress specific rules.");
    println!("  Use --only DF001,DF002 to run only specific rules.");
    println!("  Use --min-severity warning to hide INFO findings.\n");
}

fn print_rule_list_json() {
    let rules: Vec<_> = rules::all_rules()
        .into_iter()
        .map(|rule| {
            serde_json::json!({
                "id": rule.id,
                "severity": rule.severity.to_string(),
                "description": rule.description,
                "categories": rule.categories(),
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&rules).expect("rule metadata is serializable")
    );
}
