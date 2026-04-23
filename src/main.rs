use dockerfile_roast::{config, linter, output, rules};

use std::io;
use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use colored::*;

use config::DroastConfig;
use linter::LintOptions;
use output::{print_findings, print_summary_header, OutputFormat};
use rules::Severity;

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
}

impl From<FormatArg> for OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Terminal => OutputFormat::Terminal,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Github => OutputFormat::Github,
            FormatArg::Compact => OutputFormat::Compact,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ShellArg {
    Bash,
    Fish,
    Zsh,
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
    version,
    author
)]
struct Cli {
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Output format [default: terminal] [possible values: terminal, json, github, compact]
    #[arg(short, long, value_enum)]
    format: Option<FormatArg>,

    /// Minimum severity to report [default: info] [possible values: info, warning, error]
    #[arg(short = 's', long, value_enum)]
    min_severity: Option<SeverityArg>,

    #[arg(long, value_delimiter = ',', value_name = "RULE")]
    skip: Vec<String>,

    #[arg(long)]
    no_roast: bool,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    check_dockerignore: bool,

    #[arg(long)]
    no_fail: bool,

    #[arg(long)]
    list_rules: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(Commands::Completion { shell }) = cli.command {
        generate(Shell::from(shell), &mut Cli::command(), "droast", &mut io::stdout());
        return Ok(());
    }

    if cli.list_rules {
        print_rule_list();
        return Ok(());
    }

    // Load project config (droast.toml), then merge CLI on top.
    // Priority: CLI flag > droast.toml > built-in default.
    let cfg = DroastConfig::load();

    let format: OutputFormat = cli.format
        .map(Into::into)
        .or_else(|| parse_format(cfg.format.as_deref()))
        .unwrap_or(OutputFormat::Terminal);

    let min_severity: Severity = cli.min_severity
        .map(Into::into)
        .or_else(|| parse_severity(cfg.min_severity.as_deref()))
        .unwrap_or(Severity::Info);

    // --no-roast on CLI always wins; config can also enable it.
    let no_roast = cli.no_roast || cfg.no_roast.unwrap_or(false);

    // --no-fail on CLI always wins; config can also enable it.
    let no_fail = cli.no_fail || cfg.no_fail.unwrap_or(false);

    // skip: union of CLI and config (config = baseline, CLI = additions).
    let mut skip = cli.skip.clone();
    if let Some(config_skip) = &cfg.skip {
        for rule in config_skip {
            let normalized = rule.to_uppercase();
            if !skip.iter().any(|s| s.eq_ignore_ascii_case(&normalized)) {
                skip.push(normalized);
            }
        }
    }

    if format == OutputFormat::Terminal {
        print_summary_header();
    }

    let files = resolve_files(&cli.files);
    if files.is_empty() {
        eprintln!(
            "{} No Dockerfile(s) found. Pass a path or run in a directory that contains a Dockerfile.",
            "x".red().bold()
        );
        process::exit(1);
    }

    let opts = LintOptions {
        skip_rules: skip,
        min_severity,
        check_dockerignore: cli.check_dockerignore,
    };

    let mut any_error = false;
    let mut total_findings = 0usize;

    for file in &files {
        match linter::lint_file(file, &opts) {
            Ok(result) => {
                total_findings += result.findings.len();
                if linter::has_errors(&result.findings) { any_error = true; }
                print_findings(&result.file, &result.findings, format, no_roast);
            }
            Err(e) => {
                eprintln!("{} {}", "x".red().bold(), e);
                any_error = true;
            }
        }
    }

    if files.len() > 1 && format == OutputFormat::Terminal {
        println!(
            "  {} Linted {} file(s), {} total finding(s)\n",
            "-".dimmed(), files.len(), total_findings
        );
    }

    if any_error && !no_fail { process::exit(1); }
    Ok(())
}

fn parse_format(s: Option<&str>) -> Option<OutputFormat> {
    match s? {
        "terminal" => Some(OutputFormat::Terminal),
        "json"     => Some(OutputFormat::Json),
        "github"   => Some(OutputFormat::Github),
        "compact"  => Some(OutputFormat::Compact),
        other => {
            eprintln!("{} droast.toml: unknown format {:?}, ignoring", "!".yellow(), other);
            None
        }
    }
}

fn parse_severity(s: Option<&str>) -> Option<Severity> {
    match s? {
        "info"    => Some(Severity::Info),
        "warning" => Some(Severity::Warning),
        "error"   => Some(Severity::Error),
        other => {
            eprintln!("{} droast.toml: unknown min-severity {:?}, ignoring", "!".yellow(), other);
            None
        }
    }
}

fn print_rule_list() {
    println!("\n  {}\n", "Available Rules".bold().underline());
    println!("  {:<8} {}", "ID".bold(), "DESCRIPTION".bold());
    println!("  {}", "─".repeat(70));
    for rule in rules::all_rules() {
        println!("  {:<8} {}", rule.id.cyan(), rule.description);
    }
    println!();
    println!("  Use --skip DF001,DF002 to suppress specific rules.");
    println!("  Use --min-severity warning to hide INFO findings.\n");
}

fn resolve_files(input: &[PathBuf]) -> Vec<PathBuf> {
    if input.is_empty() {
        let default = PathBuf::from("Dockerfile");
        if default.exists() { return vec![default]; }
        return vec![];
    }
    let mut result = Vec::new();
    for p in input {
        let s = p.to_string_lossy();
        if s.contains('*') || s.contains('?') || s.contains('[') {
            if let Ok(paths) = glob::glob(&s) {
                for entry in paths.flatten() {
                    if entry.is_file() { result.push(entry); }
                }
            }
        } else if p.is_dir() {
            let candidate = p.join("Dockerfile");
            if candidate.exists() { result.push(candidate); }
            else {
                eprintln!("{} No Dockerfile found in directory '{}'", "!".yellow(), p.display());
            }
        } else {
            result.push(p.clone());
        }
    }
    result
}
