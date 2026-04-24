use dockerfile_roast::{config, linter, output, rules};
use std::io::{self, Read, Write};
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
    Init,
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

    match cli.command {
        Some(Commands::Completion { shell }) => {
            generate(Shell::from(shell), &mut Cli::command(), "droast", &mut io::stdout());
            return Ok(());
        }
        Some(Commands::Init) => {
            return cmd_init();
        }
        None => {}
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

    // SARIF suppresses the ASCII banner — it writes pure JSON to stdout.
    if format == OutputFormat::Terminal {
        print_summary_header();
    }

    let files = resolve_files(&cli.files);
    if files.is_empty() {
        eprintln!(
            "{} No Dockerfile(s) found. Pass a path or run in a directory that contains a Dockerfile.",
            "x".red().bold()
        );
        exit(1);
    }

    let opts = LintOptions {
        skip_rules: skip,
        min_severity,
        check_dockerignore: cli.check_dockerignore,
    };

    let mut any_error = false;
    let mut total_findings = 0usize;

    if format == OutputFormat::Sarif {
        // SARIF is a document format: collect all results, emit once.
        let mut all_results: Vec<linter::LintResult> = Vec::new();
        for file in &files {
            match lint_one(file, &opts) {
                Ok(result) => {
                    if linter::has_errors(&result.findings) { any_error = true; }
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
        output::print_sarif(&pairs);
    } else {
        for file in &files {
            match lint_one(file, &opts) {
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
    }

    if any_error && !no_fail { exit(1); }
    Ok(())
}

fn cmd_init() -> Result<()> {
    let path = std::path::Path::new("droast.toml");
    if path.exists() {
        eprintln!(
            "{} droast.toml already exists. Remove it first if you want a fresh template.",
            "x".red().bold()
        );
        exit(1);
    }
    std::fs::write(path, CONFIG_TEMPLATE)?;
    println!("{} Created droast.toml", "✓".green().bold());
    println!("  All settings are commented out — uncomment what you need.");
    Ok(())
}

const CONFIG_TEMPLATE: &str = r#"# droast.toml — project-level configuration
# https://github.com/immanuwell/dockerfile-roast
#
# All settings are optional and commented out by default.
# This file has no effect until you uncomment a line.
# CLI flags always take precedence over values set here.
#
# droast searches for this file starting from the current directory,
# walking up to the nearest .git root.

# ── rules ────────────────────────────────────────────────────────────────────

# Suppress specific rules project-wide. Useful for rules your team has
# consciously accepted (e.g. no HEALTHCHECK by design, no EXPOSE needed).
# Run `droast --list-rules` for the full list of rule IDs.
#
# skip = ["DF012", "DF022"]

# ── severity ─────────────────────────────────────────────────────────────────

# Minimum severity level to report.
# Values: "info" (default) | "warning" | "error"
# "warning" is a good default for CI — suppresses style hints, keeps real issues.
#
# min-severity = "info"

# ── output ───────────────────────────────────────────────────────────────────

# Output format.
# Values: "terminal" (default) | "github" | "json" | "compact"
# Use "github" in GitHub Actions to get inline PR annotations.
# Use "json" to pipe findings into other tools.
#
# format = "terminal"

# ── behaviour ────────────────────────────────────────────────────────────────

# Suppress roast messages — print technical descriptions only.
# Useful if your team finds the humour distracting (they're wrong, but ok).
#
# no-roast = false

# Advisory mode: never exit with code 1, even when errors are found.
# Findings are still printed; the build is never blocked.
# Handy while rolling droast out across a large codebase.
#
# no-fail = false
"#;

fn parse_format(s: Option<&str>) -> Option<OutputFormat> {
    match s? {
        "terminal" => Some(OutputFormat::Terminal),
        "json"     => Some(OutputFormat::Json),
        "github"   => Some(OutputFormat::Github),
        "compact"  => Some(OutputFormat::Compact),
        "sarif"    => Some(OutputFormat::Sarif),
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
fn lint_one(path: &std::path::Path, opts: &linter::LintOptions) -> anyhow::Result<linter::LintResult> {
    if path == std::path::Path::new("-") {
        let mut content = String::new();
        std::io::stdin().read_to_string(&mut content)
            .map_err(|e| anyhow::anyhow!("Failed to read stdin: {e}"))?;
        Ok(linter::lint_content(&content, "<stdin>", opts))
    } else {
        linter::lint_file(path, opts)
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
