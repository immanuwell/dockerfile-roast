use dockerfile_roast::{linter, output, rules};

use std::io;
use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use colored::*;

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
                  Think of it as a very opinionated senior engineer doing a code review.",
    version,
    author
)]
struct Cli {
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    #[arg(short, long, value_enum, default_value = "terminal")]
    format: FormatArg,

    #[arg(short = 's', long, value_enum, default_value = "info")]
    min_severity: SeverityArg,

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

    let format: OutputFormat = cli.format.into();

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
        skip_rules: cli.skip.clone(),
        min_severity: cli.min_severity.into(),
        check_dockerignore: cli.check_dockerignore,
    };

    let mut any_error = false;
    let mut total_findings = 0usize;

    for file in &files {
        match linter::lint_file(file, &opts) {
            Ok(result) => {
                total_findings += result.findings.len();
                if linter::has_errors(&result.findings) { any_error = true; }
                print_findings(&result.file, &result.findings, format, cli.no_roast);
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

    if any_error && !cli.no_fail { process::exit(1); }
    Ok(())
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
