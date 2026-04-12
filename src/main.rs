mod linter;
mod output;
mod parser;
mod rules;

use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{Parser, ValueEnum};
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

#[derive(Parser, Debug)]
#[command(
    name = "roast",
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let format: OutputFormat = cli.format.into();

    if format == OutputFormat::Terminal {
        print_summary_header();
    }

    let files = resolve_files(&cli.files);
    if files.is_empty() {
        eprintln!(
            "{} No Dockerfile(s) found.",
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
        } else {
            result.push(p.clone());
        }
    }
    result
}
