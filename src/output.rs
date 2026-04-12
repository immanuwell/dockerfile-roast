use crate::rules::{Finding, Severity};
use colored::*;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Github,
    Compact,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "tty" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            "github" | "gh" => Ok(OutputFormat::Github),
            "compact" => Ok(OutputFormat::Compact),
            other => Err(format!("unknown format '{}'", other)),
        }
    }
}

#[derive(Serialize)]
struct JsonFinding {
    rule: String,
    severity: String,
    line: usize,
    message: String,
    roast: String,
}

#[derive(Serialize)]
struct JsonOutput {
    file: String,
    total: usize,
    errors: usize,
    warnings: usize,
    infos: usize,
    findings: Vec<JsonFinding>,
}

pub fn print_findings(file: &str, findings: &[Finding], format: OutputFormat, no_roast: bool) {
    match format {
        OutputFormat::Terminal => print_terminal(file, findings, no_roast),
        OutputFormat::Json => print_json(file, findings),
        OutputFormat::Github => print_github(file, findings),
        OutputFormat::Compact => print_compact(file, findings),
    }
}

fn severity_color(s: &Severity) -> ColoredString {
    match s {
        Severity::Error => "ERROR".red().bold(),
        Severity::Warning => "WARN ".yellow().bold(),
        Severity::Info => "INFO ".cyan(),
    }
}

fn print_terminal(file: &str, findings: &[Finding], no_roast: bool) {
    if findings.is_empty() {
        println!(
            "\n  {} {}\n",
            "✓".green().bold(),
            format!("{} passed with no issues. Impressive restraint.", file).green()
        );
        return;
    }

    println!("\n  {} {}\n", "🔥".bold(), format!("Roasting {}...", file).bold());

    for f in findings {
        let line_info = if f.line > 0 {
            format!("{}:{}", file, f.line).dimmed().to_string()
        } else {
            file.dimmed().to_string()
        };

        println!(
            "  {} [{}]  {}",
            severity_color(&f.severity),
            f.rule.dimmed(),
            f.message.bold()
        );
        println!("  {}      at {}", " ".repeat(5), line_info);
        if !no_roast {
            println!(
                "  {}      {} {}\n",
                " ".repeat(5),
                "💬".dimmed(),
                format!("\"{}\"", f.roast).italic().dimmed()
            );
        } else {
            println!();
        }
    }

    let errors = findings.iter().filter(|f| f.severity == Severity::Error).count();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let infos = findings.iter().filter(|f| f.severity == Severity::Info).count();

    println!(
        "  {} {} error(s), {} warning(s), {} info(s)",
        "Summary:".bold(),
        errors.to_string().red().bold(),
        warnings.to_string().yellow().bold(),
        infos.to_string().cyan()
    );

    if errors > 0 {
        println!("\n  {} This Dockerfile is a liability. Fix the errors.", "💀".bold());
    } else if warnings > 0 {
        println!("\n  {} Could be worse. Could also be much better.", "🤔".bold());
    } else {
        println!("\n  {} Only informational findings. You're almost competent.", "📝".bold());
    }
    println!();
}

fn print_json(file: &str, findings: &[Finding]) {
    let errors = findings.iter().filter(|f| f.severity == Severity::Error).count();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    let infos = findings.iter().filter(|f| f.severity == Severity::Info).count();
    let out = JsonOutput {
        file: file.to_string(),
        total: findings.len(),
        errors,
        warnings,
        infos,
        findings: findings.iter().map(|f| JsonFinding {
            rule: f.rule.to_string(),
            severity: f.severity.to_string(),
            line: f.line,
            message: f.message.clone(),
            roast: f.roast.clone(),
        }).collect(),
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn print_github(file: &str, findings: &[Finding]) {
    for f in findings {
        let level = match f.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "notice",
        };
        let line_part = if f.line > 0 { format!(",line={}", f.line) } else { String::new() };
        println!(
            "::{} file={}{},title=[{}] {}::{}",
            level, file, line_part, f.rule, f.message, f.roast
        );
    }
}

fn print_compact(file: &str, findings: &[Finding]) {
    for f in findings {
        let line_info = if f.line > 0 { format!(":{}", f.line) } else { String::new() };
        println!("{}{}:{} [{}] {}", file, line_info, f.severity, f.rule, f.message);
    }
}

pub fn print_summary_header() {
    println!(
        "\n{}",
        r#"
  ██████╗ ██████╗  ██████╗  █████╗ ███████╗████████╗
  ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝
  ██║  ██║██████╔╝██║   ██║███████║███████╗   ██║
  ██║  ██║██╔══██╗██║   ██║██╔══██║╚════██║   ██║
  ██████╔╝██║  ██║╚██████╔╝██║  ██║███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝
  Dockerfile linter with personality
"#
        .bold()
        .red()
    );
}
