/// Integration tests verifying each lint rule fires (or doesn't) correctly.

use dockerfile_roast::parser;
use dockerfile_roast::rules::{all_rules, Finding};

fn lint(dockerfile: &str) -> Vec<Finding> {
    let instrs = parser::parse(dockerfile);
    let mut findings = Vec::new();
    for rule in all_rules() {
        findings.extend((rule.func)(&instrs, dockerfile));
    }
    findings
}

fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule == rule_id)
}

fn no_rule(findings: &[Finding], rule_id: &str) -> bool {
    !has_rule(findings, rule_id)
}

// ─── DF001: latest tag ───────────────────────────────────────────────────────

#[test]
fn df001_fires_on_latest() {
    let df = "FROM ubuntu:latest\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF001"));
}

#[test]
fn df001_fires_on_no_tag() {
    let df = "FROM ubuntu\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF001"));
}

#[test]
fn df001_clear_on_pinned_tag() {
    let df = "FROM ubuntu:22.04\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF001"));
}

#[test]
fn df001_clear_on_digest() {
    let df = "FROM ubuntu@sha256:abc123def456\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF001"));
}

#[test]
fn df001_clear_on_scratch() {
    let df = "FROM scratch\nCOPY binary /binary\nENTRYPOINT [\"/binary\"]\n";
    assert!(no_rule(&lint(df), "DF001"));
}

// ─── DF002: explicit root ────────────────────────────────────────────────────

#[test]
fn df002_fires_on_user_root() {
    let df = "FROM alpine:3.19\nUSER root\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF002"));
}

#[test]
fn df002_fires_on_user_zero() {
    let df = "FROM alpine:3.19\nUSER 0\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF002"));
}

#[test]
fn df002_clear_on_non_root_user() {
    let df = "FROM alpine:3.19\nUSER appuser\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF002"));
}

// ─── DF003: many RUN layers ──────────────────────────────────────────────────

#[test]
fn df003_fires_on_many_runs() {
    let df = "FROM alpine:3.19\nRUN a\nRUN b\nRUN c\nRUN d\nRUN e\n";
    assert!(has_rule(&lint(df), "DF003"));
}

#[test]
fn df003_clear_on_few_runs() {
    let df = "FROM alpine:3.19\nRUN a\nRUN b\n";
    assert!(no_rule(&lint(df), "DF003"));
}

// ─── DF004: uncleaned apt cache ──────────────────────────────────────────────

#[test]
fn df004_fires_when_no_cleanup() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF004"));
}

#[test]
fn df004_clear_when_cleanup_present() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF004"));
}

// ─── DF006: ADD instead of COPY ─────────────────────────────────────────────
#[test]
fn df006_fires_on_local_add() {
    let df = "FROM alpine:3.19\nADD ./config /app/config\n";
    assert!(has_rule(&lint(df), "DF006"));
}

#[test]
fn df006_clear_on_local_archive_extraction() {
    let df = "FROM alpine:3.19\nADD ND_rejected_me0102.tgz /\n";
    assert!(no_rule(&lint(df), "DF006"));
}

#[test]
fn df006_clear_on_different_archive_formats() {
    let df = "FROM alpine:3.19\nADD bundle.tar.gz /app/\nADD data.tar.xz /data/\n";
    assert!(no_rule(&lint(df), "DF006"));
}

#[test]
fn df006_fires_on_local_file_to_root() {
    let df = "FROM alpine:3.19\nADD id_rsa.pub /\n";
    assert!(has_rule(&lint(df), "DF006"));
}

#[test]
fn df006_clear_on_remote_add() {
    // ADD with a URL is legitimate
    let df = "FROM alpine:3.19\nADD https://example.com/file.tar.gz /tmp/\n";
    assert!(no_rule(&lint(df), "DF006"));
}

// ─── DF007: COPY . ───────────────────────────────────────────────────────────

#[test]
fn df007_fires_on_copy_dot() {
    let df = "FROM alpine:3.19\nCOPY . .\n";
    assert!(has_rule(&lint(df), "DF007"));
}

#[test]
fn df007_clear_on_specific_copy() {
    let df = "FROM alpine:3.19\nCOPY src/ /app/src/\n";
    assert!(no_rule(&lint(df), "DF007"));
}

// ─── DF009: relative WORKDIR ─────────────────────────────────────────────────

#[test]
fn df009_fires_on_relative_workdir() {
    let df = "FROM alpine:3.19\nWORKDIR app\n";
    assert!(has_rule(&lint(df), "DF009"));
}

#[test]
fn df009_clear_on_absolute_workdir() {
    let df = "FROM alpine:3.19\nWORKDIR /app\n";
    assert!(no_rule(&lint(df), "DF009"));
}

// ─── DF013: secrets in ENV ───────────────────────────────────────────────────

#[test]
fn df013_fires_on_secret_env() {
    let df = "FROM alpine:3.19\nENV DATABASE_PASSWORD=secret\n";
    assert!(has_rule(&lint(df), "DF013"));
}

#[test]
fn df013_clear_on_normal_env() {
    let df = "FROM alpine:3.19\nENV APP_PORT=8080\n";
    assert!(no_rule(&lint(df), "DF013"));
}

// ─── DF015: apt without -y ───────────────────────────────────────────────────

#[test]
fn df015_fires_without_y() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install curl\n";
    assert!(has_rule(&lint(df), "DF015"));
}

#[test]
fn df015_clear_with_y() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n";
    assert!(no_rule(&lint(df), "DF015"));
}

// ─── DF018: shell form ENTRYPOINT ────────────────────────────────────────────

#[test]
fn df018_fires_on_shell_form() {
    let df = "FROM alpine:3.19\nENTRYPOINT /app/server\n";
    assert!(has_rule(&lint(df), "DF018"));
}

#[test]
fn df018_clear_on_exec_form() {
    let df = "FROM alpine:3.19\nENTRYPOINT [\"/app/server\"]\n";
    assert!(no_rule(&lint(df), "DF018"));
}

// ─── DF019: deprecated MAINTAINER ───────────────────────────────────────────

#[test]
fn df019_fires_on_maintainer() {
    let df = "FROM alpine:3.19\nMAINTAINER old@example.com\n";
    assert!(has_rule(&lint(df), "DF019"));
}

// ─── DF021: curl | sh ────────────────────────────────────────────────────────

#[test]
fn df021_fires_on_curl_pipe_sh() {
    let df = "FROM alpine:3.19\nRUN curl http://example.com/install.sh | sh\n";
    assert!(has_rule(&lint(df), "DF021"));
}

#[test]
fn df021_fires_on_wget_pipe_bash() {
    let df = "FROM alpine:3.19\nRUN wget -O- http://example.com/install.sh | bash\n";
    assert!(has_rule(&lint(df), "DF021"));
}

// ─── DF025: shell form CMD ───────────────────────────────────────────────────

#[test]
fn df025_fires_on_shell_cmd() {
    let df = "FROM alpine:3.19\nCMD python3 app.py\n";
    assert!(has_rule(&lint(df), "DF025"));
}

#[test]
fn df025_clear_on_exec_cmd() {
    let df = "FROM alpine:3.19\nCMD [\"python3\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF025"));
}

// ─── DF028: split apt update/install ────────────────────────────────────────

#[test]
fn df028_fires_on_split_update_install() {
    let df = "FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl\n";
    assert!(has_rule(&lint(df), "DF028"));
}

#[test]
fn df028_clear_on_combined() {
    let df = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n";
    assert!(no_rule(&lint(df), "DF028"));
}

// ─── DF034: chmod 777 ────────────────────────────────────────────────────────

#[test]
fn df034_fires_on_chmod_777() {
    let df = "FROM alpine:3.19\nRUN chmod 777 /app\n";
    assert!(has_rule(&lint(df), "DF034"));
}

#[test]
fn df034_clear_on_sane_chmod() {
    let df = "FROM alpine:3.19\nRUN chmod 755 /app\n";
    assert!(no_rule(&lint(df), "DF034"));
}

// ─── DF030: pip no-cache-dir ─────────────────────────────────────────────────

#[test]
fn df030_fires_without_no_cache() {
    let df = "FROM python:3.12\nRUN pip install flask\nCMD [\"python\", \"app.py\"]\n";
    assert!(has_rule(&lint(df), "DF030"));
}

#[test]
fn df030_clear_with_no_cache() {
    let df = "FROM python:3.12\nRUN pip install --no-cache-dir flask\nCMD [\"python\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF030"));
}
