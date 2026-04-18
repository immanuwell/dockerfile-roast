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

// ─── DF005: unpinned package versions ────────────────────────────────────────

#[test]
fn df005_fires_on_unpinned_apt() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n";
    assert!(has_rule(&lint(df), "DF005"));
}

#[test]
fn df005_clear_on_pinned_apt() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl=7.68.0-1ubuntu2 && rm -rf /var/lib/apt/lists/*\n";
    assert!(no_rule(&lint(df), "DF005"));
}

#[test]
fn df005_fires_on_unpinned_yum() {
    let df = "FROM centos:7\nRUN yum install -y curl && yum clean all\n";
    assert!(has_rule(&lint(df), "DF005"));
}

// ─── DF008: cd instead of WORKDIR ────────────────────────────────────────────

#[test]
fn df008_fires_on_cd_in_run() {
    let df = "FROM alpine:3.19\nRUN cd /app && make\n";
    assert!(has_rule(&lint(df), "DF008"));
}

#[test]
fn df008_clear_with_workdir() {
    let df = "FROM alpine:3.19\nWORKDIR /app\nRUN make\n";
    assert!(no_rule(&lint(df), "DF008"));
}

// ─── DF010: sudo usage ────────────────────────────────────────────────────────

#[test]
fn df010_fires_on_sudo() {
    let df = "FROM ubuntu:22.04\nRUN sudo apt-get install -y curl\n";
    assert!(has_rule(&lint(df), "DF010"));
}

#[test]
fn df010_clear_without_sudo() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl\n";
    assert!(no_rule(&lint(df), "DF010"));
}

// ─── DF011: no multi-stage build for heavy images ────────────────────────────

#[test]
fn df011_fires_on_single_stage_golang() {
    let df = "FROM golang:1.21\nRUN go build ./...\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF011"));
}

#[test]
fn df011_fires_on_single_stage_node() {
    let df = "FROM node:20\nCOPY . .\nRUN npm ci\nCMD [\"node\", \"app.js\"]\n";
    assert!(has_rule(&lint(df), "DF011"));
}

#[test]
fn df011_clear_on_multistage() {
    let df = "FROM golang:1.21 AS builder\nRUN go build ./...\nFROM alpine:3.19\nCOPY --from=builder /go/bin/app /app\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF011"));
}

#[test]
fn df011_clear_on_non_build_image() {
    let df = "FROM alpine:3.19\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF011"));
}

// ─── DF012: no HEALTHCHECK ────────────────────────────────────────────────────

#[test]
fn df012_fires_with_expose_no_healthcheck() {
    let df = "FROM alpine:3.19\nEXPOSE 8080\nCMD [\"/app/server\"]\n";
    assert!(has_rule(&lint(df), "DF012"));
}

#[test]
fn df012_clear_with_healthcheck() {
    let df = "FROM alpine:3.19\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nEXPOSE 8080\nCMD [\"/app/server\"]\n";
    assert!(no_rule(&lint(df), "DF012"));
}

// ─── DF014: hardcoded secrets in ARG/ENV ─────────────────────────────────────

#[test]
fn df014_fires_on_hardcoded_password_arg() {
    let df = "FROM alpine:3.19\nARG password=supersecret\n";
    assert!(has_rule(&lint(df), "DF014"));
}

#[test]
fn df014_fires_on_hardcoded_token_env() {
    let df = "FROM alpine:3.19\nENV API_TOKEN=abc123def456\n";
    assert!(has_rule(&lint(df), "DF014"));
}

#[test]
fn df014_clear_on_empty_arg() {
    let df = "FROM alpine:3.19\nARG password\n";
    assert!(no_rule(&lint(df), "DF014"));
}

#[test]
fn df014_clear_on_arg_with_env_reference() {
    let df = "FROM alpine:3.19\nARG password=$DEFAULT_PASS\n";
    assert!(no_rule(&lint(df), "DF014"));
}

// ─── DF016: apt without --no-install-recommends ───────────────────────────────

#[test]
fn df016_fires_without_no_install_recommends() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n";
    assert!(has_rule(&lint(df), "DF016"));
}

#[test]
fn df016_clear_with_no_install_recommends() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\n";
    assert!(no_rule(&lint(df), "DF016"));
}

// ─── DF020: no USER instruction ──────────────────────────────────────────────

#[test]
fn df020_fires_with_no_user() {
    let df = "FROM alpine:3.19\nCMD [\"/app/server\"]\n";
    assert!(has_rule(&lint(df), "DF020"));
}

#[test]
fn df020_clear_with_user_set() {
    let df = "FROM alpine:3.19\nUSER appuser\nCMD [\"/app/server\"]\n";
    assert!(no_rule(&lint(df), "DF020"));
}

// ─── DF022: no EXPOSE ────────────────────────────────────────────────────────

#[test]
fn df022_fires_with_no_expose() {
    let df = "FROM alpine:3.19\nUSER appuser\nCMD [\"/app/server\"]\n";
    assert!(has_rule(&lint(df), "DF022"));
}

#[test]
fn df022_clear_with_expose() {
    let df = "FROM alpine:3.19\nEXPOSE 8080\nCMD [\"/app/server\"]\n";
    assert!(no_rule(&lint(df), "DF022"));
}

// ─── DF023: multiple FROM without aliases ────────────────────────────────────

#[test]
fn df023_fires_on_from_without_alias() {
    let df = "FROM golang:1.21\nRUN go build ./...\nFROM alpine:3.19\nCOPY --from=0 /go/bin/app /app\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF023"));
}

#[test]
fn df023_clear_when_all_have_aliases() {
    let df = "FROM golang:1.21 AS builder\nRUN go build ./...\nFROM alpine:3.19 AS final\nCOPY --from=builder /go/bin/app /app\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF023"));
}

// ─── DF026: COPY to filesystem root ──────────────────────────────────────────

#[test]
fn df026_fires_on_copy_to_root() {
    let df = "FROM alpine:3.19\nCOPY app /\n";
    assert!(has_rule(&lint(df), "DF026"));
}

#[test]
fn df026_clear_on_copy_to_subdir() {
    let df = "FROM alpine:3.19\nCOPY app /app/\n";
    assert!(no_rule(&lint(df), "DF026"));
}

// ─── DF027: yum without -y ───────────────────────────────────────────────────

#[test]
fn df027_fires_on_yum_without_y() {
    let df = "FROM centos:7\nRUN yum install curl\n";
    assert!(has_rule(&lint(df), "DF027"));
}

#[test]
fn df027_clear_on_yum_with_y() {
    let df = "FROM centos:7\nRUN yum install -y curl && yum clean all\n";
    assert!(no_rule(&lint(df), "DF027"));
}

// ─── DF029: apk add without --no-cache ───────────────────────────────────────

#[test]
fn df029_fires_on_apk_without_no_cache() {
    let df = "FROM alpine:3.19\nRUN apk add curl\n";
    assert!(has_rule(&lint(df), "DF029"));
}

#[test]
fn df029_clear_on_apk_with_no_cache() {
    let df = "FROM alpine:3.19\nRUN apk add --no-cache curl\n";
    assert!(no_rule(&lint(df), "DF029"));
}

// ─── DF031: npm install instead of npm ci ────────────────────────────────────

#[test]
fn df031_fires_on_npm_install() {
    let df = "FROM node:20\nRUN npm install\nCMD [\"node\", \"app.js\"]\n";
    assert!(has_rule(&lint(df), "DF031"));
}

#[test]
fn df031_clear_on_npm_ci() {
    let df = "FROM node:20\nRUN npm ci\nCMD [\"node\", \"app.js\"]\n";
    assert!(no_rule(&lint(df), "DF031"));
}

#[test]
fn df031_clear_on_npm_install_production() {
    let df = "FROM node:20\nRUN npm install --production\nCMD [\"node\", \"app.js\"]\n";
    assert!(no_rule(&lint(df), "DF031"));
}

// ─── DF032: Python env vars missing ──────────────────────────────────────────

#[test]
fn df032_fires_on_python_without_env_vars() {
    let df = "FROM python:3.12\nRUN pip install --no-cache-dir flask\nCMD [\"python\", \"app.py\"]\n";
    assert!(has_rule(&lint(df), "DF032"));
}

#[test]
fn df032_clear_on_python_with_env_vars() {
    let df = "FROM python:3.12\nENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\nRUN pip install --no-cache-dir flask\nCMD [\"python\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF032"));
}

#[test]
fn df032_clear_on_non_python_image() {
    let df = "FROM alpine:3.19\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF032"));
}

// ─── DF035: curl without --fail ──────────────────────────────────────────────

#[test]
fn df035_fires_on_curl_without_fail() {
    let df = "FROM alpine:3.19\nRUN curl https://example.com/file -o /tmp/file\n";
    assert!(has_rule(&lint(df), "DF035"));
}

#[test]
fn df035_clear_on_curl_with_fail_flag() {
    let df = "FROM alpine:3.19\nRUN curl --fail https://example.com/file -o /tmp/file\n";
    assert!(no_rule(&lint(df), "DF035"));
}

#[test]
fn df035_clear_on_curl_with_fssl() {
    let df = "FROM alpine:3.19\nRUN curl -fsSL https://example.com/file -o /tmp/file\n";
    assert!(no_rule(&lint(df), "DF035"));
}

// ─── DF036: no CMD or ENTRYPOINT ─────────────────────────────────────────────

#[test]
fn df036_fires_with_no_cmd_or_entrypoint() {
    let df = "FROM alpine:3.19\nWORKDIR /app\nCOPY . .\n";
    assert!(has_rule(&lint(df), "DF036"));
}

#[test]
fn df036_clear_with_cmd() {
    let df = "FROM alpine:3.19\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF036"));
}

#[test]
fn df036_clear_with_entrypoint() {
    let df = "FROM alpine:3.19\nENTRYPOINT [\"/app/server\"]\n";
    assert!(no_rule(&lint(df), "DF036"));
}

// ─── DF037: invalid instruction order ────────────────────────────────────────

#[test]
fn df037_fires_when_run_before_from() {
    let df = "RUN echo hello\nFROM alpine:3.19\n";
    assert!(has_rule(&lint(df), "DF037"));
}

#[test]
fn df037_clear_when_from_first() {
    let df = "FROM alpine:3.19\nRUN echo hello\n";
    assert!(no_rule(&lint(df), "DF037"));
}

#[test]
fn df037_clear_when_arg_before_from() {
    let df = "ARG VERSION=3.19\nFROM alpine:${VERSION}\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF037"));
}

// ─── DF038: multiple CMD ──────────────────────────────────────────────────────

#[test]
fn df038_fires_on_multiple_cmd() {
    let df = "FROM alpine:3.19\nCMD [\"first\"]\nCMD [\"second\"]\n";
    assert!(has_rule(&lint(df), "DF038"));
}

#[test]
fn df038_clear_on_single_cmd() {
    let df = "FROM alpine:3.19\nCMD [\"only\"]\n";
    assert!(no_rule(&lint(df), "DF038"));
}

// ─── DF039: multiple ENTRYPOINT ──────────────────────────────────────────────

#[test]
fn df039_fires_on_multiple_entrypoint() {
    let df = "FROM alpine:3.19\nENTRYPOINT [\"/first\"]\nENTRYPOINT [\"/second\"]\n";
    assert!(has_rule(&lint(df), "DF039"));
}

#[test]
fn df039_clear_on_single_entrypoint() {
    let df = "FROM alpine:3.19\nENTRYPOINT [\"/only\"]\n";
    assert!(no_rule(&lint(df), "DF039"));
}

// ─── DF040: EXPOSE port out of range ─────────────────────────────────────────

#[test]
fn df040_fires_on_invalid_port() {
    let df = "FROM alpine:3.19\nEXPOSE 99999\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF040"));
}

#[test]
fn df040_clear_on_valid_port() {
    let df = "FROM alpine:3.19\nEXPOSE 8080\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF040"));
}

// ─── DF041: multiple HEALTHCHECK ─────────────────────────────────────────────

#[test]
fn df041_fires_on_multiple_healthcheck() {
    let df = "FROM alpine:3.19\nHEALTHCHECK CMD ping -c1 localhost\nHEALTHCHECK CMD curl -f http://localhost/\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF041"));
}

#[test]
fn df041_clear_on_single_healthcheck() {
    let df = "FROM alpine:3.19\nHEALTHCHECK CMD curl -f http://localhost/\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF041"));
}

// ─── DF042: duplicate stage aliases ──────────────────────────────────────────

#[test]
fn df042_fires_on_duplicate_alias() {
    let df = "FROM alpine:3.19 AS base\nFROM ubuntu:22.04 AS base\n";
    assert!(has_rule(&lint(df), "DF042"));
}

#[test]
fn df042_clear_on_unique_aliases() {
    let df = "FROM alpine:3.19 AS base\nFROM ubuntu:22.04 AS final\n";
    assert!(no_rule(&lint(df), "DF042"));
}

// ─── DF043: zypper install without -y ────────────────────────────────────────

#[test]
fn df043_fires_on_zypper_without_y() {
    let df = "FROM opensuse/leap:15.5\nRUN zypper install curl\n";
    assert!(has_rule(&lint(df), "DF043"));
}

#[test]
fn df043_clear_on_zypper_with_y() {
    let df = "FROM opensuse/leap:15.5\nRUN zypper install -y curl && zypper clean\n";
    assert!(no_rule(&lint(df), "DF043"));
}

// ─── DF044: zypper dist-upgrade ──────────────────────────────────────────────

#[test]
fn df044_fires_on_zypper_dist_upgrade() {
    let df = "FROM opensuse/leap:15.5\nRUN zypper dist-upgrade\n";
    assert!(has_rule(&lint(df), "DF044"));
}

#[test]
fn df044_fires_on_zypper_dup() {
    let df = "FROM opensuse/leap:15.5\nRUN zypper dup\n";
    assert!(has_rule(&lint(df), "DF044"));
}

#[test]
fn df044_clear_on_normal_zypper_install() {
    let df = "FROM opensuse/leap:15.5\nRUN zypper install -y curl && zypper clean\n";
    assert!(no_rule(&lint(df), "DF044"));
}

// ─── DF045: zypper cache not cleaned ─────────────────────────────────────────

#[test]
fn df045_fires_on_zypper_without_clean() {
    let df = "FROM opensuse/leap:15.5\nRUN zypper install -y curl\n";
    assert!(has_rule(&lint(df), "DF045"));
}

#[test]
fn df045_clear_on_zypper_with_clean() {
    let df = "FROM opensuse/leap:15.5\nRUN zypper install -y curl && zypper clean\n";
    assert!(no_rule(&lint(df), "DF045"));
}

// ─── DF046: dnf clean all missing ────────────────────────────────────────────

#[test]
fn df046_fires_on_dnf_without_clean() {
    let df = "FROM fedora:38\nRUN dnf install -y curl\n";
    assert!(has_rule(&lint(df), "DF046"));
}

#[test]
fn df046_clear_on_dnf_with_clean() {
    let df = "FROM fedora:38\nRUN dnf install -y curl && dnf clean all\n";
    assert!(no_rule(&lint(df), "DF046"));
}

// ─── DF047: yum clean all missing ────────────────────────────────────────────

#[test]
fn df047_fires_on_yum_without_clean() {
    let df = "FROM centos:7\nRUN yum install -y curl\n";
    assert!(has_rule(&lint(df), "DF047"));
}

#[test]
fn df047_clear_on_yum_with_clean() {
    let df = "FROM centos:7\nRUN yum install -y curl && yum clean all\n";
    assert!(no_rule(&lint(df), "DF047"));
}

// ─── DF048: COPY multi-source without trailing slash ─────────────────────────

#[test]
fn df048_fires_on_multi_source_no_slash() {
    let df = "FROM alpine:3.19\nCOPY file1.txt file2.txt /app\n";
    assert!(has_rule(&lint(df), "DF048"));
}

#[test]
fn df048_clear_on_multi_source_with_slash() {
    let df = "FROM alpine:3.19\nCOPY file1.txt file2.txt /app/\n";
    assert!(no_rule(&lint(df), "DF048"));
}

#[test]
fn df048_clear_on_two_arg_copy() {
    let df = "FROM alpine:3.19\nCOPY app.py /app/app.py\n";
    assert!(no_rule(&lint(df), "DF048"));
}

// ─── DF049: COPY --from undefined stage ──────────────────────────────────────

#[test]
fn df049_fires_on_copy_from_undefined() {
    let df = "FROM alpine:3.19\nCOPY --from=nonexistent /app /app\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF049"));
}

#[test]
fn df049_clear_on_copy_from_defined_stage() {
    let df = "FROM golang:1.21 AS builder\nRUN go build ./...\nFROM alpine:3.19\nCOPY --from=builder /go/bin/app /app\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF049"));
}

#[test]
fn df049_clear_on_copy_from_numeric_index() {
    let df = "FROM golang:1.21\nRUN go build ./...\nFROM alpine:3.19\nCOPY --from=0 /go/bin/app /app\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF049"));
}

// ─── DF050: COPY --from current stage ────────────────────────────────────────

#[test]
fn df050_fires_on_copy_from_self() {
    let df = "FROM alpine:3.19 AS myapp\nCOPY --from=myapp /tmp /app\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF050"));
}

#[test]
fn df050_clear_on_copy_from_other_stage() {
    let df = "FROM golang:1.21 AS builder\nRUN go build ./...\nFROM alpine:3.19 AS myapp\nCOPY --from=builder /go/bin/app /app\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF050"));
}

// ─── DF051: pip version pinning ──────────────────────────────────────────────

#[test]
fn df051_fires_on_unpinned_pip() {
    let df = "FROM python:3.12\nRUN pip install --no-cache-dir flask\nCMD [\"python\", \"app.py\"]\n";
    assert!(has_rule(&lint(df), "DF051"));
}

#[test]
fn df051_clear_on_pinned_pip() {
    let df = "FROM python:3.12\nRUN pip install --no-cache-dir flask==2.3.3\nCMD [\"python\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF051"));
}

#[test]
fn df051_clear_on_pip_requirements_file() {
    let df = "FROM python:3.12\nRUN pip install --no-cache-dir -r requirements.txt\nCMD [\"python\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF051"));
}

// ─── DF052: apk version pinning ──────────────────────────────────────────────

#[test]
fn df052_fires_on_unpinned_apk() {
    let df = "FROM alpine:3.19\nRUN apk add --no-cache curl\n";
    assert!(has_rule(&lint(df), "DF052"));
}

#[test]
fn df052_clear_on_pinned_apk() {
    let df = "FROM alpine:3.19\nRUN apk add --no-cache curl=8.4.0-r0\n";
    assert!(no_rule(&lint(df), "DF052"));
}

// ─── DF053: gem version pinning ──────────────────────────────────────────────

#[test]
fn df053_fires_on_unpinned_gem() {
    let df = "FROM ruby:3.2\nRUN gem install rails\nCMD [\"rails\", \"s\"]\n";
    assert!(has_rule(&lint(df), "DF053"));
}

#[test]
fn df053_clear_on_pinned_gem() {
    let df = "FROM ruby:3.2\nRUN gem install rails:7.1.0\nCMD [\"rails\", \"s\"]\n";
    assert!(no_rule(&lint(df), "DF053"));
}

// ─── DF054: go install without @version ──────────────────────────────────────

#[test]
fn df054_fires_on_go_install_no_version() {
    let df = "FROM golang:1.21\nRUN go install github.com/user/tool\n";
    assert!(has_rule(&lint(df), "DF054"));
}

#[test]
fn df054_clear_on_go_install_with_version() {
    let df = "FROM golang:1.21\nRUN go install github.com/user/tool@v1.2.3\n";
    assert!(no_rule(&lint(df), "DF054"));
}

// ─── DF055: yarn cache not cleaned ───────────────────────────────────────────

#[test]
fn df055_fires_on_yarn_install_no_clean() {
    let df = "FROM node:20\nRUN yarn install\nCMD [\"node\", \"app.js\"]\n";
    assert!(has_rule(&lint(df), "DF055"));
}

#[test]
fn df055_clear_on_yarn_install_with_clean() {
    let df = "FROM node:20\nRUN yarn install && yarn cache clean\nCMD [\"node\", \"app.js\"]\n";
    assert!(no_rule(&lint(df), "DF055"));
}

// ─── DF056: wget without --progress ──────────────────────────────────────────

#[test]
fn df056_fires_on_wget_without_progress() {
    let df = "FROM alpine:3.19\nRUN wget https://example.com/file -O /tmp/file\n";
    assert!(has_rule(&lint(df), "DF056"));
}

#[test]
fn df056_clear_on_wget_with_quiet() {
    let df = "FROM alpine:3.19\nRUN wget -q https://example.com/file -O /tmp/file\n";
    assert!(no_rule(&lint(df), "DF056"));
}

#[test]
fn df056_clear_on_wget_with_progress_flag() {
    let df = "FROM alpine:3.19\nRUN wget --progress=dot:giga https://example.com/file -O /tmp/file\n";
    assert!(no_rule(&lint(df), "DF056"));
}

// ─── DF057: pipefail missing ──────────────────────────────────────────────────

#[test]
fn df057_fires_on_pipe_without_pipefail() {
    let df = "FROM alpine:3.19\nRUN cat /etc/os-release | grep ID\n";
    assert!(has_rule(&lint(df), "DF057"));
}

#[test]
fn df057_clear_on_pipe_with_pipefail() {
    let df = "FROM alpine:3.19\nRUN set -o pipefail && cat /etc/os-release | grep ID\n";
    assert!(no_rule(&lint(df), "DF057"));
}

// ─── DF058: wget and curl both used ──────────────────────────────────────────

#[test]
fn df058_fires_on_both_wget_and_curl() {
    let df = "FROM alpine:3.19\nRUN wget https://a.com/file\nRUN curl -fsSL https://b.com/file -o /tmp/f\n";
    assert!(has_rule(&lint(df), "DF058"));
}

#[test]
fn df058_clear_on_only_wget() {
    let df = "FROM alpine:3.19\nRUN wget https://a.com/file\n";
    assert!(no_rule(&lint(df), "DF058"));
}

#[test]
fn df058_clear_on_only_curl() {
    let df = "FROM alpine:3.19\nRUN curl -fsSL https://a.com/file -o /tmp/f\n";
    assert!(no_rule(&lint(df), "DF058"));
}

// ─── DF059: apt used instead of apt-get ──────────────────────────────────────

#[test]
fn df059_fires_on_apt_install() {
    let df = "FROM ubuntu:22.04\nRUN apt install curl\n";
    assert!(has_rule(&lint(df), "DF059"));
}

#[test]
fn df059_clear_on_apt_get_install() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n";
    assert!(no_rule(&lint(df), "DF059"));
}

// ─── DF060: useless interactive commands ─────────────────────────────────────

#[test]
fn df060_fires_on_systemctl() {
    let df = "FROM ubuntu:22.04\nRUN systemctl enable nginx\n";
    assert!(has_rule(&lint(df), "DF060"));
}

#[test]
fn df060_fires_on_service() {
    let df = "FROM ubuntu:22.04\nRUN service nginx start\n";
    assert!(has_rule(&lint(df), "DF060"));
}

#[test]
fn df060_clear_on_normal_command() {
    let df = "FROM ubuntu:22.04\nRUN nginx -t\n";
    assert!(no_rule(&lint(df), "DF060"));
}

// ─── DF061: --platform in FROM ────────────────────────────────────────────────

#[test]
fn df061_fires_on_platform_flag() {
    let df = "FROM --platform=linux/amd64 alpine:3.19\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF061"));
}

#[test]
fn df061_clear_without_platform_flag() {
    let df = "FROM alpine:3.19\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF061"));
}

// ─── DF062: ENV self-reference ────────────────────────────────────────────────

#[test]
fn df062_fires_on_env_self_reference() {
    // VAR=$VAR:suffix — self-reference at the start of the value
    let df = "FROM alpine:3.19\nENV PATH=$PATH:/usr/local/bin\n";
    assert!(has_rule(&lint(df), "DF062"));
}

#[test]
fn df062_fires_on_direct_self_reference() {
    // VAR=$VAR — bare self-assignment
    let df = "FROM alpine:3.19\nENV MY_VAR=$MY_VAR\n";
    assert!(has_rule(&lint(df), "DF062"));
}

#[test]
fn df062_fires_on_quoted_self_reference() {
    // VAR="$VAR" — quoted self-assignment
    let df = "FROM alpine:3.19\nENV PATH=\"$PATH\"\n";
    assert!(has_rule(&lint(df), "DF062"));
}

#[test]
fn df062_clear_on_no_self_reference() {
    let df = "FROM alpine:3.19\nENV MYAPP_PATH=/usr/local/bin\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn df062_clear_on_path_append() {
    // VAR="prefix:$OTHER_VAR" — extending PATH using a different previously-set variable
    let df = "FROM python:3.13-slim\nENV VENV=/opt/venv/bin\nENV PATH=\"$VENV:$PATH\"\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn df062_clear_on_normal_assignment() {
    // BAZ=$FOO — referencing a different variable
    let df = "FROM alpine:3.19\nENV FOO=bar\nENV BAZ=$FOO\n";
    assert!(no_rule(&lint(df), "DF062"));
}

// ─── DF063: COPY relative dest without WORKDIR ───────────────────────────────

#[test]
fn df063_fires_on_relative_copy_no_workdir() {
    let df = "FROM alpine:3.19\nCOPY app.py app.py\n";
    assert!(has_rule(&lint(df), "DF063"));
}

#[test]
fn df063_clear_on_relative_copy_with_workdir() {
    let df = "FROM alpine:3.19\nWORKDIR /app\nCOPY app.py app.py\n";
    assert!(no_rule(&lint(df), "DF063"));
}

#[test]
fn df063_clear_on_absolute_dest_copy() {
    let df = "FROM alpine:3.19\nCOPY app.py /app/app.py\n";
    assert!(no_rule(&lint(df), "DF063"));
}

// ─── DF064: useradd without -l ────────────────────────────────────────────────

#[test]
fn df064_fires_on_useradd_without_l() {
    let df = "FROM ubuntu:22.04\nRUN useradd appuser\n";
    assert!(has_rule(&lint(df), "DF064"));
}

#[test]
fn df064_clear_on_useradd_with_l() {
    let df = "FROM ubuntu:22.04\nRUN useradd -l appuser\n";
    assert!(no_rule(&lint(df), "DF064"));
}

#[test]
fn df064_clear_on_useradd_with_no_log_init() {
    let df = "FROM ubuntu:22.04\nRUN useradd --no-log-init appuser\n";
    assert!(no_rule(&lint(df), "DF064"));
}

// ─── DF065: unrecognised registry ────────────────────────────────────────────

#[test]
fn df065_fires_on_unknown_registry() {
    let df = "FROM myregistry.internal.example.com/myimage:1.0\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF065"));
}

#[test]
fn df065_clear_on_trusted_registry_ghcr() {
    let df = "FROM ghcr.io/owner/image:1.0\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF065"));
}

#[test]
fn df065_clear_on_docker_hub_short_name() {
    let df = "FROM ubuntu:22.04\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF065"));
}

// ─── DF066: bash syntax without SHELL ────────────────────────────────────────

#[test]
fn df066_fires_on_double_bracket_no_shell() {
    let df = "FROM alpine:3.19\nRUN [[ -f /etc/os-release ]] && cat /etc/os-release\n";
    assert!(has_rule(&lint(df), "DF066"));
}

#[test]
fn df066_fires_on_source_builtin_no_shell() {
    let df = "FROM ubuntu:22.04\nRUN source /etc/profile && env\n";
    assert!(has_rule(&lint(df), "DF066"));
}

#[test]
fn df066_clear_with_shell_instruction() {
    let df = "FROM alpine:3.19\nSHELL [\"/bin/bash\", \"-c\"]\nRUN [[ -f /etc/os-release ]] && cat /etc/os-release\n";
    assert!(no_rule(&lint(df), "DF066"));
}

// ─── DF067: COPY of archive (use ADD instead) ────────────────────────────────

#[test]
fn df067_fires_on_copy_of_tarball() {
    let df = "FROM alpine:3.19\nCOPY app.tar.gz /tmp/\n";
    assert!(has_rule(&lint(df), "DF067"));
}

#[test]
fn df067_fires_on_copy_of_tgz() {
    let df = "FROM alpine:3.19\nCOPY dist.tgz /opt/\n";
    assert!(has_rule(&lint(df), "DF067"));
}

#[test]
fn df067_clear_on_copy_of_non_archive() {
    let df = "FROM alpine:3.19\nCOPY app.py /app/\n";
    assert!(no_rule(&lint(df), "DF067"));
}

#[test]
fn df067_clear_on_copy_from_stage() {
    let df = "FROM alpine:3.19 AS builder\nFROM alpine:3.19\nCOPY --from=builder /app.tar.gz /tmp/\n";
    assert!(no_rule(&lint(df), "DF067"));
}

// ─── DF068: forbidden ONBUILD triggers ───────────────────────────────────────

#[test]
fn df068_fires_on_onbuild_from() {
    let df = "FROM alpine:3.19\nONBUILD FROM ubuntu:22.04\n";
    assert!(has_rule(&lint(df), "DF068"));
}

#[test]
fn df068_fires_on_onbuild_onbuild() {
    let df = "FROM alpine:3.19\nONBUILD ONBUILD RUN echo hello\n";
    assert!(has_rule(&lint(df), "DF068"));
}

#[test]
fn df068_fires_on_onbuild_maintainer() {
    let df = "FROM alpine:3.19\nONBUILD MAINTAINER someone@example.com\n";
    assert!(has_rule(&lint(df), "DF068"));
}

#[test]
fn df068_clear_on_allowed_onbuild_trigger() {
    let df = "FROM alpine:3.19\nONBUILD RUN echo hello\n";
    assert!(no_rule(&lint(df), "DF068"));
}
