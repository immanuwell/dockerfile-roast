//! Integration tests verifying each lint rule fires (or doesn't) correctly.

use dockerfile_roast::parser;
use dockerfile_roast::rules::{all_rules, Finding, Severity, ALL_CATEGORIES};

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

fn finding<'a>(findings: &'a [Finding], rule_id: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.rule == rule_id)
        .unwrap_or_else(|| panic!("expected {rule_id} finding"))
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

#[test]
fn df001_clear_on_pinned_image_with_platform_flag() {
    let df = "FROM --platform=$BUILDPLATFORM node:26.5.0-alpine@sha256:abc123 AS restore\n";
    assert!(no_rule(&lint(df), "DF001"));
}

#[test]
fn df001_clear_when_previous_stage_is_the_base() {
    let df = "FROM node:26.5.0-alpine@sha256:abc123 AS restore\nFROM restore AS migrate\n";
    assert!(no_rule(&lint(df), "DF001"));
}

#[test]
fn df001_clear_when_the_image_reference_is_a_build_argument() {
    let df = "ARG IMAGE=buildpack-deps:resolute\nFROM ${IMAGE}\n";
    assert!(no_rule(&lint(df), "DF001"));
}

#[test]
fn df001_resolves_known_global_arg_defaults() {
    let nested = "ARG REGISTRY=quay.io\nARG OWNER=jupyter\nARG IMAGE=$REGISTRY/$OWNER/minimal-notebook\nFROM $IMAGE\n";
    let composed = "ARG VERSION=3-latest\nARG PYTHON=3.12\nFROM prefecthq/prefect:${VERSION}-python${PYTHON}\n";
    let pinned = "ARG IMAGE=ubuntu:24.04\nFROM ${IMAGE}\n";
    assert!(has_rule(&lint(nested), "DF001"));
    assert!(has_rule(&lint(composed), "DF001"));
    assert!(no_rule(&lint(pinned), "DF001"));
}

#[test]
fn df001_resolves_quoted_global_arg_images() {
    let df = "ARG BASE_IMAGE=\"rayproject/ray:latest\"\nFROM \"$BASE_IMAGE\"\n";
    assert!(has_rule(&lint(df), "DF001"));
}

#[test]
fn df001_still_fires_when_only_the_platform_is_a_build_argument() {
    let df = "FROM --platform=$BUILDPLATFORM alpine:latest\n";
    assert!(has_rule(&lint(df), "DF001"));
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

#[test]
fn df002_clear_when_root_is_only_used_for_setup() {
    let df = "FROM alpine:3.19\nUSER root\nRUN apk add --no-cache curl\nUSER appuser\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF002"));
}

#[test]
fn df002_ignores_root_user_in_non_final_build_stage() {
    let df = "FROM alpine:3.19 AS builder\nUSER root\nRUN echo build\nFROM alpine:3.19\nUSER appuser\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF002"));
}

#[test]
fn df002_fires_when_final_stage_ends_as_root() {
    let df = "FROM alpine:3.19 AS builder\nUSER appuser\nRUN echo build\nFROM alpine:3.19\nUSER root\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF002"));
}

#[test]
fn df002_tracks_user_inherited_from_named_stage() {
    let df = "FROM scratch AS base\nUSER root\nFROM base\nCMD [\"/app\"]\n";
    assert!(has_rule(&lint(df), "DF002"));
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

#[test]
fn df003_is_an_info_level_advisory() {
    let findings = lint("FROM alpine:3.19\nRUN a\nRUN b\nRUN c\nRUN d\n");
    assert_eq!(finding(&findings, "DF003").severity, Severity::Info);
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

#[test]
fn df004_recognizes_cleanup_regardless_of_path_order_or_rm_flags() {
    let reordered = "FROM ubuntu:24.04\nRUN apt-get install -y curl && rm -rf /tmp/* /var/lib/apt/lists/* /var/log/*\n";
    let package_lists =
        "FROM ubuntu:20.04\nRUN apt-get install -y curl && rm /var/lib/apt/lists/*_*\n";
    assert!(no_rule(&lint(reordered), "DF004"));
    assert!(no_rule(&lint(package_lists), "DF004"));
}

#[test]
fn package_cache_rules_ignore_disposable_stages_but_follow_inheritance() {
    let disposable = "FROM ubuntu:24.04 AS build\nRUN apt-get install -y make\nFROM scratch\nCOPY --from=build /usr/bin/make /make\n";
    let inherited = "FROM ubuntu:24.04 AS base\nRUN apt-get install -y curl\nFROM base\nCMD [\"curl\", \"--version\"]\n";
    let root_copy = "FROM ubuntu:24.04 AS rootfs\nRUN apt-get install -y curl\nFROM scratch\nCOPY --from=rootfs / /\n";
    assert!(no_rule(&lint(disposable), "DF004"));
    assert!(has_rule(&lint(inherited), "DF004"));
    assert!(has_rule(&lint(root_copy), "DF004"));
}

#[test]
fn package_cache_cleanup_before_root_snapshot_prevents_runtime_findings() {
    let df = "FROM registry.access.redhat.com/ubi9/ubi AS rootfs\nRUN microdnf install -y curl\nRUN microdnf clean all\nFROM scratch\nCOPY --from=rootfs / /\n";
    let findings = lint(df);
    assert!(no_rule(&findings, "DF004"));
    assert!(no_rule(&findings, "DF046"));
}

#[test]
fn df004_reports_the_install_token_on_its_physical_line() {
    let df = "FROM ubuntu:24.04\nRUN set -eux; \\\n    apt-get update; \\\n    apt-get install -y curl\n";
    let findings = lint(df);
    let finding = finding(&findings, "DF004");
    assert_eq!((finding.line, finding.column), (4, 5));
}

#[test]
fn df004_clear_with_apt_get_distclean() {
    let df = "FROM ubuntu:24.04\nRUN apt-get install -U -y --no-install-recommends bash && apt-get distclean\nCMD [\"/bin/sh\"]\n";
    assert!(no_rule(&lint(df), "DF004"));
}

#[test]
fn df004_clear_with_apt_get_dist_clean_and_brace_expansion() {
    let dist_clean =
        "FROM debian:trixie\nRUN apt-get update && apt-get install -y curl && apt-get dist-clean\n";
    let brace_cleanup = "FROM debian:bookworm\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/{apt,dpkg,cache,log}\n";
    assert!(no_rule(&lint(dist_clean), "DF004"));
    assert!(no_rule(&lint(brace_cleanup), "DF004"));
}

#[test]
fn df004_fires_on_similarly_named_non_cleanup_command() {
    let df = "FROM ubuntu:24.04\nRUN apt-get install -y bash && apt-get distcleaner\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF004"));
}

#[test]
fn df004_clear_with_comment_inside_continuation() {
    // Docker strips comment lines inside continuations, so the trailing
    // cleanup still belongs to the same RUN (issue #11).
    let df = "FROM debian:bookworm-slim\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends \\\n        curl \\\n        # embedded comment\n        ca-certificates && \\\n    apt-get clean && \\\n    rm -rf /var/lib/apt/lists/*\nCMD [\"true\"]\n";
    assert!(no_rule(&lint(df), "DF004"));
}

#[test]
fn df004_clear_when_apt_state_is_on_buildkit_cache_mounts() {
    let df = "# syntax=docker/dockerfile:1\nFROM ubuntu:24.04\nRUN --mount=type=cache,target=/var/lib/apt \\\n+    --mount=type=cache,target=/var/cache/apt \\\n+    apt-get update && apt-get install -y curl\n";
    assert!(no_rule(&lint(df), "DF004"));
}

#[test]
fn df004_clear_when_apt_lists_are_on_tmpfs() {
    let df = "# syntax=docker/dockerfile:1\nFROM ubuntu:24.04\nRUN --mount=type=tmpfs,target=/var/lib/apt/lists \\\n+    apt-get update && apt-get install -y curl\n";
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

#[test]
fn df006_clear_on_local_archive_tar_bz2() {
    let df = "FROM alpine:3.19\nADD data.tar.bz2 /data/\n";
    assert!(no_rule(&lint(df), "DF006"));
}

#[test]
fn df006_clear_on_chown_with_url() {
    // --chown flag must not confuse source detection
    let df = "FROM alpine:3.19\nADD --chown=user:group https://example.com/file /tmp/\n";
    assert!(no_rule(&lint(df), "DF006"));
}

#[test]
fn df006_clear_on_chown_with_archive() {
    let df = "FROM alpine:3.19\nADD --chown=appuser archive.tar.gz /app/\n";
    assert!(no_rule(&lint(df), "DF006"));
}

// ─── DF007: COPY . ───────────────────────────────────────────────────────────

#[test]
fn df007_fires_on_copy_dot() {
    let df = "FROM alpine:3.19\nCOPY . .\n";
    assert!(has_rule(&lint(df), "DF007"));
}

#[test]
fn df007_is_informational_in_a_scratch_staging_stage() {
    let findings = lint("FROM scratch AS context\nCOPY . /source/\nFROM alpine:3.20\nCOPY --from=context /source/app /app\n");
    assert_eq!(finding(&findings, "DF007").severity, Severity::Info);
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

#[test]
fn df009_clear_on_quoted_absolute_workdir() {
    let df = "FROM alpine:3.19\nWORKDIR \"/\"\n";
    assert!(no_rule(&lint(df), "DF009"));
}

#[test]
fn df009_accepts_windows_absolute_workdirs() {
    for path in ["C:/Users/ContainerAdministrator/app", "C:\\\\app"] {
        let df = format!("FROM mcr.microsoft.com/windows/servercore:ltsc2022\nWORKDIR {path}\n");
        assert!(no_rule(&lint(&df), "DF009"), "unexpected DF009 for {path}");
    }
}

// ─── DF013: secrets in ENV ───────────────────────────────────────────────────

#[test]
fn df013_ignores_secret_env_pass_through() {
    let df = "FROM alpine:3.19\nARG DATABASE_PASSWORD\nENV DATABASE_PASSWORD=$DATABASE_PASSWORD\n";
    assert!(no_rule(&lint(df), "DF013"));
}

#[test]
fn df014_supersedes_df013_for_a_hardcoded_env_secret() {
    let findings = lint("FROM alpine:3.19\nENV DATABASE_PASSWORD=secret\n");
    assert!(no_rule(&findings, "DF013"));
    assert!(has_rule(&findings, "DF014"));
}

#[test]
fn df013_clear_on_normal_env() {
    let df = "FROM alpine:3.19\nENV APP_PORT=8080\n";
    assert!(no_rule(&lint(df), "DF013"));
}

#[test]
fn df013_and_df014_ignore_secret_file_variables() {
    let df = "FROM scratch\nENV MINIO_ACCESS_KEY_FILE=access_key \\\n    MINIO_ROOT_PASSWORD_FILE=secret_key \\\n    MINIO_KMS_SECRET_KEY_FILE=kms_master_key\n";
    let findings = lint(df);
    assert!(no_rule(&findings, "DF013"));
    assert!(no_rule(&findings, "DF014"));
}

#[test]
fn df013_reports_literal_run_credentials_at_the_value() {
    let df = "FROM ubuntu:24.04\nRUN service postgresql start && psql -c \"ALTER USER postgres WITH PASSWORD 'postgres';\"\nRUN pkcs11-tool --slot 0 --init-token --so-pin 0000 --pin \"$HSM_PIN\"\n";
    let findings: Vec<_> = lint(df)
        .into_iter()
        .filter(|finding| finding.rule == "DF013")
        .collect();
    assert_eq!(findings.len(), 2);
    assert_eq!((findings[0].line, findings[0].column), (2, 77));
    assert_eq!((findings[1].line, findings[1].column), (3, 48));
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

#[test]
fn df015_clear_with_combined_and_quiet_assume_yes_options() {
    for options in ["-Uy", "-qq", "-q=2", "--quiet=2", "-q 2"] {
        let df = format!("FROM ubuntu:24.04\nRUN apt-get install {options} bash\n");
        assert!(
            no_rule(&lint(&df), "DF015"),
            "unexpected DF015 for {options}"
        );
    }
}

#[test]
fn df015_fires_with_single_quiet_option() {
    let df = "FROM ubuntu:24.04\nRUN apt-get install -q bash\n";
    assert!(has_rule(&lint(df), "DF015"));
}

#[test]
fn df015_respects_inherited_apt_assume_yes_configuration() {
    let df = "FROM ubuntu:24.04 AS configured\nRUN echo 'APT::Get::Assume-Yes \"true\";' > /etc/apt/apt.conf.d/90ci\nFROM configured\nRUN apt-get update && apt-get install curl\n";
    assert!(no_rule(&lint(df), "DF015"));
}

#[test]
fn df015_does_not_leak_apt_configuration_to_unrelated_stages() {
    let df = "FROM ubuntu:24.04 AS configured\nRUN echo 'APT::Get::Assume-Yes \"true\";' > /etc/apt/apt.conf.d/90ci\nFROM ubuntu:24.04\nRUN apt-get install curl\n";
    assert!(has_rule(&lint(df), "DF015"));
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

#[test]
fn df021_covers_interpreters_assignments_and_shell_substitutions() {
    for command in [
        "curl -fsSL https://example.com/install.sh | TAG=v1 bash",
        "curl -fsSL https://example.com/get-pip.py | python3.12",
        "sh -c \"$(curl -fsSL https://example.com/install.sh)\"",
    ] {
        let df = format!("FROM ubuntu:24.04\nRUN {command}\n");
        assert!(has_rule(&lint(&df), "DF021"), "missed {command}");
    }
}

#[test]
fn df021_detects_env_wrappers_and_download_then_execute_flows() {
    let wrapped = "FROM ubuntu:24.04\nRUN wget -qO- https://example.com/install.sh | sudo -E env TOOL_HOME=/opt sh\n";
    let same_run = "FROM ubuntu:24.04\nRUN curl -fsSL https://example.com/install.sh -o /tmp/tool.sh && sh /tmp/tool.sh\n";
    let later_run =
        "FROM ubuntu:24.04\nRUN curl -fsSLO https://example.com/tool.sh\nRUN ./tool.sh\n";
    let copied = "FROM ubuntu:24.04 AS download\nRUN curl -fsSL https://example.com/install.sh > install.sh\nFROM ubuntu:24.04\nCOPY --from=download install.sh .\nRUN sh install.sh\n";
    for dockerfile in [wrapped, same_run, later_run, copied] {
        assert!(has_rule(&lint(dockerfile), "DF021"), "missed {dockerfile}");
    }
}

#[test]
fn df021_ignores_checksum_verified_download_then_execute() {
    let df = "FROM ubuntu:24.04\nRUN curl -fsSL -o /tmp/tool.sh https://example.com/tool.sh && echo 'abc  /tmp/tool.sh' | sha256sum -c - && sh /tmp/tool.sh\n";
    assert!(no_rule(&lint(df), "DF021"));
}

#[test]
fn df021_reports_the_executed_downloader_on_its_physical_line() {
    let df = "FROM ubuntu:24.04\nRUN echo 'installing curl' \\\n+    && curl -fsSL https://example.com/bootstrap.py | python3\n";
    let findings = lint(df);
    let remote = finding(&findings, "DF021");
    assert_eq!(remote.line, 3);
    assert!(remote.column > 0);
}

#[test]
fn df021_clear_when_checksum_output_is_piped_to_sha256sum() {
    let df = "FROM ubuntu:24.04\nRUN curl -fsSLo /tmp/tool https://example.com/tool \\\n+        && printf '%s  %s\\n' \"$TOOL_SHA256\" /tmp/tool | sha256sum -c -\n";
    assert!(no_rule(&lint(df), "DF021"));
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
fn df034_detects_equivalent_world_writable_modes_but_not_sticky_directories() {
    for mode in ["0777", "a+w", "a+rwx", "a+rwX", "ugo+w", "o+w"] {
        let df = format!("FROM alpine:3.19\nRUN chmod {mode} /app\n");
        assert!(has_rule(&lint(&df), "DF034"), "missed chmod {mode}");
    }
    assert!(no_rule(
        &lint("FROM alpine:3.19\nRUN chmod 1777 /tmp/shared\n"),
        "DF034"
    ));
}

#[test]
fn df034_clear_on_sane_chmod() {
    let df = "FROM alpine:3.19\nRUN chmod 755 /app\n";
    assert!(no_rule(&lint(df), "DF034"));
}

#[test]
fn df034_ignores_removed_mktemp_directories() {
    let df = "FROM debian:bookworm\nRUN tempDir=\"$(mktemp -d)\" \\\n+    && chmod 777 \"$tempDir\" \\\n+    && do-something \"$tempDir\" \\\n+    && rm -rf \"$tempDir\"\n";
    assert!(no_rule(&lint(df), "DF034"));
}

#[test]
fn df034_reports_each_occurrence_at_the_actual_mode_token() {
    let df = "FROM alpine:3.20\nRUN chmod 777 /one \\\n+    && chmod -R 777 /two\n";
    let findings = lint(df)
        .into_iter()
        .filter(|finding| finding.rule == "DF034")
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 2);
    assert_eq!((findings[0].line, findings[1].line), (2, 3));
    assert!(findings.iter().all(|finding| finding.column > 0));
}

// ─── DF030: pip no-cache-dir ─────────────────────────────────────────────────

#[test]
fn df030_fires_without_no_cache() {
    let df = "FROM python:3.12\nRUN pip install flask\nCMD [\"python\", \"app.py\"]\n";
    assert!(has_rule(&lint(df), "DF030"));
}

#[test]
fn df030_clear_with_no_cache() {
    let df =
        "FROM python:3.12\nRUN pip install --no-cache-dir flask\nCMD [\"python\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF030"));
}

#[test]
fn df030_clear_when_cache_is_purged_in_the_same_run() {
    let pip = "FROM python:3.12\nRUN python -m pip install flask && python -m pip cache purge\n";
    let uv = "FROM python:3.12\nRUN uv pip install flask && uv cache clean\n";
    assert!(no_rule(&lint(pip), "DF030"));
    assert!(no_rule(&lint(uv), "DF030"));
}

#[test]
fn df030_ignores_cache_in_selectively_copied_builder_stages() {
    let uv = "FROM python:3.13 AS build\nWORKDIR /app\nRUN uv pip install .\nFROM python:3.13-slim\nCOPY --from=build /app /app\n";
    let pip = "FROM python:3.13 AS build\nRUN pip install flask\nFROM scratch\nCOPY --from=build /usr/local/lib/python3.13/site-packages /site-packages\n";
    assert!(no_rule(&lint(uv), "DF030"));
    assert!(no_rule(&lint(pip), "DF030"));
}

#[test]
fn df030_clear_when_pip_no_cache_dir_environment_is_enabled() {
    for value in ["1", "true", "yes", "on"] {
        let df = format!(
            "FROM python:3.12\nENV PIP_NO_CACHE_DIR={value}\nRUN python -m pip install flask\n"
        );
        assert!(
            no_rule(&lint(&df), "DF030"),
            "value {value} should disable pip cache"
        );
    }
}

#[test]
fn df030_fires_when_pip_no_cache_dir_environment_is_disabled_or_overridden() {
    for value in ["0", "false", "no", "off", "${CACHE_SETTING}"] {
        let df = format!("FROM python:3.12\nENV PIP_NO_CACHE_DIR={value}\nRUN pip install flask\n");
        assert!(
            has_rule(&lint(&df), "DF030"),
            "value {value} must not suppress DF030"
        );
    }
    let overridden = "FROM python:3.12 AS build\nENV PIP_NO_CACHE_DIR=1\nENV PIP_NO_CACHE_DIR=0\nRUN pip install flask\n";
    assert!(has_rule(&lint(overridden), "DF030"));
}

#[test]
fn df030_inherits_pip_no_cache_dir_from_named_parent_stage() {
    let df = "FROM python:3.12 AS base\nENV PIP_NO_CACHE_DIR=1\nFROM base AS runtime\nRUN pip install flask\n";
    assert!(no_rule(&lint(df), "DF030"));
}

#[test]
fn df030_uses_uv_no_cache_flag() {
    let flagged = lint("FROM python:3.12\nRUN uv pip install flask\n");
    assert!(has_rule(&flagged, "DF030"));
    assert!(flagged
        .iter()
        .any(|finding| finding.rule == "DF030" && finding.message.contains("--no-cache")));
    assert!(no_rule(
        &lint("FROM python:3.12\nRUN uv pip install --no-cache flask\n"),
        "DF030"
    ));
}

#[test]
fn df030_clear_when_pip_or_uv_cache_is_buildkit_mounted() {
    let pip = "# syntax=docker/dockerfile:1\nFROM python:3.12\nRUN --mount=type=cache,target=/tmp/.cache pip install flask\n";
    let uv = "# syntax=docker/dockerfile:1\nFROM python:3.12\nRUN --mount=type=cache,target=${HOME}/.cache/uv uv pip install flask\n";
    assert!(no_rule(&lint(pip), "DF030"));
    assert!(no_rule(&lint(uv), "DF030"));
}

#[test]
fn df030_respects_uv_cache_dir_backed_by_a_cache_mount() {
    let df = "FROM python:3.12\nENV UV_CACHE_DIR=/opt/uv/cache\nRUN --mount=type=cache,target=/opt/uv/cache uv pip install flask\n";
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
fn df005_ignores_equals_signs_in_apt_options() {
    let df = "FROM ubuntu:24.04\nRUN apt-get install -q=2 bash\n";
    assert!(has_rule(&lint(df), "DF005"));
}

#[test]
fn df005_fires_when_any_apt_package_is_unpinned() {
    let df = "FROM ubuntu:24.04\nRUN apt-get install -y curl=8.5.0 bash\n";
    assert!(has_rule(&lint(df), "DF005"));
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
    let df = "FROM ubuntu:22.04\nUSER root\nRUN sudo apt-get install -y curl\n";
    assert!(has_rule(&lint(df), "DF010"));
    assert_eq!(finding(&lint(df), "DF010").severity, Severity::Warning);
}

#[test]
fn df010_clear_without_sudo() {
    let df = "FROM ubuntu:22.04\nRUN apt-get install -y curl\n";
    assert!(no_rule(&lint(df), "DF010"));
}

#[test]
fn df010_clear_when_sudo_is_a_package_or_group_name() {
    let packages = "FROM ubuntu:24.04\nRUN apt-get install -y \\\n+        curl \\\n+        sudo \\\n+        tini\n";
    let group = "FROM ubuntu:24.04\nRUN usermod -aG docker,sudo appuser\n";
    assert!(no_rule(&lint(packages), "DF010"));
    assert!(no_rule(&lint(group), "DF010"));
}

#[test]
fn df010_fires_when_sudo_starts_a_chained_command() {
    let chained = "FROM ubuntu:24.04\nUSER root\nRUN make bootstrap && sudo apt-get clean\n";
    let heredoc = "FROM ubuntu:24.04\nUSER root\nRUN <<EOF\necho ready\nsudo apt-get clean\nEOF\n";
    assert!(has_rule(&lint(chained), "DF010"));
    assert!(has_rule(&lint(heredoc), "DF010"));
}

#[test]
fn df010_respects_user_state_and_shell_arrays() {
    let non_root = "FROM ubuntu:24.04\nUSER app\nRUN sudo apt-get update\n";
    let unknown = "FROM custom/image:1\nRUN sudo apt-get update\n";
    let array = "FROM ubuntu:24.04\nRUN <<EOF\nPACKAGES=(\n  sudo\n  ssh\n)\nprintf '%s' \"${PACKAGES[@]}\"\nEOF\n";
    assert!(no_rule(&lint(non_root), "DF010"));
    assert_eq!(finding(&lint(unknown), "DF010").severity, Severity::Info);
    assert!(no_rule(&lint(array), "DF010"));
    assert!(no_rule(&lint(array), "DF060"));
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

#[test]
fn df011_is_an_info_level_advisory() {
    let findings = lint("FROM golang:1.26\nRUN go build ./...\n");
    assert_eq!(finding(&findings, "DF011").severity, Severity::Info);
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

#[test]
fn df014_reports_each_hardcoded_secret_and_ignores_identifier_names() {
    let df = "FROM alpine:3.19\nARG NEXTAUTH_SECRET=secret\nARG CALENDSO_ENCRYPTION_KEY=secret\nENV GITNESS_TOKEN_COOKIE_NAME=token HSM_TOKEN_LABEL=hydra HSM_PIN=1234\n";
    let findings: Vec<_> = lint(df)
        .into_iter()
        .filter(|finding| finding.rule == "DF014")
        .collect();
    assert_eq!(findings.len(), 3);
    assert!(findings
        .iter()
        .any(|finding| finding.message.contains("NEXTAUTH_SECRET")));
    assert!(findings
        .iter()
        .any(|finding| finding.message.contains("CALENDSO_ENCRYPTION_KEY")));
    assert!(findings
        .iter()
        .any(|finding| finding.message.contains("HSM_PIN")));
}

#[test]
fn df014_ignores_tokenizer_cache_configuration_and_public_posthog_keys() {
    let df = "FROM alpine:3.19\nENV TIKTOKEN_CACHE_DIR=/cache TOKENIZERS_PARALLELISM=false POSTHOG_TOKEN=phc_public\n";
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

#[test]
fn df020_clear_when_user_is_inherited_from_named_stage() {
    let df = "FROM scratch AS base\nUSER appuser\nFROM base\nCMD [\"/app\"]\n";
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
    assert_eq!(finding(&lint(df), "DF023").severity, Severity::Info);
}

#[test]
fn df023_clear_when_only_final_stage_has_no_alias() {
    let df = "FROM golang:1.21 AS builder\nRUN go build ./...\nFROM alpine:3.19\nCOPY --from=builder /go/bin/app /app\n";
    assert!(no_rule(&lint(df), "DF023"));
}

#[test]
fn df023_fires_when_an_intermediate_stage_has_no_alias() {
    let df = "FROM golang:1.21 AS builder\nFROM alpine:3.19\nRUN cp /go/bin/app /app\nFROM scratch\nCOPY --from=1 /app /app\n";
    let findings = lint(df);
    let finding = finding(&findings, "DF023");
    assert_eq!(finding.line, 2);
}

#[test]
fn df023_clear_when_all_have_aliases() {
    let df = "FROM golang:1.21 AS builder\nRUN go build ./...\nFROM alpine:3.19 AS final\nCOPY --from=builder /go/bin/app /app\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF023"));
}

#[test]
fn df023_clear_with_platform_flags_and_aliases() {
    let df = "FROM --platform=$BUILDPLATFORM node:26.5.0-alpine@sha256:abc123 AS restore\nFROM --platform=$BUILDPLATFORM restore AS migrate\n";
    assert!(no_rule(&lint(df), "DF023"));
}

// ─── DF026: COPY to filesystem root ──────────────────────────────────────────

#[test]
fn df026_fires_on_copy_to_root() {
    let df = "FROM alpine:3.19\nCOPY app/ /\n";
    assert!(has_rule(&lint(df), "DF026"));
}

#[test]
fn df026_ignores_an_explicit_single_file_copied_to_root() {
    let df = "FROM alpine:3.19\nCOPY docker-entrypoint.sh /\n";
    assert!(no_rule(&lint(df), "DF026"));
}

#[test]
fn df026_clear_on_copy_to_subdir() {
    let df = "FROM alpine:3.19\nCOPY app /app/\n";
    assert!(no_rule(&lint(df), "DF026"));
}

#[test]
fn df026_clear_when_root_is_source_but_destination_is_subdir() {
    let df = "FROM alpine:3.19 AS artifacts\nFROM alpine:3.19\nCOPY --from=artifacts / /usr/bin/\n";
    assert!(no_rule(&lint(df), "DF026"));
}

#[test]
fn df026_handles_json_copy_destination() {
    let root = "FROM alpine:3.19\nCOPY [\"app/\", \"/\"]\n";
    let subdir = "FROM alpine:3.19\nCOPY [\"app\", \"/opt/app/\"]\n";
    assert!(has_rule(&lint(root), "DF026"));
    assert!(no_rule(&lint(subdir), "DF026"));
}

#[test]
fn df026_ignores_scratch_and_cross_stage_root_composition() {
    let scratch = "FROM scratch\nCOPY rootfs /\n";
    let cross_stage =
        "FROM alpine:3.19 AS rootfs\nRUN touch /app\nFROM alpine:3.19\nCOPY --from=rootfs / /\n";
    assert!(no_rule(&lint(scratch), "DF026"));
    assert!(no_rule(&lint(cross_stage), "DF026"));
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

#[test]
fn df029_clear_when_apk_cache_is_buildkit_mounted() {
    let df = "# syntax=docker/dockerfile:1\nFROM alpine:3.19\nRUN --mount=type=cache,target=/var/cache/apk apk add curl\n";
    assert!(no_rule(&lint(df), "DF029"));
}

#[test]
fn df029_clear_when_apk_cache_is_removed_in_the_same_run() {
    let df = "FROM alpine:3.19\nRUN apk add curl && rm -rf /var/cache/apk/*\n";
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

#[test]
fn df031_clear_on_npm_global_install() {
    let df = "FROM node:20\nRUN npm install -g corepack@0.35.0 npm@12.0.1 npm-bundle@3.0.3\n";
    assert!(no_rule(&lint(df), "DF031"));
}

#[test]
fn df031_clear_on_prefixed_package_managers() {
    for command in ["pnpm install --frozen-lockfile", "cnpm install"] {
        let df = format!("FROM node:20\nRUN {command}\nCMD [\"node\", \"app.js\"]\n");
        assert!(
            no_rule(&lint(&df), "DF031"),
            "unexpected DF031 for {command}"
        );
    }
}

// ─── DF032: Python env vars missing ──────────────────────────────────────────

#[test]
fn df032_fires_on_python_without_env_vars() {
    let df =
        "FROM python:3.12\nRUN pip install --no-cache-dir flask\nCMD [\"python\", \"app.py\"]\n";
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

#[test]
fn df035_ignores_curl_as_a_package_name() {
    let df = "FROM ubuntu:24.04\nRUN apt-get install -y curl && echo https://example.com\n";
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

#[test]
fn df036_clear_when_command_is_inherited_from_named_stage() {
    let df = "FROM scratch AS base\nENTRYPOINT [\"/app\"]\nFROM base\nCOPY app /app\n";
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
fn df038_clear_on_one_cmd_per_stage() {
    let df =
        "FROM alpine:3.19 AS debug\nCMD [\"debug\"]\nFROM alpine:3.19 AS final\nCMD [\"app\"]\n";
    assert!(no_rule(&lint(df), "DF038"));
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

#[test]
fn df039_clear_on_one_entrypoint_per_stage() {
    let df = "FROM alpine:3.19 AS development\nENTRYPOINT [\"/dev\"]\nFROM alpine:3.19 AS production\nENTRYPOINT [\"/prod\"]\n";
    assert!(no_rule(&lint(df), "DF039"));
}

#[test]
fn df039_fires_only_for_duplicate_entrypoint_in_same_stage() {
    let df = "FROM alpine:3.19 AS development\nENTRYPOINT [\"/dev\"]\nFROM alpine:3.19 AS production\nENTRYPOINT [\"/first\"]\nENTRYPOINT [\"/second\"]\n";
    let findings = lint(df);
    let duplicates: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule == "DF039")
        .collect();
    assert_eq!(duplicates.len(), 1);
    assert_eq!(duplicates[0].line, 5);
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

#[test]
fn df045_clear_when_zypper_cache_paths_are_removed() {
    let df = "FROM opensuse/tumbleweed\nRUN zypper in -y curl && rm -rf /var/cache/zypp /var/cache/zypper\n";
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

#[test]
fn df046_accepts_clean_options_and_does_not_duplicate_df004() {
    let clean = "FROM registry.access.redhat.com/ubi9/ubi\nRUN dnf install -y curl && dnf clean --disableplugin=subscription-manager all\n";
    let dirty = "FROM fedora:latest\nRUN dnf install -y curl\n";
    assert!(no_rule(&lint(clean), "DF046"));
    let findings = lint(dirty);
    assert!(has_rule(&findings, "DF046"));
    assert!(no_rule(&findings, "DF004"));
}

#[test]
fn df046_recognizes_removed_rpm_cache_and_disposable_stages() {
    let removed = "FROM registry.access.redhat.com/ubi10/ubi-minimal\nRUN microdnf install -y tar && rm -rf /var/cache/yum\n";
    let disposable = "FROM fedora:latest AS build\nRUN dnf install -y tar\nFROM scratch\nCOPY --from=build /usr/bin/tar /tar\n";
    assert!(no_rule(&lint(removed), "DF004"));
    assert!(no_rule(&lint(removed), "DF046"));
    assert!(no_rule(&lint(disposable), "DF046"));
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

#[test]
fn df046_and_df047_clear_when_rpm_caches_are_ephemeral_mounts() {
    let dnf = "# syntax=docker/dockerfile:1\nFROM fedora:latest\nRUN --mount=type=tmpfs,target=/var/cache/dnf dnf install -y curl\n";
    let yum = "# syntax=docker/dockerfile:1\nFROM centos:7\nRUN --mount=type=cache,target=/var/cache/yum yum install -y curl\n";
    assert!(no_rule(&lint(dnf), "DF004"));
    assert!(no_rule(&lint(dnf), "DF046"));
    assert!(no_rule(&lint(yum), "DF004"));
    assert!(no_rule(&lint(yum), "DF047"));
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
fn df048_accepts_current_directory_as_a_multi_source_destination() {
    let shell = "FROM alpine:3.19\nWORKDIR /app\nCOPY go.mod go.sum .\n";
    let json = "FROM alpine:3.19\nWORKDIR /app\nCOPY [\"go.mod\", \"go.sum\", \".\"]\n";
    assert!(no_rule(&lint(shell), "DF048"));
    assert!(no_rule(&lint(json), "DF048"));
}

#[test]
fn df048_clear_on_two_arg_copy() {
    let df = "FROM alpine:3.19\nCOPY app.py /app/app.py\n";
    assert!(no_rule(&lint(df), "DF048"));
}

#[test]
fn df048_clear_on_quoted_json_destination_with_slash() {
    let df = "FROM alpine:3.19\nCOPY [\"package.json\", \"lock.json\", \"./\"]\n";
    assert!(no_rule(&lint(df), "DF048"));
}

#[test]
fn df048_fires_on_json_multi_source_without_destination_slash() {
    let df = "FROM alpine:3.19\nCOPY [\"package.json\", \"lock.json\", \"/app\"]\n";
    assert!(has_rule(&lint(df), "DF048"));
}

// ─── DF049: COPY --from undefined stage ──────────────────────────────────────

#[test]
fn df049_does_not_treat_external_images_as_undefined_stages() {
    let df = "FROM alpine:3.19\nCOPY --from=nonexistent /app /app\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF049"));
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
    let df =
        "FROM python:3.12\nRUN pip install --no-cache-dir flask\nCMD [\"python\", \"app.py\"]\n";
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

#[test]
fn df051_clear_on_local_pip_package() {
    let df = "FROM python:3.12\nRUN uv pip install --no-deps .\nCMD [\"python\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF051"));
}

#[test]
fn df051_clear_on_locally_built_wheels() {
    let df = "FROM python:3.12\nRUN pip3 install --no-cache-dir *.whl && rm -f *.whl\nCMD [\"python\", \"app.py\"]\n";
    assert!(no_rule(&lint(df), "DF051"));
}

#[test]
fn df051_still_fires_when_a_wheel_is_combined_with_an_unpinned_package() {
    let df = "FROM python:3.12\nRUN pip install flask *.whl\nCMD [\"python\", \"app.py\"]\n";
    assert!(has_rule(&lint(df), "DF051"));
}

#[test]
fn df051_accepts_local_archives_editable_directories_and_dist_globs() {
    for target in [
        "./package.tar.gz",
        "dist/text_generation_server*.tar.gz",
        "-e ./src/project",
        "/wheels/*.whl",
        "$(realpath dist/*.whl)",
    ] {
        let df = format!("FROM python:3.12\nRUN pip install {target}\n");
        assert!(
            no_rule(&lint(&df), "DF051"),
            "unexpected DF051 for {target}"
        );
    }
}

#[test]
fn df051_does_not_claim_dynamic_install_targets_are_unpinned() {
    let dynamic = "FROM python:3.12\nARG EXTRA_PIP_PACKAGES\nRUN [ -z \"$EXTRA_PIP_PACKAGES\" ] || pip install \"$EXTRA_PIP_PACKAGES\"\n";
    let local_with_index = "FROM python:3.12\nRUN uv pip install dist/*.whl --extra-index-url https://example.test/cu$(echo 12 | tr -d .)\n";
    assert!(no_rule(&lint(dynamic), "DF051"));
    assert!(no_rule(&lint(local_with_index), "DF051"));
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

#[test]
fn df052_clear_on_multiline_pinned_apk_install() {
    let df = "FROM alpine:3.21\nRUN apk add \\\n    bash=5.3.9-r1 \\\n    curl=8.21.0-r0 && \\\n    echo done\n";
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

#[test]
fn df054_clear_on_cargo_install() {
    let df = "FROM rust:1.80\nRUN cargo install --locked --path .\n";
    assert!(no_rule(&lint(df), "DF054"));
}

#[test]
fn df054_fires_on_go_install_after_a_shell_operator() {
    let df = "FROM golang:1.21\nRUN echo building && go install github.com/user/tool\n";
    assert!(has_rule(&lint(df), "DF054"));
}

#[test]
fn df054_accepts_module_managed_go_tool_install() {
    let df = "FROM golang:1.24\nCOPY go.mod go.sum ./\nRUN go install tool\n";
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

#[test]
fn df055_clear_when_yarn_cache_is_buildkit_mounted() {
    let df = "# syntax=docker/dockerfile:1\nFROM node:20\nRUN --mount=type=cache,target=/usr/local/share/.cache/yarn yarn install\n";
    assert!(no_rule(&lint(df), "DF055"));
}

#[test]
fn df055_respects_inline_yarn_cache_folder_mounts() {
    let df = "FROM node:20\nARG TARGETPLATFORM\nRUN --mount=type=cache,target=/root/.yarn/${TARGETPLATFORM} YARN_CACHE_FOLDER=/root/.yarn/${TARGETPLATFORM} yarn install\n";
    assert!(no_rule(&lint(df), "DF055"));
}

#[test]
fn df055_ignores_cache_in_a_selectively_copied_builder() {
    let df = "FROM node:20 AS build\nRUN yarn install\nRUN rm -rf .yarn/cache\nFROM node:20\nCOPY --from=build /app/node_modules /app/node_modules\n";
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
    let df =
        "FROM alpine:3.19\nRUN wget --progress=dot:giga https://example.com/file -O /tmp/file\n";
    assert!(no_rule(&lint(df), "DF056"));
}

#[test]
fn df056_accepts_no_verbose_wget_modes() {
    for option in ["-nv", "--no-verbose"] {
        let df = format!("FROM alpine:3.19\nRUN wget {option} https://example.com/file\n");
        assert!(no_rule(&lint(&df), "DF056"));
    }
}

#[test]
fn df056_and_df058_ignore_downloader_package_names() {
    let df = "FROM ubuntu:24.04\nRUN apt-get install -y curl wget && curl -fsSL https://example.com/file -o /tmp/file\n";
    let findings = lint(df);
    assert!(no_rule(&findings, "DF056"));
    assert!(no_rule(&findings, "DF058"));
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

#[test]
fn df057_clear_when_buildkit_flags_precede_pipefail() {
    let df = "FROM alpine:3.19\nRUN --mount=type=secret,id=.netrc set -euo pipefail; echo | cat\n";
    assert!(no_rule(&lint(df), "DF057"));
}

#[test]
fn df057_fires_when_set_options_omit_pipefail() {
    let df = "FROM debian:trixie\nRUN set -ex; \\\n+    grep ^root: /etc/passwd | \\\n+    cut -d: -f7\nRUN set -ex; \\\n+    grep ^root: /etc/passwd | cut -d: -f7\n";
    let findings: Vec<_> = lint(df)
        .into_iter()
        .filter(|finding| finding.rule == "DF057")
        .collect();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].line, 3);
    assert_eq!(findings[1].line, 6);
}

#[test]
fn df057_fires_on_pipelines_without_spaces_or_with_pipefail_text() {
    let df = "FROM alpine:3.19\nRUN printf pipefail|cat\n";
    assert!(has_rule(&lint(df), "DF057"));

    let substitution =
        "FROM debian:bookworm\nRUN arch=\"$(dpkg --print-architecture | awk -F- '{ print $NF }')\"\n";
    assert!(no_rule(&lint(substitution), "DF057"));
}

#[test]
fn df057_ignores_logical_or_and_literal_pipes() {
    let df = "FROM alpine:3.19\nRUN test -f /missing || echo 'not a | pipeline'\n";
    assert!(no_rule(&lint(df), "DF057"));
}

#[test]
fn df057_respects_combined_pipefail_options_and_later_disabling() {
    let protected = "FROM alpine:3.19\nRUN set -euo pipefail; printf ok|cat\n";
    assert!(no_rule(&lint(protected), "DF057"));

    let disabled = "FROM alpine:3.19\nRUN set -o pipefail; set +o pipefail; printf ok|cat\n";
    assert!(has_rule(&lint(disabled), "DF057"));

    let shell_disabled = "FROM alpine:3.19\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nRUN set +o pipefail; printf ok|cat\n";
    assert!(has_rule(&lint(shell_disabled), "DF057"));
}

#[test]
fn df057_clear_when_shell_instruction_enables_pipefail() {
    let df = "FROM ubuntu:24.04\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nRUN cat /etc/os-release | grep ID\n";
    assert!(no_rule(&lint(df), "DF057"));
}

#[test]
fn df057_clear_when_shell_instruction_uses_combined_pipefail_option() {
    let df = "FROM ubuntu:24.04\nSHELL [\"/bin/bash\", \"-opipefail\", \"-c\"]\nRUN cat /etc/os-release | grep ID\n";
    assert!(no_rule(&lint(df), "DF057"));
}

#[test]
fn df057_ignores_non_posix_shell_pipelines() {
    let df = "FROM mcr.microsoft.com/windows/servercore:ltsc2022\nSHELL [\"powershell\", \"-Command\", \"$ErrorActionPreference = 'Stop';\"]\nRUN New-Item -ItemType Directory C:/temp | Out-Null\n";
    assert!(no_rule(&lint(df), "DF057"));
}

#[test]
fn df057_reports_the_unprotected_pipe_token() {
    let df = "FROM ubuntu:24.04\nRUN set -ex; \\\n    value=$(printf ok \\\n      | sed s/o/a/)\n";
    let findings = lint(df);
    let finding = finding(&findings, "DF057");
    assert_eq!((finding.line, finding.column), (4, 7));
}

#[test]
fn df057_shell_pipefail_resets_at_next_stage() {
    let df = "FROM ubuntu:24.04 AS build\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nRUN cat /etc/os-release | grep ID\nFROM ubuntu:24.04\nRUN cat /etc/os-release | grep ID\n";
    let findings: Vec<_> = lint(df)
        .into_iter()
        .filter(|finding| finding.rule == "DF057")
        .collect();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 5);
}

#[test]
fn df057_inherits_pipefail_shell_from_named_stage() {
    let df = "FROM ubuntu:24.04 AS base\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nFROM base\nRUN cat /etc/os-release | grep ID\n";
    assert!(no_rule(&lint(df), "DF057"));
}

#[test]
fn df057_later_shell_without_pipefail_overrides_prior_shell() {
    let df = "FROM ubuntu:24.04\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nRUN cat /etc/os-release | grep ID\nSHELL [\"/bin/sh\", \"-c\"]\nRUN cat /etc/os-release | grep ID\n";
    let findings: Vec<_> = lint(df)
        .into_iter()
        .filter(|finding| finding.rule == "DF057")
        .collect();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 5);
}

#[test]
fn df057_does_not_duplicate_remote_execution_or_break_yes_pipelines() {
    let remote = "FROM ubuntu:24.04\nRUN curl -fsSL https://example.com/install.sh | bash\n";
    let expected_sigpipe = "FROM ubuntu:24.04\nRUN yes | unminimize\n";
    let remote_findings = lint(remote);
    assert!(has_rule(&remote_findings, "DF021"));
    assert!(no_rule(&remote_findings, "DF057"));
    assert!(no_rule(&lint(expected_sigpipe), "DF057"));
}

#[test]
fn df057_ignores_low_value_and_non_pipeline_shell_syntax() {
    for command in [
        "echo 'abc file' | sha256sum -c -",
        "echo root:root | chpasswd",
        "rm -f /tmp/missing | :",
        "case x in x86_64) true ;; arm64 | aarch64) true ;; esac",
        "{ echo one; echo two; } | tee /tmp/config",
        "arch=$(uname -m | sed s/x86_64/amd64/)",
        "value=$(echo abc | cut -c1 | tr a-z A-Z)",
        "echo \"$([ x = y ] || echo fallback)\"",
    ] {
        let df = format!("FROM ubuntu:24.04\nRUN {command}\n");
        assert!(
            no_rule(&lint(&df), "DF057"),
            "unexpected DF057 for {command}"
        );
    }
}

#[test]
fn df057_recognizes_inherited_powershell_syntax_and_maps_the_real_pipe() {
    let powershell = "FROM external/windows-base:latest\nRUN Invoke-WebRequest https://example.test/a | Out-File C:/a\n";
    assert!(no_rule(&lint(powershell), "DF057"));

    let mapped =
        "FROM ubuntu:24.04\nRUN test -f /x || true; \\\n    printf ok \\\n      | sed s/o/a/\n";
    let findings = lint(mapped);
    let finding = finding(&findings, "DF057");
    assert_eq!((finding.line, finding.column), (4, 7));
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

#[test]
fn df058_is_an_info_level_advisory() {
    let findings =
        lint("FROM alpine:3.19\nRUN wget https://a.test/file\nRUN curl https://b.test/file\n");
    assert_eq!(finding(&findings, "DF058").severity, Severity::Info);
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

#[test]
fn df059_ignores_apt_paths_keys_and_heredoc_comments() {
    let df = "FROM ubuntu:24.04\nRUN <<EOF\n#!/bin/bash\n# avoid apt update issues\necho /etc/apt/keyrings apt-key\nEOF\n";
    assert!(no_rule(&lint(df), "DF059"));
}

// ─── DF060: useless interactive commands ─────────────────────────────────────

#[test]
fn df060_fires_on_systemctl() {
    let df = "FROM ubuntu:22.04\nRUN systemctl start nginx\n";
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

#[test]
fn df060_ignores_package_names_paths_version_checks_and_symlink_targets() {
    for command in [
        "apt-get install -y vim",
        "/usr/bin/mount --version",
        "ln -s init /rootfs/usr/bin/shutdown",
        "mkdir -p /home/app/.ssh",
    ] {
        let df = format!("FROM ubuntu:24.04\nRUN {command}\n");
        assert!(
            no_rule(&lint(&df), "DF060"),
            "unexpected DF060 for {command}"
        );
    }
}

#[test]
fn df060_accepts_offline_service_configuration_and_database_initialization() {
    let systemd =
        "FROM ubuntu:24.04\nRUN systemctl enable kubelet && systemctl mask systemd-binfmt\n";
    let database =
        "FROM ubuntu:24.04\nRUN service postgresql start && su postgres -c \"psql -c 'SELECT 1'\"\n";
    assert!(no_rule(&lint(systemd), "DF060"));
    assert!(no_rule(&lint(database), "DF060"));
}

#[test]
fn df060_ignores_commands_named_inside_shell_arrays() {
    let df = "FROM ubuntu:24.04\nRUN packages=(\n    curl\n    ssh\n    vim\n)\n";
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

#[test]
fn df061_clear_for_native_build_stage() {
    let df = "FROM --platform=$BUILDPLATFORM node:22 AS builder\nRUN npm run build\nFROM nginx:1.27\nCOPY --from=builder /app/dist /usr/share/nginx/html\n";
    assert!(no_rule(&lint(df), "DF061"));
}

#[test]
fn df061_clear_for_braced_native_build_stage() {
    let df = "FROM --platform=${BUILDPLATFORM} node:22 AS builder\nRUN npm run build\nFROM nginx:1.27\nCOPY --from=builder /app/dist /usr/share/nginx/html\n";
    assert!(no_rule(&lint(df), "DF061"));
}

#[test]
fn df061_fires_when_final_stage_uses_buildplatform() {
    let df = "FROM alpine:3.19 AS helper\nRUN echo helper\nFROM --platform=$BUILDPLATFORM alpine:3.19\nCMD [\"/bin/sh\"]\n";
    assert!(has_rule(&lint(df), "DF061"));
}

// ENV references retain values inherited from the base image or earlier layers.

#[test]
fn env_path_append_is_not_reported() {
    // VAR=$VAR:suffix — self-reference at the start of the value
    let df = "FROM alpine:3.19\nENV PATH=$PATH:/usr/local/bin\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn env_self_reference_is_not_reported() {
    // VAR=$VAR — bare self-assignment
    let df = "FROM alpine:3.19\nENV MY_VAR=$MY_VAR\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn quoted_env_self_reference_is_not_reported() {
    // VAR="$VAR" — quoted self-assignment
    let df = "FROM alpine:3.19\nENV PATH=\"$PATH\"\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn env_normal_assignment_is_not_reported() {
    let df = "FROM alpine:3.19\nENV MYAPP_PATH=/usr/local/bin\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn env_path_append_with_another_variable_is_not_reported() {
    // VAR="prefix:$OTHER_VAR" — extending PATH using a different previously-set variable
    let df = "FROM python:3.13-slim\nENV VENV=/opt/venv/bin\nENV PATH=\"$VENV:$PATH\"\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn env_reference_to_another_variable_is_not_reported() {
    // BAZ=$FOO — referencing a different variable
    let df = "FROM alpine:3.19\nENV FOO=bar\nENV BAZ=$FOO\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn env_arg_promotion_is_not_reported() {
    let df = "FROM alpine:3.19\nARG MY_VARIABLE\nENV MY_VARIABLE=${MY_VARIABLE}\n";
    assert!(no_rule(&lint(df), "DF062"));
}

#[test]
fn global_arg_env_promotion_is_not_reported() {
    let df = "ARG MY_VARIABLE\nFROM alpine:3.19\nENV MY_VARIABLE=${MY_VARIABLE}\n";
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

#[test]
fn df063_clear_on_quoted_or_variable_absolute_destination() {
    let quoted = "FROM alpine:3.19\nCOPY app.py \"/opt/app.py\"\n";
    let variable = "FROM alpine:3.19\nARG DEST=/opt/app.py\nCOPY app.py \"${DEST}\"\n";
    assert!(no_rule(&lint(quoted), "DF063"));
    assert!(no_rule(&lint(variable), "DF063"));
}

#[test]
fn df063_accepts_windows_absolute_copy_destinations() {
    for destination in ["C:/app/program.exe", "C:\\\\app\\\\program.exe"] {
        let df = format!(
            "FROM mcr.microsoft.com/windows/nanoserver:ltsc2022\nCOPY program.exe {destination}\n"
        );
        assert!(
            no_rule(&lint(&df), "DF063"),
            "unexpected DF063 for {destination}"
        );
    }
}

#[test]
fn df063_clear_when_workdir_is_inherited_from_previous_stage() {
    let df = "FROM node:26.5.0-alpine@sha256:abc123 AS restore\nWORKDIR /tmp/foo/bar\nCOPY Dockerfile .\nFROM restore AS migrate\nCOPY Dockerfile .\n";
    assert!(no_rule(&lint(df), "DF063"));
}

#[test]
fn df063_is_informational_when_external_workdir_metadata_is_unknown() {
    let findings = lint("FROM external/image:1\nCOPY app.py app.py\n");
    assert_eq!(finding(&findings, "DF063").severity, Severity::Info);
}

// ─── DF064: useradd without -l ────────────────────────────────────────────────

#[test]
fn df064_fires_on_useradd_without_l() {
    let df = "FROM ubuntu:22.04\nRUN useradd --uid 100000 appuser\n";
    assert!(has_rule(&lint(df), "DF064"));
}

#[test]
fn df064_ignores_default_normal_and_unknown_uids() {
    for command in [
        "useradd appuser",
        "useradd --uid 1000 appuser",
        "useradd -u 1500 appuser",
        "useradd --uid $APP_UID appuser",
    ] {
        let df = format!("FROM ubuntu:22.04\nRUN {command}\n");
        assert!(
            no_rule(&lint(&df), "DF064"),
            "unexpected DF064 for {command}"
        );
    }
}

#[test]
fn df064_clear_on_useradd_with_l() {
    let df = "FROM ubuntu:22.04\nRUN useradd -l --uid 100000 appuser\n";
    assert!(no_rule(&lint(df), "DF064"));
}

#[test]
fn df064_clear_on_useradd_with_no_log_init() {
    let df = "FROM ubuntu:22.04\nRUN useradd --no-log-init --uid 100000 appuser\n";
    assert!(no_rule(&lint(df), "DF064"));
}

// ─── DF065: configured registry policy ──────────────────────────────────────

#[test]
fn df065_is_inactive_without_an_approved_registry_policy() {
    let df = "FROM myregistry.internal.example.com/myimage:1.0\nCMD [\"/app\"]\n";
    assert!(no_rule(&lint(df), "DF065"));
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

#[test]
fn df065_clear_on_docker_hardened_images_registry() {
    let df = "FROM dhi.io/python:3.14\nCMD [\"python\"]\n";
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

#[test]
fn df066_clear_when_bash_c_owns_the_bash_syntax() {
    let df = "FROM ubuntu:22.04\nRUN bash -c \"source $NVM_DIR/nvm.sh && make html\"\n";
    assert!(no_rule(&lint(df), "DF066"));
}

#[test]
fn df066_still_fires_on_bash_syntax_outside_bash_c() {
    let df = "FROM ubuntu:22.04\nRUN bash -c \"echo ready\" && source /etc/profile\n";
    assert!(has_rule(&lint(df), "DF066"));
}

#[test]
fn df066_does_not_confuse_source_paths_or_mount_options_with_builtin() {
    let mount = "# syntax=docker/dockerfile:1\nFROM alpine:3.19\nRUN --mount=type=bind,source=/src,target=/src make\n";
    let path = "FROM alpine:3.19\nRUN mkdir -p gpg/source && cp key gpg/source/key\n";
    assert!(no_rule(&lint(mount), "DF066"));
    assert!(no_rule(&lint(path), "DF066"));
}

#[test]
fn df066_respects_a_bash_shebang_in_run_heredocs() {
    let df = "FROM ubuntu:24.04\nRUN <<'SCRIPT'\n#!/bin/bash\nif [[ -f /tmp/x ]]; then source /etc/profile; fi\nSCRIPT\n";
    assert!(no_rule(&lint(df), "DF066"));
}

#[test]
fn df066_tracks_shell_per_stage_and_through_named_inheritance() {
    let unrelated = "FROM ubuntu:24.04 AS bash-stage\nSHELL [\"/bin/bash\", \"-c\"]\nRUN source /etc/profile\nFROM ubuntu:24.04\nRUN source /etc/profile\n";
    let inherited = "FROM ubuntu:24.04 AS bash-stage\nSHELL [\"/bin/bash\", \"-c\"]\nFROM bash-stage\nRUN source /etc/profile\n";
    assert!(has_rule(&lint(unrelated), "DF066"));
    assert!(no_rule(&lint(inherited), "DF066"));
}

// ─── DF067: reserved; archive handling is context-dependent ─────────────────

#[test]
fn df067_does_not_recommend_add_for_explicit_archive_handling() {
    let df = "FROM alpine:3.19\nCOPY app.tar.gz /tmp/\n";
    assert!(no_rule(&lint(df), "DF067"));
}

#[test]
fn df067_does_not_replace_verified_or_custom_extraction_with_add() {
    let df = "FROM alpine:3.19\nCOPY dist.tgz /tmp/dist.tgz\nRUN sha256sum -c dist.tgz.sha256 && tar -xzf /tmp/dist.tgz --strip-components=1 -C /opt\n";
    assert!(no_rule(&lint(df), "DF067"));
}

#[test]
fn df067_clear_on_copy_of_non_archive() {
    let df = "FROM alpine:3.19\nCOPY app.py /app/\n";
    assert!(no_rule(&lint(df), "DF067"));
}

#[test]
fn df067_clear_on_copy_from_stage() {
    let df =
        "FROM alpine:3.19 AS builder\nFROM alpine:3.19\nCOPY --from=builder /app.tar.gz /tmp/\n";
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

// ─── DF069: apt-get upgrade ───────────────────────────────────────────────────

#[test]
fn df069_fires_on_apt_get_upgrade() {
    let df = "FROM ubuntu:22.04\nRUN apt-get update && apt-get upgrade -y\n";
    assert!(has_rule(&lint(df), "DF069"));
}

#[test]
fn df069_fires_on_apt_get_dist_upgrade() {
    let df = "FROM ubuntu:22.04\nRUN apt-get dist-upgrade -y\n";
    assert!(has_rule(&lint(df), "DF069"));
}

#[test]
fn df069_fires_on_apt_upgrade() {
    let df = "FROM ubuntu:22.04\nRUN apt upgrade -y\n";
    assert!(has_rule(&lint(df), "DF069"));
}

#[test]
fn df069_clear_on_apt_get_install_only() {
    let df = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n";
    assert!(no_rule(&lint(df), "DF069"));
}

// ─── DF070: COPY . before package install ────────────────────────────────────

#[test]
fn df070_fires_on_copy_dot_before_npm_install() {
    let df = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm install\n";
    assert!(has_rule(&lint(df), "DF070"));
}

#[test]
fn df070_fires_on_copy_dot_before_pip_install() {
    let df = "FROM python:3.12\nWORKDIR /app\nCOPY . /app\nRUN pip install -r requirements.txt\n";
    assert!(has_rule(&lint(df), "DF070"));
}

#[test]
fn df070_clear_on_copy_dot_after_install() {
    let df = "FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN npm install\nCOPY . .\n";
    assert!(no_rule(&lint(df), "DF070"));
}

#[test]
fn df070_clear_on_specific_copy_before_install() {
    let df = "FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\nCOPY src ./src\n";
    assert!(no_rule(&lint(df), "DF070"));
}

#[test]
fn df070_clear_on_copy_before_local_pip_install() {
    let df = "FROM python:3.12\nWORKDIR /app\nCOPY . /app\nRUN uv pip install --no-deps .\n";
    assert!(no_rule(&lint(df), "DF070"));
}

// ─── DF071: parser syntax diagnostics ────────────────────────────────────────

#[test]
fn df071_fires_on_unknown_instruction() {
    let findings = lint("FROM alpine:3.20\nRNU echo typo\n");
    let finding = findings
        .iter()
        .find(|finding| finding.rule == "DF071")
        .expect("syntax finding");

    assert_eq!(finding.line, 2);
    assert!(finding
        .message
        .contains("unknown Dockerfile instruction RNU"));
}

#[test]
fn df071_fires_on_unterminated_heredoc() {
    let findings = lint("FROM alpine:3.20\nRUN <<EOF\necho incomplete\n");
    assert!(findings.iter().any(|finding| {
        finding.rule == "DF071" && finding.message.contains("unterminated heredoc")
    }));
}

#[test]
fn df071_keeps_recoverable_parser_warnings_as_warnings() {
    let dockerfile = concat!("FROM alpine:3.20 \\", "\n", "\n", "RUN echo ok\n");
    let findings = lint(dockerfile);
    let finding = findings
        .iter()
        .find(|finding| finding.rule == "DF071")
        .expect("continuation warning");

    assert_eq!(finding.severity, dockerfile_roast::rules::Severity::Warning);
}

#[test]
fn df071_does_not_treat_heredoc_script_as_dockerfile_syntax() {
    let findings = lint(
        "FROM alpine:3.20\nRUN <<EOF\nFROM this is shell text\nRUN echo shell text\nEOF\nCMD [\"sh\"]\n",
    );
    assert!(no_rule(&findings, "DF071"));
}

#[test]
fn shell_rules_inspect_run_heredoc_contents() {
    let findings =
        lint("FROM ubuntu:24.04\nRUN <<SCRIPT\napt-get update\napt-get install curl\nSCRIPT\n");

    assert!(has_rule(&findings, "DF015"));
    assert!(has_rule(&findings, "DF016"));
    assert!(no_rule(&findings, "DF071"));
}

// ─── Docker build-check compatibility ───────────────────────────────────────

#[test]
fn docker_casing_checks_report_token_spans() {
    let findings = lint("FROM alpine:3.20 as Build\nrun true\nEXPOSE 8080/TCP\n");
    let instruction = finding(&findings, "DF076");
    assert_eq!(
        (instruction.line, instruction.column, instruction.end_line),
        (2, 1, 2)
    );
    let as_keyword = finding(&findings, "DF079");
    assert_eq!((as_keyword.line, as_keyword.column), (1, 18));
    let protocol = finding(&findings, "DF078");
    assert_eq!((protocol.line, protocol.column), (3, 8));
}

#[test]
fn docker_key_value_and_stage_checks_accept_modern_forms() {
    let findings = lint("FROM --platform=$BUILDPLATFORM alpine:3.20 AS build\nENV NAME=value\nLABEL org.opencontainers.image.title=droast\n");
    assert!(no_rule(&findings, "DF082"));
    assert!(no_rule(&findings, "DF083"));
    assert!(no_rule(&findings, "DF084"));
    assert!(no_rule(&findings, "DF085"));

    let findings = lint("FROM --platform=$TARGETPLATFORM alpine:3.20 AS Build\nENV NAME value\n");
    assert!(has_rule(&findings, "DF082"));
    assert!(has_rule(&findings, "DF083"));
    assert!(has_rule(&findings, "DF085"));
}

#[test]
fn df084_is_a_warning_for_the_reserved_scratch_alias() {
    let findings = lint("FROM scratch AS scratch\nCOPY app /app\n");
    assert_eq!(finding(&findings, "DF084").severity, Severity::Warning);
}

#[test]
fn docker_variable_checks_distinguish_declared_and_undefined_variables() {
    let findings = lint("ARG TAG=3.20\nFROM scratch AS build\nCOPY ${MISSING} /app/\n");
    assert!(no_rule(&findings, "DF086"));
    assert!(has_rule(&findings, "DF087"));

    let findings = lint("FROM alpine:${TAG}\n");
    assert!(has_rule(&findings, "DF086"));
}

#[test]
fn df087_accounts_for_named_stage_and_unknown_external_base_environment() {
    let inherited = "FROM scratch AS base\nENV APP_ROOT=/app\nFROM base\nCOPY app ${APP_ROOT}/\n";
    let external = "FROM public.example/runtime:1\nCOPY app ${RUNTIME_ROOT}/\n";
    assert!(no_rule(&lint(inherited), "DF087"));
    assert!(no_rule(&lint(external), "DF087"));
}

#[test]
fn every_rule_has_known_categories() {
    for rule in all_rules() {
        assert!(
            !rule.categories().is_empty(),
            "{} has no categories",
            rule.id
        );
        for category in rule.categories() {
            assert!(
                ALL_CATEGORIES.contains(category),
                "{} has unknown category {}",
                rule.id,
                category
            );
        }
    }
}

#[test]
fn broad_advisory_rules_are_info_severity() {
    let cases = [
        ("DF020", "FROM alpine:3.19\nCMD [\"app\"]\n"),
        ("DF036", "FROM alpine:3.19\nWORKDIR /app\nCOPY app .\n"),
        ("DF052", "FROM alpine:3.19\nRUN apk add --no-cache curl\n"),
        (
            "DF061",
            "FROM --platform=linux/amd64 alpine:3.19\nCMD [\"sh\"]\n",
        ),
        ("DF082", "FROM alpine:3.19\nENV NAME value\n"),
    ];
    for (rule, dockerfile) in cases {
        assert_eq!(finding(&lint(dockerfile), rule).severity, Severity::Info);
    }
}
