# droast documentation

droast is an opinionated Dockerfile linter. It checks security, correctness, reproducibility, image size, cache use, package installation, and runtime behavior.

Use this guide as a quick reference. Every section favors copy-paste examples over long explanations.

## Table of contents

- [Quick start](#quick-start)
- [Install](#install)
- [What droast understands](#what-droast-understands)
- [Command line reference](#command-line-reference)
- [Repository discovery](#repository-discovery)
- [Effective build invocations](#effective-build-invocations)
- [Configuration](#configuration)
- [Hadolint replacement mode](#hadolint-replacement-mode)
- [Custom messages](#custom-messages)
- [Copy-paste presets](#copy-paste-presets)
- [Control rules and severity](#control-rules-and-severity)
- [Safe deterministic fixes](#safe-deterministic-fixes)
- [Output formats](#output-formats)
- [CI integration](#ci-integration)
- [Local development workflows](#local-development-workflows)
- [Docker and container usage](#docker-and-container-usage)
- [Wasmer and WASI](#wasmer-and-wasi)
- [VS Code](#vs-code)
- [Web version](#web-version)
- [Rust library](#rust-library)
- [Parser API](#parser-api)
- [Rule catalog](#rule-catalog)
- [Adoption recipes](#adoption-recipes)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

## Quick start

Lint one Dockerfile:

```bash
droast Dockerfile
```

Lint every supported Dockerfile in a repository:

```bash
droast .
```

Lint the current repository:

```bash
droast
```

Show warnings and errors only:

```bash
droast --min-severity warning .
```

Use technical messages without the roast text:

```bash
droast --no-roast .
```

Start with a configuration file:

```bash
droast init
droast .
```

List every rule:

```bash
droast --list-rules
```

Get the rule list as JSON:

```bash
droast --list-rules --format json | jq .
```

## Install

### Install script

Linux and macOS:

```bash
curl -fsL https://ewry.net/droast/install.sh | sh
```

Verify the installation:

```bash
droast --version
droast --help
```

### Homebrew

```bash
brew tap immanuwell/droast https://github.com/immanuwell/homebrew-droast.git
brew install immanuwell/droast/droast
```

Upgrade later:

```bash
brew update
brew upgrade droast
```

### Cargo

Rust users can install from crates.io:

```bash
cargo install dockerfile-roast
```

The installed executable is named `droast`.

Upgrade by reinstalling:

```bash
cargo install dockerfile-roast --force
```

### GitHub release binaries

Download the archive for your platform from [GitHub Releases](https://github.com/immanuwell/dockerfile-roast/releases).

The release includes Linux, macOS, and Windows builds. Put the extracted executable on your `PATH`.

### Container image

```bash
docker pull immanuwell/droast:1.4.5
```

Use a fixed version in CI. Use `latest` only when automatic upgrades are acceptable.

The identical image is also published to `ghcr.io/immanuwell/droast`; choose the registry that is most convenient for your environment.

The image is OCI-compatible and can also be run with Podman:

```bash
podman run --rm -v "$PWD:/workspace:Z" -w /workspace \
  ghcr.io/immanuwell/droast:1.4.5 --engine podman .
```

Use `:Z` for a private SELinux relabel of the mounted repository. On systems without SELinux it is harmless to omit the suffix.

### Wasmer package

Run droast as a sandboxed WASI command from the [Wasmer Registry](https://wasmer.io/immanuwell/droast):

```bash
wasmer run immanuwell/droast -- --check-dockerignore=false - < Dockerfile
```

No host files are visible unless you explicitly mount them. To lint a repository:

```bash
wasmer run --volume "$PWD:/workspace" immanuwell/droast -- /workspace
```

Use a fixed package version in CI:

```bash
wasmer run --volume "$PWD:/workspace" immanuwell/droast@1.4.5 -- /workspace
```

When the repository uses configuration, pass its mounted path explicitly:

```bash
wasmer run --volume "$PWD:/workspace" immanuwell/droast -- \
  --config /workspace/droast.toml /workspace
```

### Install the VS Code extension

```bash
code --install-extension ImmanuelTikhonov.droast
```

See [VS Code](#vs-code) for settings.

## What droast understands

droast uses a span-aware Dockerfile parser. It is not limited to one instruction per physical line.

### Standard and modern syntax

It understands:

- shell and JSON instruction forms
- line continuations
- quoted and unquoted values
- variable references and modifiers
- multi-stage builds
- parser directives
- BuildKit instruction flags
- heredocs
- Windows paths
- PowerShell commands
- CRLF and UTF-8 input
- malformed syntax with recoverable diagnostics

### Parser directives

Syntax and escape directives are preserved:

```dockerfile
# syntax=docker/dockerfile:1.7
# escape=\

FROM alpine:3.20
```

Windows Dockerfiles can change the escape character:

```dockerfile
# escape=`

FROM mcr.microsoft.com/windows/nanoserver:ltsc2022
SHELL ["powershell", "-Command"]
RUN Write-Host `
    "building"
```

### BuildKit flags

Flags are parsed separately from the command:

```dockerfile
# syntax=docker/dockerfile:1.7
FROM rust:1.79 AS build
WORKDIR /src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release
```

This includes flags such as:

- `RUN --mount`
- `RUN --network`
- `RUN --security`
- `RUN --device`
- `COPY --from`
- `COPY --chown`
- `COPY --chmod`
- newer flags that use normal BuildKit flag syntax

### Heredocs

Heredoc content is part of the parsed instruction. Shell-oriented rules inspect the executed script too.

```dockerfile
# syntax=docker/dockerfile:1.7
FROM alpine:3.20
RUN <<'SCRIPT'
set -eu
apk add --no-cache curl
curl --fail --location https://example.com/health
SCRIPT
```

Quoted delimiters, tab-stripping heredocs, multiple heredocs, and file descriptors are represented by the parser.

### Exact locations and syntax errors

Instructions, flags, words, variables, heredocs, and diagnostics carry source spans. CLI findings use source line numbers. Invalid Dockerfile syntax is reported by `DF071` when parsing can continue safely.

## Command line reference

```text
droast [OPTIONS] [FILE]... [COMMAND]
```

### Inputs

Pass files, directories, or both:

```bash
droast Dockerfile services/api/Dockerfile
droast services/
droast . Dockerfile.release
```

Quoted glob patterns are also supported:

```bash
droast 'services/*/Dockerfile'
droast 'images/*.Dockerfile'
```

With no input, droast discovers supported files from the current directory:

```bash
droast
```

Lint standard input:

```bash
printf 'FROM alpine:latest\n' | droast -
```

### Options

| Option | Purpose |
|---|---|
| `--config PATH` | Load an explicit TOML configuration |
| `--messages PATH` | Load optional terminal message overrides from YAML |
| `--shellcheck MODE` | ShellCheck bridge: `off`, `auto`, or `required` |
| `--preset NAME` | Apply `minimal`, `security`, `performance`, `production`, or `strict` |
| `--category NAMES` | Run comma-separated rule categories |
| `--skip-category NAMES` | Skip comma-separated rule categories |
| `-f, --format FORMAT` | Select `terminal`, `json`, `github`, `compact`, or `sarif`; `diff` is available for fix previews |
| `--fix [IDS]` | Apply all safe deterministic fixes, or only the optional comma-separated rule IDs |
| `--dry-run` | Plan `--fix` edits without changing files |
| `-s, --min-severity LEVEL` | Select `info`, `warning`, or `error` |
| `--fail-on LEVEL` | Exit unsuccessfully for findings at or above `info`, `warning`, or `error` |
| `--skip IDS` | Skip comma-separated rule IDs |
| `--only IDS` | Run only comma-separated rule IDs |
| `--no-roast` | Show technical messages only |
| `--check-ignorefile BOOL` | Enable or disable effective build-context ignore-file checks (`--check-dockerignore` remains an alias) |
| `--engine NAME` | Build-context conventions: `docker` (default) or `podman` |
| `--no-fail` | Always exit successfully after linting |
| `--list-rules` | Print the available rules |
| `-h, --help` | Print help |
| `-V, --version` | Print the version |

### Commands

Create `droast.toml` in the current directory:

```bash
droast init
```

Import a Hadolint YAML configuration instead. With no path, this reads `.hadolint.yaml` from the current directory:

```bash
droast init --from-hadolint
droast init --from-hadolint .config/hadolint.yml
```

Generate shell completion output:

```bash
droast completion bash
droast completion zsh
droast completion fish
```

Example for Bash:

```bash
mkdir -p ~/.local/share/bash-completion/completions
droast completion bash > ~/.local/share/bash-completion/completions/droast
```

Example for Fish:

```fish
droast completion fish > ~/.config/fish/completions/droast.fish
```

### Exit status

| Code | Meaning |
|---|---|
| `0` | No error-severity findings, or `--no-fail` was used |
| `1` | At least one error-severity finding or an execution failure occurred |

Warnings alone do not produce exit code `1`. Use output review or a chosen rule set when warnings must block a workflow.

## Repository discovery

`droast .` recursively discovers:

- `Dockerfile`
- `Dockerfile.*`
- `*.Dockerfile`
- `*.dockerfile`
- `Containerfile`
- `Containerfile.*`
- Dockerfiles referenced by Compose files
- Dockerfiles referenced by Bake HCL or JSON files

With `--engine podman`, discovery also follows Quadlet `.build` units, Quadlet `.kube` units, and `kube.yaml`/`*.kube.yaml` manifests that use Podman’s local-image directory layout. Remote build contexts and image references remain out of scope because they do not identify a local Containerfile to lint.

Use `--engine podman` when linting a Podman build workflow. This preserves the shared Dockerfile rules while making DF033 select `.containerignore` before `.dockerignore`.

Duplicate references are linted once.

### Compose awareness

Given:

```yaml
services:
  api:
    build:
      context: ./services/api
      dockerfile: Dockerfile.production
  worker:
    build: ./services/worker
```

Running this from the repository root:

```bash
droast .
```

resolves both build contexts and both Dockerfiles. Compose `.env` values are used for supported path interpolation.

### Bake awareness

Given `docker-bake.hcl`:

```hcl
variable "SERVICE" {
  default = "api"
}

target "base" {
  context = "./services/${SERVICE}"
}

target "release" {
  inherits = ["base"]
  dockerfile = "Dockerfile.release"
}
```

droast resolves variables, inherited targets, local build contexts, and Dockerfile paths.

Remote Compose or Bake contexts are not downloaded. droast reports local files it can resolve.

## Effective build invocations

Inspect the actual build variants represented by a repository without contacting a container daemon or the network:

```bash
droast invocations .
droast invocations --format json .
```

Directly discovered Dockerfiles receive a default invocation. Compose services add effective arguments (map and list forms), targets, platforms, additional contexts, secrets, SSH, caches, and outputs. `.env` is loaded before the process environment, and null inherited values remain unresolved when no environment value exists. Bake targets add variables, inheritance, matrices, named contexts, caches, exporters, and attestations. Cyclic inheritance and conflicting parent values are reported instead of being hidden.

Every value has ordered provenance and one of three states: `resolved`, `unresolved`, or `redacted`. An unresolved expression is never substituted with an empty string. Sensitive build-argument values are never serialized. Different targets, arguments, platforms, or contexts produce different stable invocation IDs even when they use the same Dockerfile. Dockerfile-specific ignore files and Docker/Podman ignore precedence are reflected in `effective_ignore_file`.

The JSON document is deterministic and versioned independently of normal lint output. Its contract is [`schemas/droast-build-invocations-v1.schema.json`](schemas/droast-build-invocations-v1.schema.json). The Rust `invocation::lint` API evaluates findings per resolved invocation and merges them only when both the finding fingerprint and all effective inputs match, retaining every contributing invocation ID.

### Repository ignore rules

Recursive discovery respects repository ignore rules so generated or vendored trees are not scanned accidentally. Explicitly requested Dockerfiles are still handled as direct inputs.

### Effective `.dockerignore`

`DF033` checks the ignore file that Docker would use for each build context.

For this build:

```bash
docker build -f docker/release.Dockerfile .
```

droast checks in this order:

1. `docker/release.Dockerfile.dockerignore`
2. `.dockerignore` in the build context

A Dockerfile-specific ignore file takes precedence. Missing, empty, comment-only, and negation-only files are considered ineffective.

Recommended starting point:

```dockerignore
.git
.env
.env.*
node_modules
target
dist
coverage
*.log
```

Disable the check for an unusual workflow:

```bash
droast --check-ignorefile false .
```

## Configuration

Configuration is optional. The file name is `droast.toml`.

### Import Hadolint configuration

`droast init --from-hadolint [PATH]` converts compatible Hadolint YAML settings into a new `droast.toml`. It imports `ignored`, severity `override` entries, `trustedRegistries`, label schemas, `strict-labels`, `no-fail`, `disable-ignore-pragma`, supported output formats, and failure thresholds. Hadolint `DL` rules with equivalent Droast checks are translated to `DF` IDs; a single Hadolint rule can map to more than one Droast rule.

The command prints unmapped rules and settings to stderr and leaves them out of the generated policy. Review those messages before committing: ShellCheck rules, Hadolint-only checks, and unsupported output formats intentionally do not become silent policy changes.

### Complete example

```toml
preset = "production"
no-roast = true

require-suppression-reason = true
suppression-reason-pattern = "^(SEC|PLAT)-[0-9]+ .+$"
require-suppression-expiration = true
max-suppression-days = 90
report-unused-suppressions = true

approved-registries = ["docker.io", "ghcr.io", "registry.example.com"]
approved-base-images = ["alpine:3.*", "registry.example.com/platform/*@sha256:*"]

[severity-overrides]
DF001 = "error"
DF020 = "error"
DF065 = "error"

[shellcheck]
mode = "auto"
exclude = ["SC2086"]

[workflow]
engine = "podman"

[required-labels]
"org.opencontainers.image.source" = "url"
"org.opencontainers.image.version" = "semver"
"org.opencontainers.image.revision" = "hash"
"org.opencontainers.image.licenses" = "spdx"

[[overrides]]
paths = ["**/Dockerfile.dev", "**/Dockerfile.test"]
skip = ["DF012", "DF022"]
```

See [`examples/droast-enterprise.toml`](examples/droast-enterprise.toml) for a complete copy-paste starting point.

### Configuration keys

| Key | Type | Values |
|---|---|---|
| `skip` | array of strings | Rule IDs such as `DF012` |
| `extends` | string or array | Local configuration files to inherit |
| `preset` | string | Built-in preset name |
| `min-severity` | string | `info`, `warning`, `error` |
| `fail-on` | string | `info`, `warning`, `error`; findings at or above this level fail the run |
| `categories` | array | Run matching rule categories |
| `skip-categories` | array | Skip matching rule categories |
| `severity-overrides` | table | Change individual rule severities |
| `inline-suppressions` | boolean | Allow governed suppression comments |
| `require-suppression-reason` | boolean | Require a non-empty reason |
| `suppression-reason-pattern` | string | Validate reasons with a regular expression |
| `require-suppression-expiration` | boolean | Require `expires=YYYY-MM-DD` |
| `max-suppression-days` | integer | Limit exception lifetime |
| `report-unused-suppressions` | boolean | Report stale exceptions |
| `approved-registries` | array | Registry allowlist with glob support |
| `extend-approved-registries` | array | Add to the inherited registry allowlist |
| `approved-base-images` | array | Base-image allowlist with glob support |
| `extend-approved-base-images` | array | Add to the inherited image allowlist |
| `required-labels` | table | Required label names and formats |
| `strict-labels` | boolean | Reject labels outside the schema |
| `shellcheck.mode` | string | `off` (default), `auto`, `required` |
| `shellcheck.exclude` | array | ShellCheck IDs to suppress, such as `SC2086` |
| `workflow.engine` | string | `docker` (default), `podman` |
| `overrides` | array of tables | Apply settings to matching paths |
| `no-roast` | boolean | `true`, `false` |
| `no-fail` | boolean | `true`, `false` |
| `format` | string | `terminal`, `json`, `github`, `compact`, `sarif` |

Unknown keys are rejected. This catches misspelled configuration early.

Unknown rule IDs, categories, severities, presets, label formats, regular expressions, inheritance cycles, and glob patterns are also rejected. CI does not silently continue with a broken policy.

### ShellCheck bridge

Droast can delegate shell analysis to an installed `shellcheck` executable. It runs ShellCheck independently for each shell-form `RUN`, honors `SHELL` instructions that select `sh`, `ash`, `bash`, `dash`, or `ksh`, and analyzes BuildKit script heredocs. Findings retain their native `SC####` IDs in terminal, JSON, and SARIF output and are mapped back to Dockerfile locations.

`off` is the default and makes no external call. `auto` runs ShellCheck only when it is available on `PATH`; `required` reports `SC0000` when it cannot start or returns an invalid result. This lets a repository adopt shell analysis without making the default binary depend on a bundled ShellCheck distribution.

### Editor schema

TOML editors that support schema directives can validate keys and values while you type:

```toml
#:schema https://raw.githubusercontent.com/immanuwell/dockerfile-roast/main/schemas/droast.schema.json

preset = "production"
```

The schema is stored at [`schemas/droast.schema.json`](schemas/droast.schema.json). Runtime validation remains authoritative and also checks registered rule IDs, inheritance, and regular expressions.

### Discovery and precedence

droast searches from the current directory upward. It stops at the repository boundary or filesystem root.

Precedence for scalar value options is:

1. CLI option
2. `droast.toml`
3. built-in default

The `skip` list is different. CLI and configuration values are combined.

Boolean switches such as `--no-roast` and `--no-fail` enable the matching behavior. If either the CLI or configuration enables one, it stays enabled for that run.

```toml
# droast.toml
skip = ["DF012"]
```

```bash
# Both DF012 and DF022 are skipped.
droast --skip DF022 .
```

### Explicit configuration

Use a project-specific file:

```bash
droast --config .droast/team.toml .
```

### CLI-only controls

`--only` and `--check-ignorefile` are CLI-only. They are not TOML keys.

### Per-rule severity overrides

Turn a recommendation into a release blocker without changing the rule itself:

```toml
[severity-overrides]
DF001 = "error"
DF020 = "error"
DF033 = "warning"
DF065 = "error"
```

Overrides are applied before `min-severity`. For example, an info rule promoted to warning remains visible when `min-severity = "warning"`.

### Rule categories

Every rule has one or more categories:

- `correctness`
- `maintainability`
- `performance`
- `reliability`
- `reproducibility`
- `security`
- `supply-chain`

Inspect categories:

```bash
droast --list-rules
droast --list-rules --format json | jq '.[] | {id, categories}'
```

Run only security and supply-chain rules:

```toml
categories = ["security", "supply-chain"]
```

Or use the CLI:

```bash
droast --category security,supply-chain .
```

Skip a category while keeping the rest:

```toml
skip-categories = ["maintainability"]
```

`--only` is the most specific selector. When it is present, category selection does not hide the requested rule IDs. Explicit `skip` values still apply.

`DF071` syntax validation and `DF072` suppression-policy validation run with every selected category unless they are explicitly skipped. Other rules cannot be trusted when the source or its exceptions are invalid.

### Inline suppressions

Suppress one rule for the next Dockerfile instruction:

```dockerfile
# droast ignore=DF001 reason="PLAT-142 legacy vendor image" expires=2026-09-30
FROM vendor.example.com/runtime:latest
```

Suppress multiple rules:

```dockerfile
# droast ignore=DF001,DF065 reason="SEC-819 reviewed migration image" expires=2026-09-30
FROM migration.example.net/runtime:latest
```

Use a file-wide suppression before the first instruction:

```dockerfile
# droast global ignore=DF020 reason="PLAT-88 runtime injects numeric user" expires=2026-09-30
FROM gcr.io/distroless/static-debian12:nonroot
COPY app /app
ENTRYPOINT ["/app"]
```

The normal directive applies only to the next logical instruction. Blank lines and ordinary comments between the directive and instruction are safe. A directive inside a `RUN` heredoc is shell content and is not treated as a Dockerfile suppression.

`DF072` reports invalid, expired, disabled, misplaced, or stale directives. `DF072` itself cannot be suppressed inline.

Replace example expiration dates with a current, policy-compliant date when copying a directive.

### Suppression governance

Keep defaults lightweight:

```toml
inline-suppressions = true
require-suppression-reason = false
require-suppression-expiration = false
report-unused-suppressions = false
```

Use a governed enterprise policy:

```toml
inline-suppressions = true
require-suppression-reason = true
suppression-reason-pattern = "^(SEC|PLAT)-[0-9]+ .+$"
require-suppression-expiration = true
max-suppression-days = 90
report-unused-suppressions = true
```

Behavior:

- a missing reason rejects the suppression
- a reason that does not match the configured pattern rejects it
- an invalid or past date rejects it
- a date beyond `max-suppression-days` rejects it
- a rejected suppression never hides the original finding
- an unused suppression is reported when enabled
- expiration uses UTC and remains valid through the named date

Disable all inline exceptions in a centrally controlled repository:

```toml
inline-suppressions = false
```

### Approved registries

Configure `DF065` as an explicit registry allowlist:

```toml
approved-registries = [
  "docker.io",
  "ghcr.io",
  "*.gcr.io",
  "registry.example.com",
  "registry.example.com:5000",
]
```

Short image names such as `alpine:3.20` resolve to `docker.io`. Glob patterns are case-insensitive. When this setting is absent, droast keeps its built-in trusted-registry behavior.

Add a repository exception without replacing an inherited list:

```toml
extend-approved-registries = ["mirror.example.com"]
```

### Approved base images

Restrict full external `FROM` references and `COPY --from=<image>` sources with `DF073`:

```toml
approved-base-images = [
  "alpine:3.*",
  "debian:12.*",
  "ghcr.io/example/runtime@sha256:*",
  "registry.example.com/platform/*@sha256:*",
]
```

Patterns match the full image reference. Internal multi-stage aliases and numeric stage indexes are exempt. `scratch` is exempt. An empty configured list rejects every external image.

Add to an inherited image list explicitly:

```toml
extend-approved-base-images = ["registry.example.com/team/runtime@sha256:*"]
```

For release images, prefer digest patterns from a controlled registry:

```toml
approved-base-images = ["registry.example.com/platform/*@sha256:*"]
```

### Required image labels

`DF074` validates labels on the final image stage:

```toml
[required-labels]
"org.opencontainers.image.source" = "url"
"org.opencontainers.image.created" = "rfc3339"
"org.opencontainers.image.version" = "semver"
"org.opencontainers.image.revision" = "hash"
"org.opencontainers.image.licenses" = "spdx"
"com.example.owner" = "email"
"com.example.cost-center" = "regex:^CC-[0-9]{4}$"
```

Supported formats:

| Format | Accepted value |
|---|---|
| `text` | Any non-empty text, including build-time variables |
| `url` | A valid URL |
| `semver` | A semantic version, optionally prefixed with `v` |
| `hash` | 7 through 64 hexadecimal characters |
| `rfc3339` | An RFC 3339 timestamp |
| `spdx` | A valid SPDX expression |
| `email` | A basic email address |
| `regex:<pattern>` | A value matching the custom regular expression |

Dynamic values such as `${VERSION}` can only satisfy `text`, because their final value is unknown during linting.

Reject undeclared labels:

```toml
strict-labels = true

[required-labels]
"org.opencontainers.image.source" = "url"
"org.opencontainers.image.version" = "semver"
```

### Path-specific configuration

Use ordered overrides for monorepos:

```toml
preset = "production"

[[overrides]]
paths = ["services/**/Dockerfile", "services/**/*.Dockerfile"]
min-severity = "error"

[overrides.severity-overrides]
DF020 = "error"

[[overrides]]
paths = ["**/Dockerfile.dev", "**/Dockerfile.test"]
skip = ["DF012", "DF022"]

[[overrides]]
paths = ["docker/release.Dockerfile"]
preset = "strict"
approved-base-images = ["registry.example.com/platform/*@sha256:*"]
```

Patterns are resolved relative to the configuration that declares them. Every matching block is applied in file order. Later scalar values win. Additive lists such as `skip` are combined.

Output `format` remains scan-wide because one repository run emits one document. Set it at the top level or on the CLI. Other path settings, including severity, presets, policy, `no-roast`, and `no-fail`, apply per Dockerfile.

### Inherited organization configuration

Inherit one or more policy files:

```toml
extends = [
  ".droast/organization.toml",
  ".droast/language-team.toml",
]

# Repository-specific additions follow.
extend-approved-base-images = ["registry.example.com/platform/java@sha256:*"]
```

Relative paths start at the file containing `extends`. Absolute paths are supported. Inheritance cycles and missing files fail clearly.

Merge behavior:

- parents are loaded from left to right
- the repository file is applied last
- scalar values use the nearest explicit value
- `skip` and `skip-categories` are additive
- `approved-registries` and `approved-base-images` replace inherited lists
- `extend-approved-registries` and `extend-approved-base-images` add entries explicitly
- severity overrides use the nearest value for each rule
- parent required-label formats cannot be weakened by a child
- required reason, required expiration, unused checks, strict labels, and disabled inline suppressions cannot be weakened by a child
- the shortest configured `max-suppression-days` wins
- path overrides are appended and evaluated in inherited order

Remote URLs are not fetched automatically. This keeps linting deterministic, offline-capable, and free from hidden network policy changes.

For an organization policy stored elsewhere, download a pinned revision in CI, verify it, then inherit the local file:

```bash
mkdir -p .droast
curl -fsSL \
  https://raw.githubusercontent.com/example/platform/0123456789abcdef/droast.toml \
  -o .droast/organization.toml
echo 'EXPECTED_SHA256  .droast/organization.toml' | sha256sum --check
droast .
```

Repository `droast.toml`:

```toml
extends = ".droast/organization.toml"
```

See [`examples/droast-organization.toml`](examples/droast-organization.toml) and [`examples/droast-repository.toml`](examples/droast-repository.toml).

### Why these controls exist

These patterns are established in mature tooling:

- [Hadolint configuration](https://github.com/hadolint/hadolint/blob/master/README.md) provides severity overrides, trusted registries, label schemas, and inline ignores.
- [Ruff configuration](https://docs.astral.sh/ruff/configuration/) uses explicit inheritance and per-file configuration for large repositories.
- [ESLint bulk suppressions](https://eslint.org/docs/latest/use/suppressions) treats committed suppressions and stale-suppression reporting as migration controls.
- [GitHub organization security configuration](https://docs.github.com/en/code-security/how-tos/secure-at-scale/configure-organization-security) demonstrates centrally managed policy across repositories.

This is evidence of established team workflows, not a claim about private configuration inside any named company. Exact internal policies are rarely public.

droast keeps all of this optional. With no `droast.toml`, no policy-specific rule activates and existing lint defaults remain unchanged.

## Hadolint replacement mode

Try droast in an existing Hadolint workflow without changing its policy file:

```bash
droast --hadolint-compatible Dockerfile
```

In this mode, `--config` refers to Hadolint YAML rather than `droast.toml`. Without `--config`, droast uses Hadolint's first existing config location, including the project-local `.hadolint.yaml` and `.hadolint.yml` paths. With no Dockerfile argument, input is read from stdin; use `-` explicitly when that is clearer in scripts.

The compatibility CLI accepts:

- `-c/--config`, `-f/--format`, `-o/--output`, and `--file-path-in-report`
- `--ignore`, `--error`, `--warning`, `--info`, and `--style`
- `--trusted-registry`, `--require-label`, and `--strict-labels`
- `--disable-ignore-pragma`, `--no-color`, `--no-fail`, and `-V/--verbose`
- `-t/--failure-threshold` with `error`, `warning`, `info`, `style`, `ignore`, or `none`

It also reads `NO_COLOR` and the common `HADOLINT_*` variables: `HADOLINT_NOFAIL`, `HADOLINT_VERBOSE`, `HADOLINT_FORMAT`, `HADOLINT_FAILURE_THRESHOLD`, all four `HADOLINT_OVERRIDE_*` lists, `HADOLINT_IGNORE`, `HADOLINT_STRICT_LABELS`, `HADOLINT_DISABLE_IGNORE_PRAGMA`, `HADOLINT_TRUSTED_REGISTRIES`, and `HADOLINT_REQUIRE_LABELS`.

Available formats are `tty`, `json`, `checkstyle`, `codeclimate`, `gitlab_codeclimate`, `gnu`, `codacy`, `sonarqube`, `sarif`, and `junit`:

```bash
droast --hadolint-compatible --format gitlab_codeclimate \
  --file-path-in-report Dockerfile Dockerfile > gl-code-quality-report.json
```

Compatibility mode deliberately runs only checks with a declared Hadolint relationship, plus external ShellCheck checks when ShellCheck is installed. An equivalent check is reported under its `DL####` ID. If one droast check is broader than the Hadolint rule or differs in observable behavior, it keeps its `DF####` ID so downstream suppressions are not silently misrepresented. Referencing such a rule—or an unmatched rule or setting—in YAML, the environment, or flags prints a diagnostic on stderr while linting continues.

Print the complete versioned mapping matrix with:

```bash
droast --hadolint-compatible --hadolint-compatibility-report
```

Hadolint's inline and global pragmas are supported:

```dockerfile
# hadolint global ignore=DL3006

# hadolint ignore=DL3003
RUN cd /tmp && make
```

Use `--disable-ignore-pragma` (or the corresponding YAML/environment setting) to audit suppressed findings.

## Custom messages

Custom messages are optional terminal-output additions. Use them for team conventions, links to internal standards, migration guidance, onboarding, or a personal tone.

They never change lint rules, severities, exit codes, baselines, JSON, SARIF, or GitHub annotations. Without a message file, droast output is unchanged.

### Start in one command

Create personal overrides in the standard OS configuration directory:

```bash
droast messages init
```

Create reviewed overrides that travel with the current repository:

```bash
droast messages init --project
```

The command prints the exact path it created. Edit the YAML and rerun droast. Every invocation reads the files again; there is no reload command or daemon.

Use a small optional starter pack:

```bash
droast messages init --project --preset friendly
droast messages init --project --preset onboarding
```

The generated file is ordinary YAML. Commit a project file when its guidance is part of your engineering convention.

### Write an override

`messages init` creates a short example. Keep only the rules you want to change:

```yaml
version: 1

defaults:
  mode: message

rules:
  DF013:
    message: >-
      Secrets in ENV persist in image layers. Use BuildKit secrets instead.
    help: https://engineering.example.com/container-secrets

  DF021:
    message: "Piping curl to a shell is not an installation strategy."
```

For a personal setup, the same file can be playful:

```yaml
version: 1
rules:
  DF013:
    message: "You put the password in the fossil record again."
```

`message` is required. `help` is optional and must be an `http` or `https` URL. Rule IDs are case-insensitive in YAML and must name a droast rule.

### Layers and priority

droast merges up to three files on every terminal or compact run:

1. Personal file: the OS configuration directory.
2. Repository file: `.droast/messages.yaml`, found from the current directory or an ancestor.
3. Explicit file: `--messages PATH`.

Later layers win for the same rule. An explicit file is useful for a temporary campaign or for testing a shared file before committing it:

```bash
droast --messages team-messages.yaml Dockerfile
```

Personal locations are platform-native:

| Platform | Default location |
|---|---|
| Linux | `$XDG_CONFIG_HOME/droast/messages.yaml`, normally `~/.config/droast/messages.yaml` |
| macOS | `~/Library/Application Support/droast/messages.yaml` |
| Windows | `%APPDATA%\\droast\\messages.yaml` |

The project file is usually the right choice for organization-specific guidance. It is versioned, reviewed, and shared by every developer who runs droast in the repository.

### Choose how messages display

The default `message` mode keeps the normal technical finding visible and adds the custom text. This is the best mode for team guidance.

```yaml
defaults:
  mode: message # message | replace | append
```

- `message`: show the technical finding and the custom message.
- `replace`: show the custom message instead of droast's normal roast text.
- `append`: show droast's normal roast text, then the custom message.

`--no-roast` still removes droast's roast text. A configured custom message remains visible so organization-specific remediation is not lost.

### Safe placeholders

Messages can interpolate a small fixed set of values:

```yaml
version: 1
rules:
  DF013:
    message: "{rule} at {file}:{line}: use BuildKit secrets. Default: {default_message}"
```

Supported placeholders are `{rule}`, `{severity}`, `{file}`, `{line}`, and `{default_message}`. Unknown or unclosed placeholders fail validation. There is no scripting, shell execution, remote loading, or templating language.

### Inspect and validate

Show the effective override for a rule:

```bash
droast messages show DF013
droast messages show DF013 --messages team-messages.yaml
```

Validate a file before committing it:

```bash
droast messages validate .droast/messages.yaml
```

Print the complete reference catalog when you need to browse every rule:

```bash
droast messages dump --all > droast-messages-reference.yaml
```

The reference catalog is for discovery. Do not commit it unchanged; copy the few rules your team needs into `.droast/messages.yaml`.

All commands and their arguments are included in generated shell completions:

```bash
source <(droast completion bash)
```

## Copy-paste presets

Presets are built in. Select one in `droast.toml` or with `--preset`. Explicit settings can refine a preset.

### Minimal

Use this for an existing repository that needs a low-noise first step.

```toml
preset = "minimal"
```

```bash
droast --preset minimal .
```

This reports error-severity findings and uses technical messages.

### Security

Use this focused set for unsafe users, leaked secrets, unsafe downloads, permissions, shell pipelines, and malformed input.

```toml
preset = "security"
```

```bash
droast --preset security .
```

This selects `security` and `supply-chain` categories at warning severity.

### Performance

Use this for layer count, package caches, build context size, and cache invalidation.

```toml
preset = "performance"
```

```bash
droast --preset performance .
```

This selects the `performance` category and includes info findings.

### Production

Use this as a balanced default for a team repository.

```toml
preset = "production"
```

```bash
droast --preset production .
```

This runs all categories at warning severity with technical messages. Add only reviewed exceptions to `skip`.

### Strict

Use this for new projects, release images, or a cleanup target.

```toml
preset = "strict"
```

```bash
droast --preset strict --check-dockerignore true .
```

This runs every rule, requires reasons and expiration dates for suppressions, and reports unused suppressions.

### Makefile shortcuts

```makefile
.PHONY: lint-docker lint-docker-security lint-docker-performance lint-docker-strict

lint-docker:
	droast --preset production .

lint-docker-security:
	droast --preset security .

lint-docker-performance:
	droast --preset performance .

lint-docker-strict:
	droast --preset strict --check-dockerignore true .
```

## Control rules and severity

### Severity levels

| Level | Typical meaning |
|---|---|
| `error` | Unsafe or invalid behavior that should be fixed |
| `warning` | Strong production recommendation |
| `info` | Optimization, documentation, or maintainability advice |

`--min-severity warning` includes warnings and errors. `--min-severity error` includes errors only.

### Skip selected rules

```bash
droast --skip DF012,DF022 .
```

Use a committed config for team-wide exceptions:

```toml
skip = [
  "DF012", # Batch job has no health endpoint.
  "DF022", # Internal worker does not listen on a port.
]
```

### Run a focused rule set

```bash
droast --only DF013,DF014,DF021 Dockerfile
```

### Rule IDs are case-insensitive

Both forms work:

```bash
droast --skip DF012 .
droast --skip df012 .
```

## Safe deterministic fixes

Fixes are disabled unless `--fix` is present. The initial fixer set deliberately excludes transformations that require policy or human judgment.

Preview a repository patch without writing files:

```bash
droast fixes Dockerfile
droast --fix --dry-run --format diff .
```

Apply all available fixes to one file:

```bash
droast --fix Dockerfile
```

Select specific fixers:

```bash
droast --fix DF076,DF079 Dockerfile
```

The supported fixers are:

| Rule | Change | Safety boundary |
|---|---|---|
| `DF076` | Normalize Dockerfile instruction keyword casing | Uses the first instruction that is already entirely uppercase or lowercase; does nothing when the file establishes no convention |
| `DF078` | Lowercase an `EXPOSE` protocol | Changes only unquoted, literal `TCP` or `UDP` suffixes; variables, quoting, and unknown protocol text are untouched |
| `DF079` | Match `AS` casing to `FROM` | Requires `FROM` to be entirely uppercase or lowercase and `AS` to be a literal case-insensitive keyword |
| `DF083` | Remove `--platform=$TARGETPLATFORM` from `FROM` | Requires that exact variable value; fixed platforms and other expressions are untouched |

Fix planning happens after normal rule selection and suppression processing. A finding hidden by `skip`, `only`, categories, minimum severity, or an inline suppression is not changed. Selecting a rule without a safe fixer is an error rather than a request for a best-effort rewrite.

### Review and application guarantees

Every planned edit uses zero-based UTF-8 byte offsets plus one-based line and byte-column positions. Applying a plan:

- verifies the whole-file SHA-256 source hash
- verifies that every edit still matches its recorded original text
- rejects overlapping edits for the entire file
- applies edits from the highest byte offset to the lowest
- writes a same-directory temporary file, flushes it, rechecks the source, and atomically replaces the original
- preserves the regular file's permission bits, line endings, final-newline state, and all untouched bytes
- re-lints changed files and uses only remaining findings for the final exit status

droast refuses to rewrite stdin, symlinks, hard-linked files, non-regular files, syntactically invalid Dockerfiles, stale plans, and baseline operations. A multi-file run plans and validates every file before it begins applying changes. Atomicity is per file; if an external process changes a later file during application, earlier files may already have been safely replaced.

`droast fixes` lists available changes and is always read-only. `--dry-run` exits successfully when planning succeeds and never changes files. Terminal output reports edit counts. `--format diff` emits a unified patch. `--format json` exposes the machine-readable protocol:

```bash
droast --fix --dry-run --format json Dockerfile
```

The top-level object for one file contains `protocol_version`, `file`, `source_hash`, and `fixes`. Each fix contains:

- a stable `id` and numeric `version`
- its originating `rule`
- `applicability` (`safe`; the protocol reserves `review` and `none` for non-automatic integrations)
- a human-readable `title` and `rationale`
- behavioral, syntax, and cache `impact`
- one or more non-overlapping edits with `start_byte`, `end_byte`, positions, `original`, and `replacement`

Multiple files produce an array of these per-file plan objects. The complete contract is published as [`schemas/droast-fix-plan-v1.schema.json`](schemas/droast-fix-plan-v1.schema.json). Protocol version 1 applies only edits marked `safe`; future review-level suggestions will never become automatically applicable through `--fix`.

Normal `--format json` findings carry their matching `fixes` array. SARIF results use the standard `fixes.artifactChanges.replacements` structure and retain complete Droast protocol objects under `properties.droastFixes`.

The initial fixes have no intended behavioral impact. Their cache impact is conservatively reported as `may_invalidate` because changing Dockerfile source can cause a builder to recompute the affected instruction and later layers even when the resulting operation is equivalent.

Fixing base-image digests, inventing a runtime `USER`, choosing package versions, combining `RUN` instructions, or creating a `HEALTHCHECK` is intentionally outside this safe fixer set.

### Inline suppression

Use a governed exception directly above the affected instruction:

```dockerfile
# droast ignore=DF001 reason="PLAT-142 migration" expires=2026-09-30
FROM alpine:latest
```

See [Inline suppressions](#inline-suppressions) for global directives and policy controls.

## Output formats

### Terminal

This is the default human-readable output:

```bash
droast --format terminal Dockerfile
```

Keep personality enabled for local use:

```bash
droast Dockerfile
```

Use technical text for logs and team CI:

```bash
droast --no-roast Dockerfile
```

### Compact

Compact output is useful for editors and Unix pipelines:

```bash
droast --format compact --no-roast .
```

The output uses one finding per line with file, line, severity, rule, and message.

### JSON

```bash
droast --format json --no-roast Dockerfile > droast.json
```

A single input produces one result object. Multiple inputs produce an array of result objects.

Inspect all findings:

```bash
jq '.findings' droast.json
```

Count findings by severity for one file:

```bash
jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})' droast.json
```

For repository output:

```bash
droast --format json --no-roast . > droast.json
jq '[.[].findings[]] | group_by(.severity) | map({severity: .[0].severity, count: length})' droast.json
```

### GitHub annotations

```bash
droast --format github --no-roast .
```

This emits workflow commands that GitHub renders as file annotations. The Marketplace action selects this format automatically.

### SARIF

Create a SARIF 2.1.0 report:

```bash
droast --format sarif --no-roast --no-fail . > droast.sarif
```

### Baselines and stable fingerprints

Every JSON finding includes a deterministic `sha256:` fingerprint. SARIF results
carry the same value in `partialFingerprints.droast/v2`. The identity uses the
normalized file path, rule ID, source location, and diagnostic message. This
keeps repeated findings in one Dockerfile independently suppressible. Version 1
baselines must be regenerated because they collapsed repeated diagnostics.

Record the current findings for an existing repository:

```bash
droast --baseline droast-baseline.json --write-baseline --no-fail .
```

Use that baseline in CI. Existing error findings remain visible in output, but
only errors absent from the baseline make Droast return a non-zero status:

```bash
droast --baseline droast-baseline.json .
```

For a quiet gradual rollout, show only findings introduced after the baseline.
This filters accepted findings from every output format, while new error findings
continue to fail the command:

```bash
droast --baseline droast-baseline.json --only-new .
```

`--only-new` requires `--baseline` and cannot be combined with
`--write-baseline`; write or refresh the baseline in a separate command.

`--no-fail` lets the report upload step run even when droast finds errors.

### Quiet advisory runs

Keep findings but never block the caller:

```bash
droast --no-fail --no-roast .
```

## CI integration

Pin both the action and container image version for repeatable CI.

### GitHub Actions

Repository-wide annotations:

```yaml
name: Dockerfile lint

on:
  pull_request:
  push:
    branches: [main]

jobs:
  droast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: immanuwell/dockerfile-roast@1.4.5
        with:
          files: .
          min-severity: warning
          no-roast: true
          image-tag: 1.4.5
```

The action defaults to the root `Dockerfile`. Set `files: .` for recursive repository discovery, Compose, and Bake awareness.

Action inputs:

| Input | Default | Purpose |
|---|---|---|
| `files` | `Dockerfile` | Space-separated paths or glob patterns |
| `min-severity` | config or `info` | Minimum reported severity |
| `preset` | empty | Select a built-in preset |
| `category` | empty | Comma-separated categories to run |
| `skip-category` | empty | Comma-separated categories to skip |
| `skip` | empty | Comma-separated rule IDs to skip |
| `no-roast` | `false` | Use technical messages only |
| `no-fail` | `false` | Keep the workflow step non-blocking |
| `baseline` | empty | Repository path to the baseline JSON file |
| `only-new` | `false` | Report only findings absent from `baseline` |
| `engine` | config or `docker` | Build-context conventions: `docker` or `podman` |
| `image-tag` | `latest` | Select the container version used by the action |

Preset example:

```yaml
- uses: immanuwell/dockerfile-roast@1.4.5
  with:
    files: .
    preset: security
    image-tag: 1.4.5
```

Non-blocking rollout:

```yaml
- uses: immanuwell/dockerfile-roast@1.4.5
  with:
    files: .
    min-severity: info
    no-roast: true
    no-fail: true
    baseline: .droast-baseline.json
    only-new: true
    image-tag: 1.4.5
```

Skip reviewed exceptions:

```yaml
- uses: immanuwell/dockerfile-roast@1.4.5
  with:
    files: .
    skip: DF012,DF022
    no-roast: true
    image-tag: 1.4.5
```

### GitHub code scanning with SARIF

```yaml
name: Dockerfile code scanning

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  droast-sarif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - name: Generate SARIF
        run: |
          docker run --rm \
            -v "$GITHUB_WORKSPACE:/workspace" \
            -w /workspace \
            ghcr.io/immanuwell/droast:1.4.5 \
            --format sarif --no-roast --no-fail . > droast.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: droast.sarif
```

### GitLab CI

GitLab can run droast directly as the job image. Clear the image entrypoint so
GitLab can execute the job script.

#### GitLab - lint every supported Dockerfile

```yaml
droast:
  stage: test
  image:
    name: ghcr.io/immanuwell/droast:1.4.5
    entrypoint: [""]
  script:
    - droast --no-roast --min-severity warning .
  rules:
    - changes:
        - "**/Dockerfile"
        - "**/Dockerfile.*"
        - "**/*.Dockerfile"
        - "**/Containerfile*"
        - "**/compose*.yml"
        - "**/compose*.yaml"
        - "**/docker-bake.*"
```

The `changes` rule avoids starting this job when a commit cannot affect a
Docker build. Remove `rules` if Compose or Bake files use non-standard names.

#### GitLab - strict merge requests and the default branch

```yaml
droast-strict:
  stage: test
  image:
    name: ghcr.io/immanuwell/droast:1.4.5
    entrypoint: [""]
  script:
    - droast --preset strict --no-roast .
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

This blocks merge-request and default-branch pipelines when the strict preset
finds a failing issue.

#### GitLab - keep a non-blocking JSON report

```yaml
droast-report:
  stage: test
  image:
    name: ghcr.io/immanuwell/droast:1.4.5
    entrypoint: [""]
  script:
    - mkdir -p reports
    - droast --format json --no-roast --no-fail . > reports/droast.json
  artifacts:
    when: always
    name: "droast-$CI_COMMIT_SHORT_SHA"
    paths:
      - reports/droast.json
    expire_in: 1 week
```

`--no-fail` keeps the rollout advisory. Remove it when the team is ready to
enforce the configured severity threshold.

See the [GitLab CI/CD YAML reference](https://docs.gitlab.com/ci/yaml/) for
runner-specific options.

### Bitbucket Pipelines

Bitbucket Pipelines can use the public droast image as a build environment.

#### Bitbucket - lint every branch

`bitbucket-pipelines.yml`:

```yaml
image: ghcr.io/immanuwell/droast:1.4.5

pipelines:
  default:
    - step:
        name: Lint Dockerfiles
        script:
          - droast --no-roast --min-severity warning .
```

#### Bitbucket - production preset on pull requests

```yaml
image: ghcr.io/immanuwell/droast:1.4.5

pipelines:
  pull-requests:
    '**':
      - step:
          name: Lint Dockerfiles
          script:
            - droast --preset production --no-roast .
```

Bitbucket pull-request pipelines run in addition to matching `default` or
branch pipelines. Use only the trigger sections you need to avoid duplicate
runs.

#### Bitbucket - keep a non-blocking JSON report

```yaml
image: ghcr.io/immanuwell/droast:1.4.5

pipelines:
  custom:
    droast-report:
      - step:
          name: Create droast report
          script:
            - mkdir -p reports
            - droast --format json --no-roast --no-fail . > reports/droast.json
          artifacts:
            - reports/droast.json
```

The `custom` pipeline is available for manual and scheduled runs.

#### Bitbucket - keep an existing build image

Use the Docker service when the step needs a different build image:

```yaml
image: atlassian/default-image:5

pipelines:
  default:
    - step:
        name: Lint Dockerfiles
        services:
          - docker
        script:
          - >-
            docker run --rm
            -v "$BITBUCKET_CLONE_DIR:/workspace:ro"
            -w /workspace
            ghcr.io/immanuwell/droast:1.4.5
            --no-roast --min-severity warning .
```

The clone directory is within Bitbucket's permitted bind-mount area. The
read-only mount is sufficient for linting.

See the [Bitbucket Pipelines configuration reference](https://support.atlassian.com/bitbucket-cloud/docs/bitbucket-pipelines-configuration-reference/)
for build images, triggers, services, and artifacts.

### CircleCI

```yaml
version: 2.1

jobs:
  droast:
    machine:
      image: ubuntu-2404:current
    steps:
      - checkout
      - run:
          name: Lint Dockerfiles
          command: |
            docker run --rm \
              -v "$PWD:/workspace" \
              -w /workspace \
              ghcr.io/immanuwell/droast:1.4.5 \
              --no-roast --min-severity warning .

workflows:
  lint:
    jobs:
      - droast
```

### Jenkins

These examples use Declarative Pipeline syntax.

#### Jenkins - use Docker from an existing agent

```groovy
pipeline {
  agent any
  stages {
    stage('Lint Dockerfiles') {
      steps {
        sh '''
          docker run --rm \
            -v "$WORKSPACE:/workspace" \
            -w /workspace \
            ghcr.io/immanuwell/droast:1.4.5 \
            --no-roast --min-severity warning .
        '''
      }
    }
  }
}
```

The selected Jenkins agent must have Docker installed and permission to use
the Docker daemon.

#### Jenkins - use droast as the stage agent

This variant requires the Jenkins Docker Pipeline plugin:

```groovy
pipeline {
  agent none
  stages {
    stage('Lint Dockerfiles') {
      agent {
        docker {
          image 'ghcr.io/immanuwell/droast:1.4.5'
          args '--entrypoint='
          reuseNode true
        }
      }
      steps {
        sh 'droast --preset production --no-roast .'
      }
    }
  }
}
```

Clearing the image entrypoint lets Jenkins start its normal agent command.
`reuseNode true` mounts the current workspace into the container.

#### Jenkins - keep a non-blocking JSON report

```groovy
pipeline {
  agent any
  stages {
    stage('Dockerfile report') {
      steps {
        sh '''
          mkdir -p reports
          docker run --rm \
            -v "$WORKSPACE:/workspace:ro" \
            -w /workspace \
            ghcr.io/immanuwell/droast:1.4.5 \
            --format json --no-roast --no-fail . > reports/droast.json
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'reports/droast.json', fingerprint: true
    }
  }
}
```

`archiveArtifacts` keeps the report with the Jenkins build. Remove
`--no-fail` to make findings block the pipeline.

See the Jenkins references for [Pipeline syntax](https://www.jenkins.io/doc/book/pipeline/syntax/)
and [Docker agents](https://www.jenkins.io/doc/book/pipeline/docker/).

### Azure Pipelines

Microsoft-hosted Ubuntu agents include Docker. Self-hosted agents need a
running Docker daemon.

#### Azure - lint pushes and pull requests

```yaml
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
  - bash: |
      docker run --rm \
        -v "$(Build.SourcesDirectory):/workspace:ro" \
        -w /workspace \
        ghcr.io/immanuwell/droast:1.4.5 \
        --no-roast --min-severity warning .
    displayName: Lint Dockerfiles
```

The YAML `pr` trigger works with GitHub and Bitbucket Cloud repositories.
Azure Repos Git uses a build-validation branch policy for pull requests.

#### Azure - strict pull-request policy

```yaml
trigger: none

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
  - bash: |
      docker run --rm \
        -v "$(Build.SourcesDirectory):/workspace:ro" \
        -w /workspace \
        ghcr.io/immanuwell/droast:1.4.5 \
        --preset strict --no-roast .
    displayName: Enforce strict Dockerfile policy
```

Add this pipeline to the target branch's build validation policy when Azure
Repos should require it before merging. For GitHub and Bitbucket Cloud, the
YAML `pr` trigger starts it directly.

#### Azure - keep a non-blocking JSON report

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self
  - bash: |
      mkdir -p "$(Build.ArtifactStagingDirectory)/droast"
      docker run --rm \
        -v "$(Build.SourcesDirectory):/workspace:ro" \
        -w /workspace \
        ghcr.io/immanuwell/droast:1.4.5 \
        --format json --no-roast --no-fail . \
        > "$(Build.ArtifactStagingDirectory)/droast/droast.json"
    displayName: Create droast report
  - publish: $(Build.ArtifactStagingDirectory)/droast
    artifact: droast
    condition: always()
    displayName: Publish droast report
```

The `publish` shortcut creates a pipeline artifact in Azure DevOps Services.
Azure DevOps Server users should use `PublishBuildArtifacts@1` instead.

See the Azure references for [Docker on hosted agents](https://learn.microsoft.com/azure/devops/pipelines/ecosystems/containers/build-image)
and [pipeline artifacts](https://learn.microsoft.com/azure/devops/pipelines/artifacts/pipeline-artifacts).

## Local development workflows

### pre-commit

Install [pre-commit](https://pre-commit.com/) and add:

```yaml
repos:
  - repo: local
    hooks:
      - id: droast
        name: droast
        entry: droast --no-roast --min-severity warning .
        language: system
        pass_filenames: false
        always_run: true
```

Run it:

```bash
pre-commit run droast --all-files
```

### Git pre-push hook

`.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
set -euo pipefail
droast --preset production .
```

Enable it:

```bash
chmod +x .git/hooks/pre-push
```

For a team, manage hooks through a committed hook manager instead of copying `.git/hooks` manually.

### Changed Dockerfiles only

```bash
git diff --name-only --diff-filter=ACMR origin/main...HEAD \
  | grep -E '(^|/)(Dockerfile($|\.)|.*\.Dockerfile$|Containerfile($|\.))' \
  | xargs -r droast --no-roast
```

Use `droast .` in CI when Compose, Bake, or build-context resolution matters.

## Docker and container usage

### Lint a repository

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/immanuwell/droast:1.4.5 \
  --no-roast .
```

### Lint one file

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/immanuwell/droast:1.4.5 \
  Dockerfile
```

### Write JSON to the host

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/immanuwell/droast:1.4.5 \
  --format json --no-roast --no-fail . > droast.json
```

### Read-only mount

Linting does not need to change the repository:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -w /workspace \
  ghcr.io/immanuwell/droast:1.4.5 \
  --no-roast .
```

## Wasmer and WASI

The Wasmer package provides the same command-line interface through WASI. Stdin linting needs no filesystem permission:

```bash
wasmer run immanuwell/droast -- \
  --only DF001,DF002 --check-dockerignore=false - < Dockerfile
```

For repository discovery, Compose, Bake, `.dockerignore`, and project configuration, mount the repository and use guest paths:

```bash
wasmer run --volume "$PWD:/workspace" immanuwell/droast -- \
  --config /workspace/droast.toml /workspace
```

Build and validate the package locally:

```bash
./scripts/build-wasmer-package.sh
wasmer run target/wasmer/droast.webc -- --version
```

## VS Code

The extension shows findings as editor diagnostics while Dockerfiles are edited.

Install it:

```bash
code --install-extension ImmanuelTikhonov.droast
```

## Neovim

The bundled dependency-free plugin publishes Droast findings through Neovim's
native diagnostics API. It provides `:DroastLint`, `:DroastQuickfix`, and
lint-on-save for Dockerfile and Containerfile names.

Install it without a plugin manager:

```bash
curl -fsSL https://raw.githubusercontent.com/immanuwell/dockerfile-roast/main/scripts/install-neovim-extension.sh | sh
```

Or install the dedicated `immanuwell/droast.nvim` repository through a plugin
manager:

```lua
-- lazy.nvim:  { "immanuwell/droast.nvim" }
-- packer.nvim: use "immanuwell/droast.nvim"
-- mini.deps:   MiniDeps.add({ source = "immanuwell/droast.nvim" })
```

The plugin starts automatically with `droast` on `PATH` and lint-on-save. To
override defaults, call `require("droast").setup({ args = { "--preset", "production" } })`.
`args` accepts normal Droast CLI options; the plugin adds JSON output,
`--no-roast`, `--no-fail`, the current file path, and disables the
repository-wide ignore-file advisory so editor diagnostics stay focused on the
open Dockerfile.

Run the headless integration test with Neovim 0.9 or newer:

```bash
scripts/test-neovim-extension.sh
```

### Settings

`.vscode/settings.json`:

```json
{
  "droast.enable": true,
  "droast.executablePath": "",
  "droast.minSeverity": "warning",
  "droast.skipRules": ["DF012", "DF022"],
  "droast.noRoast": true
}
```

| Setting | Purpose |
|---|---|
| `droast.enable` | Enable or disable linting |
| `droast.executablePath` | Use a specific executable path; `~` and `${userHome}` are supported |
| `droast.minSeverity` | Select `info`, `warning`, or `error` |
| `droast.skipRules` | Suppress rule IDs |
| `droast.noRoast` | Show technical text only |

Leave `droast.executablePath` empty to use the bundled executable or a `droast` executable on `PATH`.

## Web version

Open [the droast web linter](https://ewry.net/droast-dockerfile-linter/).

Paste a Dockerfile to get immediate findings without installing a binary. The linter runs in the browser through WebAssembly, so the Dockerfile does not need to be sent to a linting service.

Use the web version for quick experiments. Use the CLI for repository discovery, effective build contexts, `.dockerignore`, configuration, output formats, and CI.

## Rust library

`dockerfile-roast` is published on [crates.io](https://crates.io/crates/dockerfile-roast).
It provides an `rlib` library as well as the `droast` CLI.

Add the crate to an application or integration:

```toml
[dependencies]
dockerfile-roast = "1.4.10"
```

The public API includes:

- `linter::lint_content` and `linter::lint_file` for linting
- `parser::parse_document` for structured Dockerfile data
- `fixes::plan`, `fixes::apply`, and the versioned fix protocol types for deterministic edits
- `LintOptions` and `LintResult` for lint configuration and results
- `Finding`, `Rule`, and `Severity` for working with findings and rules

The main modules are `parser`, `rules`, `linter`, `repository`, `config`, and `output`.
Use the linting API when you need findings. Use the parser API when you need the Dockerfile structure.

### Lint text

```rust
use dockerfile_roast::linter::{lint_content, LintOptions};
use dockerfile_roast::rules::Severity;

fn main() {
    let source = "FROM alpine:latest\nUSER root\n";
    let options = LintOptions {
        skip_rules: vec![],
        only_rules: vec![],
        min_severity: Severity::Info,
        check_dockerignore: false,
        ..LintOptions::default()
    };

    let result = lint_content(source, "Dockerfile", &options);
    for finding in result.findings {
        println!(
            "{}:{} {} {}",
            result.file, finding.line, finding.severity, finding.rule
        );
    }
}
```

### Lint a file

```rust
use std::path::Path;
use dockerfile_roast::linter::{lint_file, LintOptions};
use dockerfile_roast::rules::Severity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = LintOptions {
        skip_rules: vec!["DF012".into()],
        only_rules: vec![],
        min_severity: Severity::Warning,
        check_dockerignore: true,
        ..LintOptions::default()
    };

    let result = lint_file(Path::new("Dockerfile"), &options)?;
    println!("{} findings", result.findings.len());
    Ok(())
}
```

### Select rules in code

```rust
let options = LintOptions {
    skip_rules: vec![],
    only_rules: vec!["DF013".into(), "DF014".into(), "DF021".into()],
    min_severity: Severity::Warning,
    check_dockerignore: false,
    ..LintOptions::default()
};
```

## Parser API

Use `parse_document` when an integration needs structured Dockerfile data.

```rust
use dockerfile_roast::parser::{parse_document, InstructionForm};

fn main() {
    let source = r#"# syntax=docker/dockerfile:1.7
FROM alpine:3.20
RUN --mount=type=cache,target=/cache echo "$HOME"
"#;

    let document = parse_document(source);

    println!("escape character: {}", document.escape);
    for directive in &document.directives {
        println!("directive: {}={}", directive.name, directive.value);
    }

    for instruction in &document.instructions {
        println!("{} at line {}", instruction.instruction, instruction.line);
        println!("source: {}", instruction.span.text(source));
        println!("flags: {}", instruction.flags.len());

        if let InstructionForm::Json(values) = &instruction.form {
            println!("JSON arguments: {values:?}");
        }
    }

    for diagnostic in &document.diagnostics {
        println!("{}: {}", diagnostic.code, diagnostic.message);
    }
}
```

Important structured fields include:

- parser directives and the effective escape character
- exact instruction, keyword, and argument spans
- normalized command text after BuildKit flags
- structured flags and their values
- words, quote styles, and variable references
- shell, JSON, and invalid JSON forms
- heredoc delimiters, bodies, expansion mode, and spans
- recoverable parser diagnostics

`parse` remains available when only the instruction list is needed:

```rust
use dockerfile_roast::parser::parse;

let instructions = parse("FROM alpine:3.20\n");
```

## Rule catalog

Run `droast --list-rules` for the authoritative list in the installed version. This catalog describes all 75 current rules.

### Docker build-check compatibility

[`compatibility/docker-build-checks.json`](compatibility/docker-build-checks.json) is the machine-readable contract for Docker's current 21 build checks. `supported` means a rule has matching semantics and a direct compatibility fixture; `partial` means Droast overlaps but does not yet claim parity; `planned` has no compatible implementation yet. The matrix is intentionally conservative and tested for complete coverage of Docker's published check list.

### Base images, stages, and reproducibility

| Rule | Severity | Check |
|---|---|---|
| DF001 | warning | Use a specific base image tag instead of `latest` |
| DF005 | info | Pin package versions for repeatable builds |
| DF011 | info | Use multi-stage builds when they reduce the final image |
| DF023 | info | Give intermediate `FROM` stages aliases instead of numeric indexes |
| DF024 | warning | Avoid `:latest` on aliased stages |
| DF042 | error | Keep stage aliases unique |
| DF061 | info | Avoid fixed `--platform` in `FROM` unless required |
| DF065 | warning | Enforce `approved-registries` when that policy is configured |
| DF069 | warning | Avoid package upgrades that make builds non-repeatable |
| DF073 | error | Require external images approved by configured policy |

### Users, secrets, and command safety

| Rule | Severity | Check |
|---|---|---|
| DF002 | error | Do not leave the final image running as root |
| DF010 | warning | Do not use `sudo` inside a container |
| DF013 | error | Do not hardcode credentials in `RUN` commands |
| DF014 | error | Do not hardcode passwords or tokens in `ARG` or `ENV` |
| DF020 | info | Set an explicit non-root `USER` |
| DF021 | error | Do not execute unverified remote downloads with a shell or interpreter |
| DF034 | error | Do not use `chmod 777` |
| DF057 | warning | Set `pipefail` for shell pipelines |
| DF066 | warning | Set an appropriate `SHELL` before Bash-specific syntax |

### Layers, files, and build context

| Rule | Severity | Check |
|---|---|---|
| DF003 | info | Combine related `RUN` commands to reduce layers |
| DF006 | warning | Prefer `COPY` over `ADD` for local files |
| DF007 | warning | Avoid broad `COPY . .` operations; scratch staging is informational |
| DF008 | info | Use `WORKDIR` instead of inline `cd` |
| DF009 | warning | Use absolute `WORKDIR` paths |
| DF026 | warning | Avoid broad local copies to filesystem root |
| DF033 | info | Use an effective `.dockerignore` for each build context |
| DF048 | error | End multi-source `COPY` destinations with `/` |
| DF049 | warning | Reserved for invalid `COPY --from` stage references |
| DF050 | error | Do not copy from the current stage |
| DF063 | warning | Set `WORKDIR` before a relative `COPY` destination |
| DF067 | info | Reserved; archive extraction policy is context-dependent |
| DF070 | warning | Avoid a broad copy before dependency installation |

### Package managers and caches

| Rule | Severity | Check |
|---|---|---|
| DF004 | warning | Clean apt/apk caches before they reach the final image |
| DF015 | error | Pass `-y` to `apt-get` in non-interactive builds |
| DF016 | info | Use `--no-install-recommends` with `apt-get` |
| DF027 | error | Pass `-y` to `yum` |
| DF028 | warning | Combine `apt-get update` with installation |
| DF029 | warning | Use `apk add --no-cache` |
| DF030 | info | Use pip `--no-cache-dir` |
| DF031 | info | Prefer `npm ci` and production-aware installation |
| DF043 | warning | Make `zypper install` non-interactive |
| DF044 | warning | Avoid `zypper dist-upgrade` in an image build |
| DF045 | info | Clean zypper metadata after installation |
| DF046 | warning | Run `dnf clean all` after installation |
| DF047 | warning | Run `yum clean all` after installation |
| DF051 | warning | Pin versions installed by pip |
| DF052 | info | Pin versions installed by apk |
| DF053 | warning | Pin versions installed by gem |
| DF054 | warning | Pin `go install` targets with `@version` |
| DF055 | info | Clean the Yarn cache after installation |
| DF059 | warning | Use `apt-get` or `apt-cache` instead of `apt` in scripts |

### Downloads and network tools

| Rule | Severity | Check |
|---|---|---|
| DF035 | info | Make curl fail on HTTP and transfer errors |
| DF056 | info | Limit wget progress output in build logs |
| DF058 | info | Use either wget or curl consistently |

### Runtime behavior and metadata

| Rule | Severity | Check |
|---|---|---|
| DF012 | info | Add a health check to long-running services |
| DF017 | warning | Use `ENTRYPOINT` with `CMD` for flexible arguments |
| DF018 | warning | Prefer JSON form for `ENTRYPOINT` |
| DF019 | warning | Replace deprecated `MAINTAINER` with `LABEL` |
| DF022 | info | Document listening ports with `EXPOSE` |
| DF025 | warning | Prefer JSON form for `CMD` and `ENTRYPOINT` |
| DF032 | info | Set recommended Python runtime environment variables |
| DF036 | info | Give runnable images a `CMD` or `ENTRYPOINT` |
| DF038 | warning | Keep only one effective `CMD` |
| DF039 | error | Keep only one effective `ENTRYPOINT` |
| DF040 | error | Keep `EXPOSE` ports in the range 0 through 65535 |
| DF041 | error | Keep only one effective `HEALTHCHECK` |
| DF060 | info | Remove pointless interactive commands |
| DF062 | info | ENV references may use inherited values |
| DF064 | warning | Use `useradd -l` when assigning an explicitly high UID |
| DF068 | error | Do not use forbidden instructions as `ONBUILD` triggers |
| DF074 | error | Require final-stage labels to match configured policy |
| DF075 | info | Lint `Containerfile.in` after Podman CPP preprocessing |

### Syntax

| Rule | Severity | Check |
|---|---|---|
| DF037 | error | Begin with `FROM`, global `ARG`, or a comment |
| DF071 | error | Keep Dockerfile syntax valid |
| DF072 | error | Require valid and governed suppression directives |

## Adoption recipes

### Existing repository with many findings

Start without blocking:

```toml
min-severity = "error"
no-roast = true
no-fail = true
format = "terminal"
```

Then:

1. Fix all error findings.
2. Change `no-fail` to `false`.
3. Raise `min-severity` to `warning`.
4. Review remaining rules one category at a time.
5. Record only justified exceptions in `skip`.
6. Move toward the strict preset.

### New service

Use strict checks from the first commit:

```bash
droast --preset strict --check-dockerignore true .
```

Run the same command locally, in pre-commit, and in CI.

### Security gate plus full advisory scan

Use two CI jobs:

```bash
# Blocking security gate
droast --no-roast \
  --preset security .

# Full advisory report
droast --no-roast --no-fail --min-severity info .
```

### Release image review

Lint the actual release Dockerfile and its context through the repository entry point:

```bash
droast --preset strict .
docker build -f docker/release.Dockerfile .
```

This lets Compose, Bake, and `.dockerignore` context logic stay consistent with repository use.

### Machine-readable quality report

```bash
droast --format json --no-roast --no-fail . > droast.json
droast --format sarif --no-roast --no-fail . > droast.sarif
```

Use JSON for custom dashboards. Use SARIF for code scanning systems.

## Troubleshooting

### No Dockerfiles were found

Check the current directory and file names:

```bash
pwd
find . -type f \( \
  -name 'Dockerfile' -o \
  -name 'Dockerfile.*' -o \
  -name '*.Dockerfile' -o \
  -name '*.dockerfile' -o \
  -name 'Containerfile' -o \
  -name 'Containerfile.*' \
\)
```

Then pass the intended repository root:

```bash
droast /path/to/repository
```

### GitHub Action checks only one file

The action defaults to `Dockerfile`. Enable repository discovery:

```yaml
with:
  files: .
```

### DF033 reports the wrong context

Run droast from the repository root so Compose and Bake files can define the build context:

```bash
droast .
```

Check whether a Dockerfile-specific ignore file overrides the root file:

```bash
find . -name '*.dockerignore' -o -name '.dockerignore'
```

### A Compose or Bake Dockerfile is missing

Confirm its context and Dockerfile path resolve locally. Remote Git and image contexts are not downloaded. Also check Compose `.env` values and Bake variable defaults.

### JSON parsing fails after adding more files

Single-file JSON is an object. Multi-file JSON is an array.

Single file:

```bash
jq '.findings' droast.json
```

Multiple files:

```bash
jq '.[].findings' droast.json
```

### The process exits successfully with warnings

Exit code `1` is reserved for error-severity findings and execution failures. Warnings are still printed. Use focused `--only` checks or inspect structured output when selected warnings must gate a workflow.

### The process exits with findings but CI must continue

```bash
droast --no-fail .
```

For SARIF, keep `--no-fail` on the generation step so the upload step runs.

### A config option has no effect

Check the active file and precedence:

```bash
droast --config ./droast.toml --help
```

CLI values override scalar configuration values. `skip` values are combined. `--only` and `--check-dockerignore` are CLI-only.

### VS Code cannot find droast

Set an absolute executable path, or use `~` / `${userHome}` for your home directory:

```json
{
  "droast.executablePath": "${userHome}/.local/bin/droast"
}
```

On Windows, point it to `droast.exe`.

### Shell expands a file pattern too early

Quote patterns when the shell should pass them unchanged:

```bash
droast 'services/*/Dockerfile'
```

For full recursive discovery, prefer:

```bash
droast .
```

## FAQ

### Does droast modify Dockerfiles?

No. Linting is read-only.

### Is configuration required?

No. `droast .` works without configuration.

### Which preset should a team start with?

Use `minimal` for a mature repository with existing debt. Use `production` for a normal team baseline. Use `strict` for new or release-critical images.

### Are presets built in?

Yes. Use `preset = "production"` in `droast.toml` or `droast --preset production .`. Explicit configuration can refine the selected preset.

### Can droast scan a monorepo?

Yes. Run `droast .` at the monorepo root. It recursively discovers conventional names plus Compose and Bake references.

### Does it understand BuildKit Dockerfiles?

Yes. The parser understands syntax directives, generic instruction flags, heredocs, and modern `RUN --mount` forms.

### Does it support Windows Dockerfiles?

Yes. It handles escape directives, Windows paths, CRLF files, JSON forms, and PowerShell-oriented Dockerfiles.

### Can it be used without the roast messages?

Yes:

```bash
droast --no-roast .
```

### Can it produce code scanning output?

Yes. Use `--format sarif` for SARIF 2.1.0, or `--format github` for GitHub workflow annotations.

### Where should shared exceptions live?

Put reviewed exceptions in the repository's `droast.toml`. Add a short comment explaining each design choice.

### How do I see the authoritative rule list?

Run the installed executable:

```bash
droast --list-rules
```

### Where can I report a problem?

Open an issue in the [dockerfile-roast repository](https://github.com/immanuwell/dockerfile-roast/issues).

### How can I support the project?

[Buy me a coffee](https://buymeacoffee.com/immanuwell).
