# droast documentation

droast is an opinionated Dockerfile linter. It checks security, correctness, reproducibility, image size, cache use, package installation, and runtime behavior.

Use this guide as a quick reference. Every section favors copy-paste examples over long explanations.

## Table of contents

- [Quick start](#quick-start)
- [Install](#install)
- [What droast understands](#what-droast-understands)
- [Command line reference](#command-line-reference)
- [Repository discovery](#repository-discovery)
- [Configuration](#configuration)
- [Copy-paste presets](#copy-paste-presets)
- [Control rules and severity](#control-rules-and-severity)
- [Output formats](#output-formats)
- [CI integration](#ci-integration)
- [Local development workflows](#local-development-workflows)
- [Docker and container usage](#docker-and-container-usage)
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
docker pull ghcr.io/immanuwell/droast:1.4.2
```

Use a fixed version in CI. Use `latest` only when automatic upgrades are acceptable.

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
| `-f, --format FORMAT` | Select `terminal`, `json`, `github`, `compact`, or `sarif` |
| `-s, --min-severity LEVEL` | Select `info`, `warning`, or `error` |
| `--skip IDS` | Skip comma-separated rule IDs |
| `--only IDS` | Run only comma-separated rule IDs |
| `--no-roast` | Show technical messages only |
| `--check-dockerignore BOOL` | Enable or disable effective `.dockerignore` checks |
| `--no-fail` | Always exit successfully after linting |
| `--list-rules` | Print the available rules |
| `-h, --help` | Print help |
| `-V, --version` | Print the version |

### Commands

Create `droast.toml` in the current directory:

```bash
droast init
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
- `Containerfile`
- `Containerfile.*`
- Dockerfiles referenced by Compose files
- Dockerfiles referenced by Bake HCL or JSON files

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
droast --check-dockerignore false .
```

## Configuration

Configuration is optional. The file name is `droast.toml`.

### Complete example

```toml
skip = ["DF012", "DF022"]
min-severity = "warning"
no-roast = true
no-fail = false
format = "terminal"
```

### Configuration keys

| Key | Type | Values |
|---|---|---|
| `skip` | array of strings | Rule IDs such as `DF012` |
| `min-severity` | string | `info`, `warning`, `error` |
| `no-roast` | boolean | `true`, `false` |
| `no-fail` | boolean | `true`, `false` |
| `format` | string | `terminal`, `json`, `github`, `compact`, `sarif` |

Unknown keys are rejected. This catches misspelled configuration early.

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

Use a project-specific or preset file:

```bash
droast --config .droast/strict.toml .
```

### CLI-only controls

`--only` and `--check-dockerignore` are CLI-only. They are not TOML keys.

## Copy-paste presets

These presets are practical recipes, not special built-in preset names. Store them under `.droast/` and call them explicitly.

```bash
mkdir -p .droast
```

### Minimal

Use this for an existing repository that needs a low-noise first step.

`.droast/minimal.toml`:

```toml
min-severity = "error"
no-roast = true
no-fail = false
format = "terminal"
```

Run it:

```bash
droast --config .droast/minimal.toml .
```

### Security

Use this focused set for unsafe users, leaked secrets, unsafe downloads, permissions, shell pipelines, and malformed input.

`.droast/security.toml`:

```toml
min-severity = "warning"
no-roast = true
no-fail = false
format = "terminal"
```

Run it:

```bash
droast --config .droast/security.toml \
  --only DF002,DF013,DF014,DF020,DF021,DF025,DF034,DF057,DF065,DF071 .
```

Reusable script `scripts/lint-docker-security.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

droast --config .droast/security.toml \
  --only DF002,DF013,DF014,DF020,DF021,DF025,DF034,DF057,DF065,DF071 .
```

### Performance

Use this for layer count, package caches, build context size, and cache invalidation.

`.droast/performance.toml`:

```toml
min-severity = "info"
no-roast = true
no-fail = false
format = "terminal"
```

Run it:

```bash
droast --config .droast/performance.toml \
  --only DF003,DF004,DF007,DF011,DF028,DF030,DF031,DF045,DF046,DF047,DF055,DF064,DF070 .
```

### Production

Use this as a balanced default for a team repository.

`.droast/production.toml`:

```toml
skip = []
min-severity = "warning"
no-roast = true
no-fail = false
format = "terminal"
```

Run it:

```bash
droast --config .droast/production.toml .
```

Add only reviewed, documented exceptions to `skip`.

### Strict

Use this for new projects, release images, or a cleanup target.

`.droast/strict.toml`:

```toml
skip = []
min-severity = "info"
no-roast = true
no-fail = false
format = "terminal"
```

Run every rule and require an effective `.dockerignore`:

```bash
droast --config .droast/strict.toml --check-dockerignore true .
```

### Makefile shortcuts

```makefile
.PHONY: lint-docker lint-docker-security lint-docker-performance lint-docker-strict

lint-docker:
	droast --config .droast/production.toml .

lint-docker-security:
	droast --config .droast/security.toml --only DF002,DF013,DF014,DF020,DF021,DF025,DF034,DF057,DF065,DF071 .

lint-docker-performance:
	droast --config .droast/performance.toml --only DF003,DF004,DF007,DF011,DF028,DF030,DF031,DF045,DF046,DF047,DF055,DF064,DF070 .

lint-docker-strict:
	droast --config .droast/strict.toml --check-dockerignore true .
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

### Inline suppression

droast does not currently support line-level suppression comments. Keep project exceptions visible in `droast.toml`, or use `--skip` for one run.

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
      - uses: immanuwell/dockerfile-roast@1.4.2
        with:
          files: .
          min-severity: warning
          no-roast: true
          image-tag: 1.4.2
```

The action defaults to the root `Dockerfile`. Set `files: .` for recursive repository discovery, Compose, and Bake awareness.

Action inputs:

| Input | Default | Purpose |
|---|---|---|
| `files` | `Dockerfile` | Space-separated paths or glob patterns |
| `min-severity` | `info` | Minimum reported severity |
| `skip` | empty | Comma-separated rule IDs to skip |
| `no-roast` | `false` | Use technical messages only |
| `no-fail` | `false` | Keep the workflow step non-blocking |
| `image-tag` | `latest` | Select the container version used by the action |

Non-blocking rollout:

```yaml
- uses: immanuwell/dockerfile-roast@1.4.2
  with:
    files: .
    min-severity: info
    no-roast: true
    no-fail: true
    image-tag: 1.4.2
```

Skip reviewed exceptions:

```yaml
- uses: immanuwell/dockerfile-roast@1.4.2
  with:
    files: .
    skip: DF012,DF022
    no-roast: true
    image-tag: 1.4.2
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
            ghcr.io/immanuwell/droast:1.4.2 \
            --format sarif --no-roast --no-fail . > droast.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: droast.sarif
```

### GitLab CI

```yaml
droast:
  image:
    name: ghcr.io/immanuwell/droast:1.4.2
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
              ghcr.io/immanuwell/droast:1.4.2 \
              --no-roast --min-severity warning .

workflows:
  lint:
    jobs:
      - droast
```

### Jenkins

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
            ghcr.io/immanuwell/droast:1.4.2 \
            --no-roast --min-severity warning .
        '''
      }
    }
  }
}
```

### Azure Pipelines

```yaml
steps:
  - checkout: self
  - script: |
      docker run --rm \
        -v "$(Build.SourcesDirectory):/workspace" \
        -w /workspace \
        ghcr.io/immanuwell/droast:1.4.2 \
        --no-roast --min-severity warning .
    displayName: Lint Dockerfiles
```

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
droast --config .droast/production.toml .
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
  ghcr.io/immanuwell/droast:1.4.2 \
  --no-roast .
```

### Lint one file

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/immanuwell/droast:1.4.2 \
  Dockerfile
```

### Write JSON to the host

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/immanuwell/droast:1.4.2 \
  --format json --no-roast --no-fail . > droast.json
```

### Read-only mount

Linting does not need to change the repository:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -w /workspace \
  ghcr.io/immanuwell/droast:1.4.2 \
  --no-roast .
```

## VS Code

The extension shows findings as editor diagnostics while Dockerfiles are edited.

Install it:

```bash
code --install-extension ImmanuelTikhonov.droast
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
| `droast.executablePath` | Use a specific executable path |
| `droast.minSeverity` | Select `info`, `warning`, or `error` |
| `droast.skipRules` | Suppress rule IDs |
| `droast.noRoast` | Show technical text only |

Leave `droast.executablePath` empty to use the bundled executable or a `droast` executable on `PATH`.

## Web version

Open [the droast web linter](https://ewry.net/droast-dockerfile-linter/).

Paste a Dockerfile to get immediate findings without installing a binary. The linter runs in the browser through WebAssembly, so the Dockerfile does not need to be sent to a linting service.

Use the web version for quick experiments. Use the CLI for repository discovery, effective build contexts, `.dockerignore`, configuration, output formats, and CI.

## Rust library

The crate exposes parser, rules, linter, repository, configuration, and output modules.

Add it:

```toml
[dependencies]
dockerfile-roast = "1.4.2"
```

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

Run `droast --list-rules` for the installed version. This catalog describes all 71 rules in version 1.4.2.

### Base images, stages, and reproducibility

| Rule | Severity | Check |
|---|---|---|
| DF001 | warning | Use a specific base image tag instead of `latest` |
| DF005 | info | Pin package versions for repeatable builds |
| DF011 | warning | Use multi-stage builds when they reduce the final image |
| DF023 | warning | Give multiple `FROM` stages aliases |
| DF024 | warning | Avoid `:latest` on aliased stages |
| DF042 | error | Keep stage aliases unique |
| DF061 | warning | Avoid fixed `--platform` in `FROM` unless required |
| DF065 | warning | Review images from unrecognized registries |
| DF069 | warning | Avoid package upgrades that make builds non-repeatable |

### Users, secrets, and command safety

| Rule | Severity | Check |
|---|---|---|
| DF002 | error | Do not leave the final image running as root |
| DF010 | warning | Do not use `sudo` inside a container |
| DF013 | error | Do not store secrets in `ENV` |
| DF014 | error | Do not hardcode passwords or tokens in `ARG` or `ENV` |
| DF020 | warning | Set an explicit non-root `USER` |
| DF021 | error | Do not pipe remote downloads directly to a shell |
| DF034 | error | Do not use `chmod 777` |
| DF057 | warning | Set `pipefail` for shell pipelines |
| DF066 | warning | Set an appropriate `SHELL` before Bash-specific syntax |

### Layers, files, and build context

| Rule | Severity | Check |
|---|---|---|
| DF003 | warning | Combine related `RUN` commands to reduce layers |
| DF006 | warning | Prefer `COPY` over `ADD` for local files |
| DF007 | warning | Avoid broad `COPY . .` operations |
| DF008 | info | Use `WORKDIR` instead of inline `cd` |
| DF009 | warning | Use absolute `WORKDIR` paths |
| DF026 | warning | Avoid recursive copies from filesystem root |
| DF033 | info | Use an effective `.dockerignore` for each build context |
| DF048 | error | End multi-source `COPY` destinations with `/` |
| DF049 | warning | Copy only from an earlier, defined stage |
| DF050 | error | Do not copy from the current stage |
| DF063 | warning | Set `WORKDIR` before a relative `COPY` destination |
| DF067 | info | Consider `ADD` when local tar auto-extraction is intended |
| DF070 | warning | Avoid a broad copy before dependency installation |

### Package managers and caches

| Rule | Severity | Check |
|---|---|---|
| DF004 | warning | Clean OS package caches in the same layer |
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
| DF052 | warning | Pin versions installed by apk |
| DF053 | warning | Pin versions installed by gem |
| DF054 | warning | Pin `go install` targets with `@version` |
| DF055 | info | Clean the Yarn cache after installation |
| DF059 | warning | Use `apt-get` or `apt-cache` instead of `apt` in scripts |

### Downloads and network tools

| Rule | Severity | Check |
|---|---|---|
| DF035 | info | Make curl fail on HTTP and transfer errors |
| DF056 | info | Limit wget progress output in build logs |
| DF058 | warning | Use either wget or curl consistently |

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
| DF036 | warning | Give runnable images a `CMD` or `ENTRYPOINT` |
| DF038 | warning | Keep only one effective `CMD` |
| DF039 | error | Keep only one effective `ENTRYPOINT` |
| DF040 | error | Keep `EXPOSE` ports in the range 0 through 65535 |
| DF041 | error | Keep only one effective `HEALTHCHECK` |
| DF060 | info | Remove pointless interactive commands |
| DF062 | error | Do not self-reference an `ENV` variable in one statement |
| DF064 | warning | Use `useradd -l` to avoid oversized user metadata layers |
| DF068 | error | Do not use forbidden instructions as `ONBUILD` triggers |

### Syntax

| Rule | Severity | Check |
|---|---|---|
| DF037 | error | Begin with `FROM`, global `ARG`, or a comment |
| DF071 | error | Keep Dockerfile syntax valid |

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
droast --config .droast/strict.toml --check-dockerignore true .
```

Run the same command locally, in pre-commit, and in CI.

### Security gate plus full advisory scan

Use two CI jobs:

```bash
# Blocking security gate
droast --no-roast \
  --only DF002,DF013,DF014,DF020,DF021,DF025,DF034,DF057,DF065,DF071 .

# Full advisory report
droast --no-roast --no-fail --min-severity info .
```

### Release image review

Lint the actual release Dockerfile and its context through the repository entry point:

```bash
droast --config .droast/strict.toml .
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

Set an absolute executable path:

```json
{
  "droast.executablePath": "/usr/local/bin/droast"
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

No. The examples in this guide are copy-paste configurations and commands. This keeps every rule choice visible in the repository.

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
