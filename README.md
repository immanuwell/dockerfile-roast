![](media/dockerfile-image.png)

![](media/screenshot-1.png)

# droast

a dockerfile linter that actually has opinions. it catches bad practices and tells you about them in the least diplomatic way possible.

think of it as code review from a senior dev who's seen too many prod incidents and has stopped being polite about it.

## install

```bash
cargo install dockerfile-roast
```

or grab a prebuilt binary from the releases page if you'd rather not wait for the rust compiler to do its thing.

## usage

```bash
# the basics
droast Dockerfile

# lint an entire project
droast **/Dockerfile

# boring mode (no roasts, just facts)
droast --no-roast Dockerfile

# only care about real problems
droast --min-severity warning Dockerfile

# disagree with a rule? valid, we respect it
droast --skip DF001,DF012 Dockerfile

# ci-friendly output
droast --format github Dockerfile    # github actions annotations
droast --format json Dockerfile      # machine-readable
droast --format compact Dockerfile   # one line per finding
```

## github action

add droast to any repo in 5 lines:

```yaml
- uses: immanuwell/dockerfile-roast@1.0.0
```

full example (`.github/workflows/lint.yml`):

```yaml
name: Lint Dockerfiles

on: [push, pull_request]

jobs:
  droast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: immanuwell/dockerfile-roast@1.0.0
```

findings show up as inline annotations on the PR diff. no configuration required.

available inputs (all optional):

| input | default | description |
|-------|---------|-------------|
| `files` | `Dockerfile` | file(s) or glob to lint |
| `min-severity` | `info` | `info`, `warning`, or `error` |
| `skip` | — | comma-separated rule IDs to ignore |
| `no-roast` | `false` | technical output only, no jokes |
| `no-fail` | `false` | advisory mode — never blocks the build |
| `image-tag` | `latest` | pin to a specific droast release, e.g. `1.0.0` |

example with options:

```yaml
- uses: immanuwell/dockerfile-roast@1.0.0
  with:
    files: '**/Dockerfile'
    min-severity: warning
    skip: DF012,DF022
    no-fail: true        # report findings but don't block the PR
```

## docker

pull from ghcr and use immediately, no install needed:

```bash
# lint a Dockerfile in the current directory
docker run --rm -v "$(pwd)/Dockerfile":/Dockerfile ghcr.io/immanuwell/droast /Dockerfile

# lint any file, anywhere
docker run --rm -v /path/to/your/Dockerfile:/Dockerfile ghcr.io/immanuwell/droast /Dockerfile

# pass flags as usual
docker run --rm -v "$(pwd)/Dockerfile":/Dockerfile ghcr.io/immanuwell/droast \
    --no-roast --min-severity warning /Dockerfile
```

or build locally from source:

```bash
docker build -t droast .
docker run --rm -v "$(pwd)/Dockerfile":/Dockerfile droast /Dockerfile
```

the image is published automatically to `ghcr.io/immanuwell/droast` on every release tag.

## shell completions

add this once, never mistype `--min-severity` again:

```bash
# bash — add to .bashrc
source <(droast completion bash)

# zsh — add to .zshrc
droast completion zsh > ~/.zfunc/_droast

# fish — add to config.fish
droast completion fish | source
```

## what it catches

63 rules, ngl thats a lot. run `droast --list-rules` for the full breakdown.

the greatest hits:

| rule | crime |
|------|-------|
| DF001 | `FROM ubuntu:latest` — pick an actual tag |
| DF002 | running explicitly as root |
| DF004 | apt cache left in the image (you made a trash can) |
| DF011 | shipping the entire build toolchain to prod |
| DF013 | secrets in ENV vars (in your layers. forever. congrats) |
| DF021 | `curl \| sh` — no. |
| DF028 | split `apt-get update` + install in separate RUN layers |
| DF034 | `chmod 777` somewhere in there |
| DF037 | instruction before FROM (invalid Dockerfile) |
| DF039 | multiple ENTRYPOINT instructions |
| DF046 | dnf install without cache cleanup |
| DF051 | pip install without version pins |
| DF057 | pipe in RUN without `set -o pipefail` |
| DF059 | `apt` used instead of `apt-get` in scripts |
| DF063 | COPY to relative path with no WORKDIR set |

rule categories: base images · security · package managers · layer hygiene · instruction quality · service quality · python/node specifics

## exit codes

`0` = clean (or `--no-fail`), `1` = errors found.

`--no-fail` is useful for advisory CI runs where you want the output but dont want to block the build yet.

## license

MIT. do whatever.
