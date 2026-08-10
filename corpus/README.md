# Validation corpus

This directory lets anyone reconstruct the corpus of real-world Dockerfiles that droast is validated against, and re-derive the published statistics from it.

The Dockerfiles themselves are **not** stored here. They remain copyrighted by their upstream authors under their own licenses. What is stored is a manifest that pins every file to an immutable commit and records its SHA-256, so the corpus can be rebuilt from its origin on your machine and verified byte for byte.

## Corpus summary

| Metric | Value |
|---|---:|
| Dockerfiles | 649 |
| Upstream repositories | 203 |
| Multi-stage Dockerfiles | 351 |
| Files using heredocs | 25 |
| Files using `RUN --mount` | 111 |
| Median line count | 80 |
| Maximum line count | 2,279 |
| Total source size | 2,866,395 bytes |

Sources include BuildKit, Buildx, Compose, Moby, Kubernetes, Grafana, Prometheus, Argo CD, Gitea, GitLab, Nextcloud, Supabase, Airbyte, Mattermost, Airflow, Superset, Kafka, Pulsar, Envoy, Istio, Cilium, Harbor, Terraform, LinuxServer, Bitnami, the official Docker Library images, Caddy, Kong, APISIX, Calico, Jupyter, Prefect, Dagster, Metabase, MongoDB, MariaDB, RabbitMQ, vLLM, Ray, Hugging Face TGI, PyTorch, TensorFlow, Kubeflow, Beam, OPA, Kyverno, and other production projects.

## Reproduce

```bash
corpus/rehydrate.sh     # fetch all 649 files from their pinned commits
corpus/stats.sh         # scan them and print the published numbers
```

`rehydrate.sh` refuses any file whose SHA-256 does not match the manifest, so a silently changed upstream file cannot contaminate the results. Re-running it is cheap: files already present and matching are left alone.

```bash
corpus/rehydrate.sh --verify-only    # check an existing corpus, download nothing
corpus/rehydrate.sh --jobs 12        # more parallel downloads
DROAST=./target/release/droast corpus/stats.sh
```

`stats.sh` passes `--check-dockerignore=false`. This matters: corpus samples are detached from their upstream build contexts, so `DF033` would otherwise fire on every file for a missing `.dockerignore` that does exist in the real repository.

## Benchmark

```bash
corpus/benchmark.sh 30
```

Runs droast and Hadolint over the same lexically sorted file list, interleaved, with the execution order reversed each iteration, after three untimed warm-up scans. It measures execution speed and binary size only. Finding totals between the two tools are not directly comparable, because they have different rule sets, severities, shell-analysis coverage, and parser behavior.

## Files

| File | Purpose |
|---|---|
| `manifest.tsv` | one row per Dockerfile: repository, commit, upstream path, source URL, license, structural statistics, SHA-256 |
| `repositories.tsv` | the 203 repository snapshots, each pinned to a commit |
| `rehydrate.sh` | rebuilds the corpus from the manifest and verifies every checksum |
| `stats.sh` | reproduces the published summary and rule frequency table |
| `benchmark.sh` | reproduces the speed and binary-size comparison |
| `select-corpus.sh` | the original selection pass, kept for provenance |

## A note on `select-corpus.sh`

This is the script that originally chose the corpus. It resolves each repository's **current** default branch and picks files from it, so running it today produces a *different* corpus than the one recorded in `manifest.tsv`. It is here to document how the sample was selected, not to reproduce it. Use `rehydrate.sh` for reproduction.

Selection worked as follows: start from a curated list of established production repositories, resolve each default branch to an exact commit SHA, find files named like `Dockerfile`, `Dockerfile.*`, `Containerfile`, or `Containerfile.*`, exclude paths under tests, fixtures, examples, documentation and vendored code, require at least 25 lines and one `FROM`, reject templates that are not valid Dockerfiles until rendered, prefer multi-stage and larger files, and cap samples per repository to preserve diversity.

This is a curated stress corpus, not a statistically random sample of all Dockerfiles. A file's presence does not imply that every upstream practice in it is recommended. Some samples require repository-specific build contexts and are not expected to build standalone.

## Licensing

Repository-level SPDX identifiers in `manifest.tsv` and `repositories.tsv` are informational and may not describe every file-specific exception. Entries marked `NOASSERTION` need individual review. If you redistribute any fetched file, inspect the exact upstream license at the recorded commit and preserve required notices.

`corpus/files/` is gitignored so a local rehydrate is never committed back.

## Sample IDs

IDs are stable provenance keys, not contiguous. Removed or disqualified entries leave gaps so existing references stay valid. To find where a sample came from:

```bash
awk -F'\t' '$1 == "sample-013"' corpus/manifest.tsv
```

The sixth field is a permanent raw source URL pinned to the recorded commit.
