# Compatibility corpus

The corpus is a reproducible local download of real Dockerfiles, not checked
into this repository. The manifest records each upstream repository, immutable
commit, source URL, SPDX metadata, checksum, and structural features so a test
run can be reproduced without redistributing third-party source.

Fetch the default 2,500-file corpus with:

```bash
scripts/fetch-compatibility-corpus.sh
```

Use a different destination or target while investigating a parser regression:

```bash
DROAST_CORPUS_TARGET=100 scripts/fetch-compatibility-corpus.sh /tmp/droast-corpus
```

The downloader refuses to overwrite an existing corpus. Its selection excludes
test fixtures and documentation, requires a `FROM` instruction, and caps each
repository so a single monorepo cannot dominate the result. Validate all files
with `scripts/run-compatibility-corpus.sh`.
