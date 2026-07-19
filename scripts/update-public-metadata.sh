#!/usr/bin/env bash
# Regenerate public rule metadata and release examples from the droast binary.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
README="$REPO_ROOT/README.md"
SITE="$REPO_ROOT/docs/index.html"
ACTION="$REPO_ROOT/action.yml"
WASMER="$REPO_ROOT/wasmer.toml"
CHECK=false

if [[ "${1:-}" == "--check" ]]; then
    CHECK=true
elif [[ $# -ne 0 ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi

for command in cargo jq perl awk; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command not found: $command" >&2
        exit 1
    }
done

echo "Building droast..."
cargo build --quiet --manifest-path "$REPO_ROOT/Cargo.toml"

DROAST="$REPO_ROOT/target/debug/droast"
[[ -x "$DROAST" ]] || {
    echo "droast binary not found at $DROAST" >&2
    exit 1
}

RULES_JSON="$("$DROAST" --list-rules --format json)"
jq -e '
    type == "array" and length > 0 and
    all(.[];
        (.id | type == "string" and test("^DF[0-9]{3}$")) and
        (.severity | type == "string" and test("^(ERROR|WARN|INFO)$")) and
        (.categories | type == "array" and length > 0 and all(.[]; type == "string")) and
        (.description | type == "string" and length > 0)
    )
' >/dev/null <<<"$RULES_JSON" || {
    echo "droast returned invalid rule metadata" >&2
    exit 1
}

RULE_COUNT="$(jq -r 'length' <<<"$RULES_JSON")"
DUPLICATE_IDS="$(jq -r '.[].id' <<<"$RULES_JSON" | sort | uniq -d)"
[[ -z "$DUPLICATE_IDS" ]] || {
    echo "duplicate rule IDs returned by droast: $DUPLICATE_IDS" >&2
    exit 1
}

VERSION="$(cargo metadata --no-deps --format-version 1 --manifest-path "$REPO_ROOT/Cargo.toml" \
    | jq -r '.packages[] | select(.name == "dockerfile-roast") | .version')"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "invalid dockerfile-roast version: $VERSION" >&2
    exit 1
}

RULE_LIST="$({
    printf '\n  Available Rules\n\n'
    printf '  %-8s %-8s %-34s %s\n' 'ID' 'SEVERITY' 'CATEGORIES' 'DESCRIPTION'
    printf '  %s\n' '──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────'
    while IFS=$'\t' read -r id severity categories description; do
        printf '  %-8s %-8s %-34s %s\n' "$id" "$severity" "$categories" "$description"
    done < <(jq -r '.[] | [.id, .severity, (.categories | join(",")), .description] | @tsv' <<<"$RULES_JSON")
    printf '\n  Use --skip DF001,DF002 to suppress specific rules.\n'
    printf '  Use --min-severity warning to hide INFO findings.\n'
})"

replace_block() {
    local file="$1"
    local begin="$2"
    local end="$3"
    local block="$4"
    local begin_count end_count temporary

    begin_count="$(grep -Fxc "$begin" "$file")"
    end_count="$(grep -Fxc "$end" "$file")"
    [[ "$begin_count" == 1 && "$end_count" == 1 ]] || {
        echo "expected exactly one marker pair in $file: $begin / $end" >&2
        exit 1
    }

    temporary="$(mktemp "$file.tmp.XXXXXX")"
    awk -v begin="$begin" -v end="$end" -v block="$block" '
        $0 == begin { print block; replacing=1; next }
        $0 == end   { replacing=0; next }
        !replacing  { print }
    ' "$file" >"$temporary"
    chmod --reference="$file" "$temporary"
    mv "$temporary" "$file"
}

RULES_BEGIN='<!-- BEGIN RULES -->'
RULES_END='<!-- END RULES -->'
RULES_BLOCK="$RULES_BEGIN
<details>
<summary data-droast-rule-count>all $RULE_COUNT rules</summary>

\`\`\`
$RULE_LIST
\`\`\`

</details>
$RULES_END"
replace_block "$README" "$RULES_BEGIN" "$RULES_END" "$RULES_BLOCK"

export DROAST_PUBLIC_RULE_COUNT="$RULE_COUNT"
perl -0pi -e 's/\b\d+ ([Rr]ules)\b/$ENV{DROAST_PUBLIC_RULE_COUNT} $1/g' \
    "$README" "$SITE" "$ACTION"

export DROAST_PUBLIC_VERSION="$VERSION"
perl -0pi -e '
    $regions = s{
        (<!--\ droast:action-version:start\ -->)
        (.*?)
        (<!--\ droast:action-version:end\ -->)
    }{
        $start = $1; $body = $2; $end = $3;
        $versions = ($body =~ s/\b\d+\.\d+\.\d+\b/$ENV{DROAST_PUBLIC_VERSION}/g);
        die "expected four release versions in README action examples\n" unless $versions == 4;
        "$start$body$end";
    }gsex;
    die "expected one generated action-version region in README\n" unless $regions == 1;
' "$README"

perl -pi -e '
    if (/droast:release-version/) {
        $versions = s/\b\d+\.\d+\.\d+\b/$ENV{DROAST_PUBLIC_VERSION}/g;
        die "expected one release version on marked action.yml line\n" unless $versions == 1;
    }
' "$ACTION"

perl -pi -e '
    if (/droast:release-version/) {
        $versions = s/\b\d+\.\d+\.\d+\b/$ENV{DROAST_PUBLIC_VERSION}/g;
        die "expected one release version on marked wasmer.toml line\n" unless $versions == 1;
    }
' "$WASMER"

STALE_COUNTS="$(grep -Eohi '[0-9]+ rules' "$README" "$SITE" "$ACTION" \
    | grep -Eiv "^${RULE_COUNT} rules$" || true)"
[[ -z "$STALE_COUNTS" ]] || {
    echo "stale public rule counts remain: $STALE_COUNTS" >&2
    exit 1
}

if $CHECK; then
    if ! git -C "$REPO_ROOT" diff --exit-code -- README.md docs/index.html action.yml wasmer.toml >/dev/null; then
        echo "public metadata is stale; run ./scripts/update-public-metadata.sh and commit the result" >&2
        exit 1
    fi
    echo "Public metadata is synchronized: $RULE_COUNT rules, version $VERSION."
else
    echo "Updated public metadata: $RULE_COUNT rules, version $VERSION."
fi
