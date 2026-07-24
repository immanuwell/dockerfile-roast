#!/usr/bin/env bash
# Prepare and publish a complete droast release.
#
# Usage: ./scripts/release.sh 1.4.9
#
# This updates every tracked release version, regenerates public metadata,
# validates the package, commits the preparation, pushes main, then creates and
# pushes the annotated tag that starts the GitHub release workflows.

set -euo pipefail

VERSION="${1:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

[[ "$#" == 1 ]] || die "usage: $0 <major.minor.patch> (for example: $0 1.4.9)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be major.minor.patch without a v prefix"

for command in cargo git gh jq npm perl; do
    require "$command"
done

cd "$REPO_ROOT"

[[ "$(git branch --show-current)" == "main" ]] || die "releases must be started from the main branch"

prepared_release_can_resume() {
    local changed_path crate_version extension_version wasmer_version
    while IFS= read -r changed_path; do
        case "$changed_path" in
            Cargo.toml|Cargo.lock|README.md|docs/index.html|action.yml|wasmer.toml|vscode-extension/package.json)
                ;;
            *)
                return 1
                ;;
        esac
    done < <(git status --porcelain | awk '{print $2}')

    crate_version="$(cargo metadata --no-deps --format-version 1 | jq -r \
        '.packages[] | select(.name == "dockerfile-roast") | .version')"
    extension_version="$(jq -r .version vscode-extension/package.json)"
    wasmer_version="$(awk -F '"' '/^version = / { print $2; exit }' wasmer.toml)"
    [[ "$crate_version" == "$VERSION" ]] && \
        [[ "$extension_version" == "$VERSION" ]] && \
        [[ "$wasmer_version" == "$VERSION" ]]
}

if [[ -n "$(git status --porcelain)" ]]; then
    if prepared_release_can_resume; then
        echo "Resuming interrupted release preparation for $VERSION."
    else
        die "working tree is not clean; commit, stash, or discard changes first"
    fi
fi

git fetch origin main --tags
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || \
    die "local main is not identical to origin/main; update it before releasing"
[[ -z "$(git tag --list "$VERSION")" ]] || die "local tag $VERSION already exists"
[[ -z "$(git ls-remote --tags origin "refs/tags/$VERSION")" ]] || die "remote tag $VERSION already exists"

if gh release view "$VERSION" --repo "$(gh repo view --json nameWithOwner -q .nameWithOwner)" >/dev/null 2>&1; then
    die "GitHub Release $VERSION already exists"
fi

export DROAST_RELEASE_VERSION="$VERSION"

# Keep the crate and lockfile in agreement without requiring cargo-edit.
perl -0pi -e '
    $count = s/^version = "[^"]+"/qq{version = "$ENV{DROAST_RELEASE_VERSION}"}/me;
    die "expected exactly one package version in Cargo.toml\n" unless $count == 1;
' Cargo.toml
perl -0pi -e '
    $count = s/(\[\[package\]\]\nname = "dockerfile-roast"\nversion = ")[^"]+"/${1}$ENV{DROAST_RELEASE_VERSION}"/;
    die "expected exactly one dockerfile-roast version in Cargo.lock\n" unless $count == 1;
' Cargo.lock

npm pkg set --prefix vscode-extension version="$VERSION" >/dev/null
./scripts/update-public-metadata.sh --version "$VERSION"

# The release changes public metadata before committing it, so --check would
# compare those intentional changes with HEAD and always fail. Run the
# generator again instead and require it to be idempotent.
metadata_before="$(git hash-object README.md docs/index.html action.yml wasmer.toml)"
./scripts/update-public-metadata.sh --version "$VERSION"
metadata_after="$(git hash-object README.md docs/index.html action.yml wasmer.toml)"
[[ "$metadata_before" == "$metadata_after" ]] || \
    die "public metadata generation is not idempotent"

crate_version="$(cargo metadata --no-deps --format-version 1 | jq -r \
    '.packages[] | select(.name == "dockerfile-roast") | .version')"
extension_version="$(jq -r .version vscode-extension/package.json)"
wasmer_version="$(awk -F '"' '/^version = / { print $2; exit }' wasmer.toml)"
[[ "$crate_version" == "$VERSION" ]] || die "Cargo.toml version is $crate_version, expected $VERSION"
[[ "$extension_version" == "$VERSION" ]] || die "VS Code extension version is $extension_version, expected $VERSION"
[[ "$wasmer_version" == "$VERSION" ]] || die "wasmer.toml version is $wasmer_version, expected $VERSION"

cargo test --locked
cargo publish --dry-run --locked --allow-dirty
git diff --check

git add Cargo.toml Cargo.lock README.md docs/index.html action.yml wasmer.toml vscode-extension/package.json
git diff --staged --quiet && die "release preparation produced no changes"
git commit -m "chore: release version $VERSION"
git push origin main

git tag -a "$VERSION" -m "$VERSION"
git push origin "refs/tags/$VERSION"

echo "Release $VERSION prepared and tagged successfully."
echo "GitHub Actions is now publishing binaries, crates.io, Docker, and Wasmer."
