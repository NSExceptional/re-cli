#!/usr/bin/env bash
# Cut a re-cli release end to end: pre-flight checks, version bump, GitHub release,
# Homebrew tap update, and install.
#
#   scripts/release.sh <version>      e.g. scripts/release.sh 0.3.0
#
# Requires: gh (authed), brew with the nscake/tap tapped, node on PATH.
set -euo pipefail

VERSION="${1:?usage: scripts/release.sh <version>  (e.g. 0.3.0)}"
REPO="NSExceptional/re-cli"
TAP_FORMULA="$(brew --repository)/Library/Taps/nscake/homebrew-tap/Formula/re-cli.rb"
TARBALL="https://github.com/${REPO}/archive/refs/tags/v${VERSION}.tar.gz"

cd "$(dirname "$0")/.."

# 0. Pre-flight: a release must typecheck and pass tests.
npm run typecheck
npm test

# 1. Bump package.json version, commit, push.
/usr/bin/sed -i '' -E "s/\"version\": \"[0-9][0-9.]*\"/\"version\": \"${VERSION}\"/" package.json
git add package.json
git commit -m "Release v${VERSION}"
git push origin main

# 2. Tag + GitHub release with auto-generated notes (creates the tag at current main).
gh release create "v${VERSION}" --repo "$REPO" --title "v${VERSION}" --generate-notes

# 3. sha256 of the published tarball.
SHA="$(curl -fsSL "$TARBALL" | shasum -a 256 | awk '{print $1}')"
[ "${#SHA}" -eq 64 ] || { echo "error: bad sha256 '$SHA'" >&2; exit 1; }

# 4. Point the tap formula at the new version + sha, commit, push.
/usr/bin/sed -i '' \
  -e "s|archive/refs/tags/v[0-9][0-9.]*\.tar\.gz|archive/refs/tags/v${VERSION}.tar.gz|" \
  -e "s|sha256 \"[0-9a-f]*\"|sha256 \"${SHA}\"|" \
  "$TAP_FORMULA"
( cd "$(dirname "$TAP_FORMULA")/.." \
  && git add Formula/re-cli.rb \
  && git commit -m "re-cli ${VERSION}" \
  && git push )

# 5. Install the stable build.
brew uninstall re-cli 2>/dev/null || true
HOMEBREW_NO_AUTO_UPDATE=1 brew install nscake/tap/re-cli

echo "Released and installed re-cli ${VERSION}: $(command -v re)"
