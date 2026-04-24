#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-0ai-Cyberviser/peachfuzz}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required. Install from https://cli.github.com/ and run: gh auth login" >&2
  exit 1
fi

git init
git add .
git commit -m "feat: initial PeachFuzz AI harness" || true
git branch -M main
gh repo create "$REPO" --public --source=. --remote=origin --push
echo "Deployed to https://github.com/$REPO"
