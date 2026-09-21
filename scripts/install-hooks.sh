#!/usr/bin/env bash
# Point git at the repo's hooks so the private-data check runs on every commit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
echo "hooks installed (core.hooksPath=.githooks)"
