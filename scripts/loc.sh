#!/usr/bin/env bash
# Line counts for the size-reduction effort: shipped code vs tests.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
files=$(git ls-files | grep -E '\.(py|js|jsx|css|sh|ya?ml|toml|ini|html)$' | grep -vE '(^|/)(uv\.lock|package-lock\.json)$|snapshots/|fixtures/')
prod=$(echo "$files" | grep -vE '^tests/|^site/e2e/|\.test\.|^site/src/test/')
test=$(echo "$files" | grep -E '^tests/|^site/e2e/|\.test\.|^site/src/test/')
echo "PROD_LINES=$(echo "$prod" | xargs cat | wc -l)"
echo "TEST_LINES=$(echo "$test" | xargs cat | wc -l)"
