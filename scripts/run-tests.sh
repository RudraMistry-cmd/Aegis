#!/usr/bin/env bash
# Builds the project and runs the unit and conformance suites.
# Usage: ./scripts/run-tests.sh [extra node --test arguments]
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Type-checking and building"
npx tsc -p tsconfig.json

echo "==> Running tests"
if [ "$#" -gt 0 ]; then
  node --test "$@"
else
  node --test "dist/test/**/*.test.js"
fi

echo "==> Done"
