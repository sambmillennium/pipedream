#!/usr/bin/env bash
# setup_test.sh — Copies test scripts into place and generates sha256 hashes
# Run after install.sh, before pipeline-composer deploy
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Setting up test composables ==="

# Copy test scripts
for script in generate filter store; do
    src="${SCRIPT_DIR}/${script}.sh"
    dst="/usr/local/bin/composer-test-${script}"
    cp "$src" "$dst"
    chmod +x "$dst"
    echo "Installed: $dst"
done

echo ""
echo "=== SHA-256 hashes (paste into pipeline_test.yaml) ==="
echo ""
for script in generate filter store; do
    dst="/usr/local/bin/composer-test-${script}"
    hash=$(pipeline-composer hash "$dst" | awk '{print $1}')
    echo "  ${script}: ${hash}"
done

echo ""
echo "Update test/pipeline_test.yaml with these hashes, then run:"
echo "  pipeline-composer validate test/pipeline_test.yaml"
echo "  sudo pipeline-composer deploy test/pipeline_test.yaml"
echo "  sudo pipeline-composer run test/pipeline_test.yaml"
