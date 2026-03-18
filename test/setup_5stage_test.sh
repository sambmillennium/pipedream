#!/usr/bin/env bash
# setup_5stage_test.sh — Installs the 5-stage character-prepend test scripts
# Run after install.sh, before pipeline-composer deploy
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Setting up 5-stage test composables ==="

for script in emit add_a add_b add_c collect; do
    src="${SCRIPT_DIR}/${script}.sh"
    dst="/usr/local/bin/composer-5s-${script}"
    cp "$src" "$dst"
    chmod +x "$dst"
    echo "Installed: $dst"
done

echo ""
echo "=== SHA-256 hashes (paste into pipeline_5stage_test.yaml) ==="
echo ""
for script in emit add_a add_b add_c collect; do
    dst="/usr/local/bin/composer-5s-${script}"
    hash=$(sha256sum "$dst" | awk '{print $1}')
    echo "  ${script}: ${hash}"
done

echo ""
echo "Done. Now run:"
echo "  sudo pipeline-composer run test/pipeline_5stage_test.yaml"
echo "  cat /tmp/composer_5stage_output.txt"
echo ""
echo "Expected output: 10 lines, each like [C][B][A]line1"
