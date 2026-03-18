#!/usr/bin/env bash
# Stage 3: ADD_B — prepends [B] to each line
set -euo pipefail

echo "add_b: starting" >&2
count=0

while IFS= read -r line; do
    count=$((count + 1))
    echo "[B]${line}"
    echo "add_b: processed line ${count}" >&2
done

echo "add_b: done — ${count} lines" >&2
