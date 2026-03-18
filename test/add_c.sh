#!/usr/bin/env bash
# Stage 4: ADD_C — prepends [C] to each line
set -euo pipefail

echo "add_c: starting" >&2
count=0

while IFS= read -r line; do
    count=$((count + 1))
    echo "[C]${line}"
    echo "add_c: processed line ${count}" >&2
done

echo "add_c: done — ${count} lines" >&2
