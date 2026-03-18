#!/usr/bin/env bash
# Stage 2: ADD_A — prepends [A] to each line
set -euo pipefail

echo "add_a: starting" >&2
count=0

while IFS= read -r line; do
    count=$((count + 1))
    echo "[A]${line}"
    echo "add_a: processed line ${count}" >&2
done

echo "add_a: done — ${count} lines" >&2
