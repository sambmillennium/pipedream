#!/usr/bin/env bash
# Stage 5: COLLECT — writes final output to file
set -euo pipefail

OUTPUT="/tmp/composer_5stage_output.txt"

echo "collect: starting, writing to ${OUTPUT}" >&2
count=0

while IFS= read -r line; do
    count=$((count + 1))
    echo "$line" >> "$OUTPUT"
    echo "collect: wrote line ${count}" >&2
done

echo "collect: done — ${count} lines written to ${OUTPUT}" >&2
