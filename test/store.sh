#!/usr/bin/env bash
# Stage 3: STORE — reads filtered JSON from stdin, writes to file
set -euo pipefail

OUTPUT="/tmp/composer_test_output.jsonl"

echo "store: starting, writing to ${OUTPUT}" >&2

count=0

while IFS= read -r line; do
    count=$((count + 1))
    echo "$line" >> "$OUTPUT"
    echo "store: wrote record ${count}" >&2
done

echo "store: done — ${count} records written to ${OUTPUT}" >&2
