#!/usr/bin/env bash
# Throughput test: write to output file
set -euo pipefail
OUTPUT="/tmp/composer_tp_output.txt"
count=0
while IFS= read -r line; do
    count=$((count + 1))
    echo "$line" >> "$OUTPUT"
done
echo "collect: ${count} lines written" >&2
