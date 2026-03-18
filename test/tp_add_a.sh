#!/usr/bin/env bash
# Throughput test: append ~1KB to each line (+1MB total)
set -euo pipefail
PAD=$(printf '%0.sA' $(seq 1 1000))
count=0
while IFS= read -r line; do
    count=$((count + 1))
    echo "${line}|${PAD}"
done
echo "add_a: ${count} lines" >&2
