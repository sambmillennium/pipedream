#!/usr/bin/env bash
# Throughput test: emit ~1MB (1000 lines x ~1KB each)
set -euo pipefail
PAD=$(printf '%0.sX' $(seq 1 1000))
i=0
while [ "$i" -lt 1000 ]; do
    i=$((i + 1))
    echo "${i}|${PAD}"
done
echo "emit: 1000 lines ~1MB" >&2
