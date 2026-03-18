#!/usr/bin/env bash
# Stage 1: EMIT — produces 10 plain text lines on stdout
set -euo pipefail

echo "emit: starting" >&2

for i in $(seq 1 10); do
    echo "line${i}"
    echo "emit: sent line${i}" >&2
    sleep 0.05
done

echo "emit: done — 10 lines" >&2
