#!/usr/bin/env bash
# Stage 1: GENERATE — produces numbered JSON lines on stdout
set -euo pipefail

echo "generate: starting, emitting 20 records" >&2

for i in $(seq 1 20); do
    ts=$(date -u +%Y-%m-%dT%H:%M:%S)
    case $((i % 4)) in
        0) sev="error" ;;
        1) sev="info" ;;
        2) sev="warn" ;;
        3) sev="debug" ;;
    esac
    echo "{\"id\":${i},\"ts\":\"${ts}\",\"severity\":\"${sev}\",\"msg\":\"event ${i}\"}"
    echo "generate: emitted record ${i} severity=${sev}" >&2
    sleep 0.1
done

echo "generate: done" >&2
