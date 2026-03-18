#!/usr/bin/env bash
# Stage 2: FILTER — reads JSON from stdin, passes only warn/error severity
set -euo pipefail

echo "filter: starting, accepting severity=warn,error" >&2

count=0
passed=0

while IFS= read -r line; do
    count=$((count + 1))
    if command -v jq &>/dev/null; then
        sev=$(echo "$line" | jq -r '.severity' 2>/dev/null)
    else
        sev=$(echo "$line" | grep -oP '"severity"\s*:\s*"\K[^"]+' 2>/dev/null || echo "")
    fi

    case "$sev" in
        warn|error)
            echo "$line"
            passed=$((passed + 1))
            echo "filter: PASS record (severity=${sev})" >&2
            ;;
        *)
            echo "filter: DROP record (severity=${sev})" >&2
            ;;
    esac
done

echo "filter: done — ${passed}/${count} records passed" >&2
