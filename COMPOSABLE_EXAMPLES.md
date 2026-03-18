# Composable Examples

A composable is any executable that reads from stdin and writes to stdout. PipeDream handles all plumbing, security, and isolation. Diagnostic output goes to stderr.

## Rules

1. Read from **stdin**, write to **stdout**
2. Diagnostic/logging output goes to **stderr**
3. Exit 0 on success
4. Handle EOF on stdin (the upstream stage closed its output)

---

## Bash

### Passthrough (identity)

```bash
#!/bin/bash
exec cat
```

### Line counter

```bash
#!/bin/bash
set -euo pipefail
count=0
while IFS= read -r line; do
    count=$((count + 1))
    echo "$line"
done
echo "processed ${count} lines" >&2
```

### Grep filter

```bash
#!/bin/bash
# Pass only lines containing "ERROR"
set -euo pipefail
grep --line-buffered "ERROR" || true
```

### Add timestamp to each line

```bash
#!/bin/bash
set -euo pipefail
while IFS= read -r line; do
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${line}"
done
```

### Field extractor (cut)

```bash
#!/bin/bash
# Extract the 2nd CSV field from each line
set -euo pipefail
cut -d',' -f2
```

### Rate limiter (1 line per second)

```bash
#!/bin/bash
set -euo pipefail
while IFS= read -r line; do
    echo "$line"
    sleep 1
done
```

### Deduplicator

```bash
#!/bin/bash
# Remove consecutive duplicate lines (like uniq)
set -euo pipefail
exec uniq
```

### Head (first N lines)

```bash
#!/bin/bash
# Pass only the first 100 lines
set -euo pipefail
head -n 100
```

### Tee to file

```bash
#!/bin/bash
# Pass data through while saving a copy
set -euo pipefail
tee /tmp/pipeline_capture.log
```

---

## Native Linux Tools as Composables

Any tool that reads stdin and writes stdout works directly as a binary path in the pipeline YAML. No wrapper script needed.

| Tool | Binary Path | What it does | seccomp notes |
|------|------------|--------------|---------------|
| `cat` | `/bin/cat` | Passthrough | `allow_fork: false` works |
| `grep` | `/bin/grep` | Filter lines by pattern | `allow_fork: false` works |
| `sed` | `/bin/sed` | Stream editing / transforms | `allow_fork: false` works |
| `awk` | `/bin/awk` | Field processing | `allow_fork: false` works |
| `cut` | `/bin/cut` | Extract fields | `allow_fork: false` works |
| `sort` | `/bin/sort` | Sort lines (buffers all input) | `allow_fork: false` works |
| `uniq` | `/bin/uniq` | Remove duplicate lines | `allow_fork: false` works |
| `head` | `/bin/head` | First N lines | `allow_fork: false` works |
| `tail` | `/bin/tail` | Last N lines | `allow_fork: false` works |
| `wc` | `/bin/wc` | Count lines/words/bytes | `allow_fork: false` works |
| `tr` | `/bin/tr` | Character translation | `allow_fork: false` works |
| `tee` | `/bin/tee` | Duplicate stream to file | `allow_fork: false` works |
| `base64` | `/bin/base64` | Encode/decode base64 | `allow_fork: false` works |
| `gzip` | `/bin/gzip` | Compress stream | `allow_fork: false` works |
| `zcat` | `/bin/zcat` | Decompress stream | `allow_fork: false` works |
| `openssl` | `/usr/bin/openssl` | Encrypt/hash stream | `allow_fork: false`, may need `allow_network: true` for some modes |

Example YAML using `sed` directly:

```yaml
- name: "sanitize"
  binary: "/bin/sed"
  args: ["s/password=[^ ]*/password=REDACTED/g"]
  sha256: "..."
  seccomp:
    allow_network: false
    allow_fork: false    # sed doesn't need fork
```

---

## Python

### JSON field filter

```python
#!/usr/bin/env python3
"""Pass only JSON records where severity is 'error' or 'warn'."""
import sys, json

for line in sys.stdin:
    try:
        rec = json.loads(line)
        if rec.get("severity") in ("error", "warn"):
            sys.stdout.write(line)
            sys.stdout.flush()
    except json.JSONDecodeError:
        pass
```

### CSV to JSON converter

```python
#!/usr/bin/env python3
"""Convert CSV lines to JSON objects. First line is the header."""
import sys, csv, json, io

reader = csv.DictReader(sys.stdin)
for row in reader:
    print(json.dumps(row), flush=True)
```

### Rolling average (stateful)

```python
#!/usr/bin/env python3
"""Compute a rolling average of a numeric field in JSON records."""
import sys, json
from collections import deque

window = deque(maxlen=10)
for line in sys.stdin:
    try:
        rec = json.loads(line)
        val = float(rec.get("value", 0))
        window.append(val)
        rec["rolling_avg"] = round(sum(window) / len(window), 2)
        print(json.dumps(rec), flush=True)
    except (json.JSONDecodeError, ValueError):
        sys.stdout.write(line)
        sys.stdout.flush()
```

### XML to JSON

```python
#!/usr/bin/env python3
"""Read XML records (one per line), emit JSON."""
import sys, json, xml.etree.ElementTree as ET

for line in sys.stdin:
    try:
        root = ET.fromstring(line.strip())
        obj = {child.tag: child.text for child in root}
        print(json.dumps(obj), flush=True)
    except ET.ParseError:
        pass
```

### SHA-256 hasher

```python
#!/usr/bin/env python3
"""Add a SHA-256 hash of each line's content."""
import sys, hashlib, json

for line in sys.stdin:
    h = hashlib.sha256(line.strip().encode()).hexdigest()
    rec = {"data": line.strip(), "sha256": h}
    print(json.dumps(rec), flush=True)
```

---

## C

### Uppercase transformer

```c
/* uppercase.c — Convert all input to uppercase.
   Compile: gcc -O2 -o uppercase uppercase.c
   seccomp: allow_fork: false works */
#include <stdio.h>
#include <ctype.h>

int main(void) {
    int c;
    while ((c = getchar()) != EOF)
        putchar(toupper(c));
    return 0;
}
```

### Line length filter

```c
/* maxlen.c — Drop lines longer than 1024 bytes.
   Compile: gcc -O2 -o maxlen maxlen.c */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[4096];
    while (fgets(buf, sizeof(buf), stdin)) {
        if (strlen(buf) <= 1025)  /* 1024 + newline */
            fputs(buf, stdout);
    }
    return 0;
}
```

### Byte counter (sink)

```c
/* bytecount.c — Count bytes and report to stderr. Useful as final stage.
   Compile: gcc -O2 -o bytecount bytecount.c */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[65536];
    long long total = 0;
    ssize_t n;
    while ((n = read(0, buf, sizeof(buf))) > 0)
        total += n;
    fprintf(stderr, "total bytes: %lld\n", total);
    return 0;
}
```

---

## Go

### JSON enricher

```go
// enrich.go — Add a hostname field to each JSON record.
// Build: CGO_ENABLED=0 go build -o enrich enrich.go
// seccomp: allow_fork: false, allow_network: false
package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "os"
)

func main() {
    host, _ := os.Hostname()
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
    for scanner.Scan() {
        var rec map[string]interface{}
        if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
            continue
        }
        rec["host"] = host
        out, _ := json.Marshal(rec)
        fmt.Println(string(out))
    }
}
```

### Rate counter

```go
// ratecount.go — Count lines per second, report to stderr.
// Build: CGO_ENABLED=0 go build -o ratecount ratecount.go
package main

import (
    "bufio"
    "fmt"
    "os"
    "time"
)

func main() {
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
    count := 0
    start := time.Now()
    for scanner.Scan() {
        fmt.Println(scanner.Text())
        count++
    }
    elapsed := time.Since(start).Seconds()
    if elapsed > 0 {
        fmt.Fprintf(os.Stderr, "%d lines in %.1fs (%.0f lines/s)\n", count, elapsed, float64(count)/elapsed)
    }
}
```

---

## Rust

### Hex encoder

```rust
// hexencode.rs — Hex-encode each line.
// Build: rustc -O -o hexencode hexencode.rs
// seccomp: allow_fork: false, allow_network: false
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io.stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        if let Ok(l) = line {
            for b in l.bytes() {
                write!(out, "{:02x}", b).unwrap();
            }
            writeln!(out).unwrap();
        }
    }
}
```

---

## Perl

### Regex substitution

```perl
#!/usr/bin/perl
# Replace email addresses with [REDACTED]
use strict;
use warnings;

while (<STDIN>) {
    s/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[REDACTED]/g;
    print;
}
```

---

## AWK one-liners as composables

Use `/bin/awk` as the binary with `args`:

```yaml
# Sum a numeric column and emit at end
- name: "summer"
  binary: "/bin/awk"
  args: ["{sum += $1} END {print sum}"]
  sha256: "..."

# Print lines where field 3 > 100
- name: "threshold"
  binary: "/bin/awk"
  args: ["-F,", "$3 > 100"]
  sha256: "..."

# Reformat fields
- name: "reformat"
  binary: "/bin/awk"
  args: ["-F:", "{print $1, $3, $5}"]
  sha256: "..."
```

---

## Whole-Document Transforms

The previous examples process data line-by-line. But composables can also buffer the entire input, transform it as a whole, and write the result. The pipeline doesn't care — a FIFO is just a byte stream. The downstream stage simply blocks until your composable writes output.

For whole-document transforms, set `memory_max_mb` high enough to hold the buffered content.

### XML to JSON (Python)

```python
#!/usr/bin/env python3
"""Read an entire XML document from stdin, convert to JSON, write to stdout."""
import sys, json, xml.etree.ElementTree as ET

xml_data = sys.stdin.read()
root = ET.fromstring(xml_data)

def elem_to_dict(elem):
    result = {}
    for child in elem:
        if len(child):
            result[child.tag] = elem_to_dict(child)
        else:
            result[child.tag] = child.text
    if elem.attrib:
        result["@attributes"] = elem.attrib
    return result

doc = {root.tag: elem_to_dict(root)}
json.dump(doc, sys.stdout, indent=2)
print()
```

### XSLT transform (Bash)

```bash
#!/bin/bash
# Apply an XSLT stylesheet to the full XML document on stdin
# Requires: libxslt (xsltproc)
set -euo pipefail
xsltproc /opt/data/transform.xsl -
```

### JSON schema validator (Python)

```python
#!/usr/bin/env python3
"""Validate a JSON document against a schema. Pass through if valid, exit 1 if not."""
import sys, json

SCHEMA_REQUIRED_KEYS = ["id", "timestamp", "payload"]

doc = json.load(sys.stdin)

missing = [k for k in SCHEMA_REQUIRED_KEYS if k not in doc]
if missing:
    print(f"validation failed: missing keys {missing}", file=sys.stderr)
    sys.exit(1)

json.dump(doc, sys.stdout)
print()
```

### JSON pretty-print / reformat (Python)

```python
#!/usr/bin/env python3
"""Read compact JSON, write pretty-printed."""
import sys, json
doc = json.load(sys.stdin)
json.dump(doc, sys.stdout, indent=2, sort_keys=True)
print()
```

### CSV to JSON (Python)

```python
#!/usr/bin/env python3
"""Read an entire CSV file (with header), emit a JSON array."""
import sys, csv, json

reader = csv.DictReader(sys.stdin)
records = list(reader)
json.dump(records, sys.stdout, indent=2)
print()
```

### Image resize (Bash + ImageMagick)

```bash
#!/bin/bash
# stdin = PNG image, stdout = resized PNG
# Requires: ImageMagick
set -euo pipefail
convert - -resize 800x600 -
```

### PDF to text (Bash)

```bash
#!/bin/bash
# stdin = PDF document, stdout = extracted plain text
# Requires: poppler-utils (pdftotext)
set -euo pipefail
pdftotext - -
```

### YAML to JSON (Python)

```python
#!/usr/bin/env python3
"""Read a YAML document, emit JSON."""
import sys, json, yaml
doc = yaml.safe_load(sys.stdin)
json.dump(doc, sys.stdout, indent=2)
print()
```

### Markdown to HTML (Bash)

```bash
#!/bin/bash
# stdin = Markdown, stdout = HTML
# Requires: pandoc
set -euo pipefail
pandoc -f markdown -t html
```

### Binary data: compress entire stream (Bash)

```bash
#!/bin/bash
# Read all of stdin, gzip compress, write to stdout
# Works with any binary data — no line parsing
set -euo pipefail
gzip -c
```

### Binary data: encrypt with OpenSSL (Bash)

```bash
#!/bin/bash
# Encrypt the entire stdin stream with AES-256-CBC
# Key should be in a required_file, not hardcoded
set -euo pipefail
KEY=$(cat /opt/data/encryption.key)
openssl enc -aes-256-cbc -salt -pass "pass:${KEY}" -pbkdf2
```

### Whole-document transform in C

```c
/* xmlcount.c — Read entire XML from stdin, count elements, emit JSON summary.
   Compile: gcc -O2 -o xmlcount xmlcount.c -lexpat
   seccomp: allow_fork: false */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <expat.h>

static int count = 0;
static void start_element(void *data, const char *el, const char **attr) {
    count++;
}

int main(void) {
    char buf[8192];
    size_t len;
    XML_Parser p = XML_ParserCreate(NULL);
    XML_SetStartElementHandler(p, start_element);

    while ((len = fread(buf, 1, sizeof(buf), stdin)) > 0) {
        if (XML_Parse(p, buf, len, feof(stdin)) == XML_STATUS_ERROR) {
            fprintf(stderr, "XML parse error: %s\n",
                    XML_ErrorString(XML_GetErrorCode(p)));
            return 1;
        }
    }
    XML_ParserFree(p);
    printf("{\"element_count\": %d}\n", count);
    return 0;
}
```

### Tips for whole-document composables

- **Memory**: Set `memory_max_mb` large enough for the full document plus processing overhead
- **Binary data**: Use `sys.stdin.buffer.read()` / `sys.stdout.buffer.write()` in Python to avoid UTF-8 encoding issues
- **Timeouts**: Large documents take longer to buffer — the pipeline waits naturally since FIFOs block until data arrives
- **Hybrid approach**: You can read the full document, process it, then stream output line-by-line (e.g. parse XML, emit one JSON line per element)

---

## Example Pipeline Patterns

### Log sanitizer (3-stage)

```
grep "ERROR\|WARN" → sed 's/password=.*/password=REDACTED/' → tee /var/log/filtered.log
```

### Data transformer (4-stage)

```
csv_to_json.py → enrich (Go binary) → json_filter.py → gzip > output.gz
```

### Network monitor (3-stage, allow_network on stage 1)

```
capture_tool → grep_filter.sh → store.py
```

### File integrity pipeline (3-stage)

```
find_files.sh → sha256_hasher.py → diff_checker.py
```

## Tips

- **Use `flush=True` in Python** or line-buffered mode to avoid stalling the pipeline
- **Compiled binaries are fastest** — C/Go/Rust with buffered I/O can push 500+ MB/s through all security layers
- **Set `allow_fork: false`** for compiled binaries and native tools — tighter seccomp profile since they don't need fork/clone
- **Set `allow_network: false`** unless the composable genuinely needs network access (rare in a CDS pipeline)
- **Bash `while read` is slow** (~0.9 MB/s) — fine for low-volume pipelines, use compiled binaries for high throughput
