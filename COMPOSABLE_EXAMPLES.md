# Composable Examples

A composable is any executable that reads from stdin and writes to stdout. PipeDream handles all plumbing, security, and isolation. Diagnostic output goes to stderr.

## Rules

1. Read from **stdin**, write to **stdout**
2. Diagnostic/logging output goes to **stderr**
3. Exit 0 on success
4. Handle EOF on stdin (the upstream stage closed its output)

---

## Flanking Systems: Ingress and Egress

PipeDream pipelines are designed to sit between external systems. The **ingress FIFO** accepts data from upstream producers, the pipeline processes it, and the **egress FIFO** delivers results to downstream consumers. The flanking systems never touch the pipeline internals — they only interact with the named FIFOs at the edges.

```
                        PipeDream Pipeline
                        ┌─────────────────────────────────────────┐
  Upstream              │                                         │              Downstream
  Systems ──────────>   │  ingress ──> [stages] ──> egress        │   ──────────> Systems
  (writers)             │  FIFO                     FIFO          │              (readers)
                        └─────────────────────────────────────────┘
```

### Pipeline YAML for flanking system integration

```yaml
pipeline:
  name: "log_pipeline"
  settings:
    hmac_signing: true
    ingress_writers:        # System users allowed to push data into the pipeline
      - "syslog_service"
      - "app_ingest"
    egress_readers:         # System users allowed to consume pipeline output
      - "siem_collector"
      - "audit_archive"

  composables:
    - name: "sanitize"
      binary: "/usr/local/bin/sanitize_logs"
      sha256: "..."
      # stdin defaults to ingress FIFO: /var/run/composer/fifos/log_pipeline_ingress

    - name: "enrich"
      binary: "/usr/local/bin/enrich_logs"
      sha256: "..."

    - name: "classify"
      binary: "/usr/local/bin/classify_logs"
      sha256: "..."
      # stdout defaults to egress FIFO: /var/run/composer/fifos/log_pipeline_egress
```

---

## Ingress Writers (Upstream Producers)

These examples show how flanking systems feed data into a running pipeline via the ingress FIFO.

### Bash: stream a log file into the pipeline

```bash
#!/bin/bash
# Feed a log file into the pipeline's ingress FIFO
INGRESS="/var/run/composer/fifos/log_pipeline_ingress"

cat /var/log/application.log > "$INGRESS"
```

### Bash: tail a live log into the pipeline

```bash
#!/bin/bash
# Continuously feed new log lines into the pipeline
INGRESS="/var/run/composer/fifos/log_pipeline_ingress"

tail -F /var/log/syslog > "$INGRESS"
```

### Bash: produce synthetic data for testing

```bash
#!/bin/bash
# Generate test records and push them into the pipeline
INGRESS="/var/run/composer/fifos/log_pipeline_ingress"

for i in $(seq 1 1000); do
    echo "{\"id\": $i, \"severity\": \"info\", \"msg\": \"test event $i\"}"
    sleep 0.01
done > "$INGRESS"
```

### Python: application writing events to the pipeline

```python
#!/usr/bin/env python3
"""Application that writes structured events into the pipeline's ingress FIFO."""
import json, time

INGRESS = "/var/run/composer/fifos/log_pipeline_ingress"

events = [
    {"ts": "2025-01-01T00:00:00Z", "severity": "error", "src": "auth", "msg": "login failed"},
    {"ts": "2025-01-01T00:00:01Z", "severity": "info", "src": "auth", "msg": "login success"},
    {"ts": "2025-01-01T00:00:02Z", "severity": "warn", "src": "disk", "msg": "space low"},
]

with open(INGRESS, "w") as fifo:
    for event in events:
        fifo.write(json.dumps(event) + "\n")
        fifo.flush()
        time.sleep(0.1)
```

### Python: bridge an API into the pipeline

```python
#!/usr/bin/env python3
"""Poll an API and feed results into the pipeline."""
import json, time, urllib.request

INGRESS = "/var/run/composer/fifos/log_pipeline_ingress"
API_URL = "http://internal-service:8080/events"

with open(INGRESS, "w") as fifo:
    while True:
        try:
            with urllib.request.urlopen(API_URL, timeout=5) as resp:
                data = json.loads(resp.read())
                for record in data.get("events", []):
                    fifo.write(json.dumps(record) + "\n")
                    fifo.flush()
        except Exception as e:
            print(f"poll error: {e}", flush=True)
        time.sleep(5)
```

### C: high-throughput ingress writer

```c
/* ingress_writer.c — Write lines to the pipeline's ingress FIFO at high speed.
   Compile: gcc -O2 -o ingress_writer ingress_writer.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    const char *fifo = "/var/run/composer/fifos/log_pipeline_ingress";
    if (argc > 1) fifo = argv[1];

    FILE *out = fopen(fifo, "w");
    if (!out) { perror("fopen ingress"); return 1; }

    char buf[4096];
    /* Read from our own stdin (e.g. another process) and forward to the pipeline */
    while (fgets(buf, sizeof(buf), stdin)) {
        fputs(buf, out);
        fflush(out);
    }

    fclose(out);
    return 0;
}
```

### Go: ingress writer service

```go
// ingress_writer.go — Long-running service that writes to the pipeline ingress FIFO.
// Build: CGO_ENABLED=0 go build -o ingress_writer ingress_writer.go
package main

import (
    "bufio"
    "fmt"
    "os"
    "time"
)

func main() {
    fifo := "/var/run/composer/fifos/log_pipeline_ingress"
    if len(os.Args) > 1 {
        fifo = os.Args[1]
    }

    f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
    if err != nil {
        fmt.Fprintf(os.Stderr, "open ingress: %v\n", err)
        os.Exit(1)
    }
    defer f.Close()

    w := bufio.NewWriter(f)
    for i := 0; ; i++ {
        fmt.Fprintf(w, "{\"seq\": %d, \"ts\": \"%s\"}\n", i, time.Now().UTC().Format(time.RFC3339))
        w.Flush()
        time.Sleep(100 * time.Millisecond)
    }
}
```

### systemd service: ingress writer as a managed service

```ini
# /etc/systemd/system/pipeline-ingress-writer.service
[Unit]
Description=Write application logs to PipeDream pipeline
After=composer-log_pipeline.service
Requires=composer-log_pipeline.service

[Service]
Type=simple
User=syslog_service
ExecStart=/bin/bash -c 'tail -F /var/log/application.log > /var/run/composer/fifos/log_pipeline_ingress'
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

---

## Egress Readers (Downstream Consumers)

These examples show how flanking systems consume output from a running pipeline via the egress FIFO.

### Bash: write pipeline output to a file

```bash
#!/bin/bash
# Consume pipeline output and write to a file
EGRESS="/var/run/composer/fifos/log_pipeline_egress"

cat "$EGRESS" > /var/log/pipeline_output.jsonl
```

### Bash: forward pipeline output to a remote system

```bash
#!/bin/bash
# Read from egress and forward each line to a remote syslog over TCP
EGRESS="/var/run/composer/fifos/log_pipeline_egress"
REMOTE="siem.internal:514"

while IFS= read -r line; do
    echo "$line" | nc -q0 "$REMOTE"
done < "$EGRESS"
```

### Python: egress reader that archives to disk with rotation

```python
#!/usr/bin/env python3
"""Read pipeline output and write to rotating log files."""
import os, time

EGRESS = "/var/run/composer/fifos/log_pipeline_egress"
OUTPUT_DIR = "/var/archive/pipeline"
MAX_LINES = 10000

os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(EGRESS, "r") as fifo:
    file_idx = 0
    line_count = 0
    out = open(os.path.join(OUTPUT_DIR, f"batch_{file_idx:04d}.jsonl"), "w")

    for line in fifo:
        out.write(line)
        out.flush()
        line_count += 1

        if line_count >= MAX_LINES:
            out.close()
            file_idx += 1
            line_count = 0
            out = open(os.path.join(OUTPUT_DIR, f"batch_{file_idx:04d}.jsonl"), "w")

    out.close()
```

### Python: egress reader that posts to an API

```python
#!/usr/bin/env python3
"""Read pipeline output and POST each batch to a downstream API."""
import json, urllib.request

EGRESS = "/var/run/composer/fifos/log_pipeline_egress"
API_URL = "http://downstream-service:9090/ingest"
BATCH_SIZE = 50

batch = []
with open(EGRESS, "r") as fifo:
    for line in fifo:
        batch.append(json.loads(line))
        if len(batch) >= BATCH_SIZE:
            payload = json.dumps({"records": batch}).encode()
            req = urllib.request.Request(API_URL, data=payload,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
            batch = []
    # flush remainder
    if batch:
        payload = json.dumps({"records": batch}).encode()
        req = urllib.request.Request(API_URL, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
```

### C: high-throughput egress reader

```c
/* egress_reader.c — Read pipeline output at high speed and write to stdout.
   Compile: gcc -O2 -o egress_reader egress_reader.c */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    const char *fifo = "/var/run/composer/fifos/log_pipeline_egress";
    if (argc > 1) fifo = argv[1];

    FILE *in = fopen(fifo, "r");
    if (!in) { perror("fopen egress"); return 1; }

    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, stdout);
        fflush(stdout);
    }

    fclose(in);
    return 0;
}
```

### Go: egress consumer service

```go
// egress_reader.go — Long-running service that reads from the pipeline egress FIFO.
// Build: CGO_ENABLED=0 go build -o egress_reader egress_reader.go
package main

import (
    "bufio"
    "fmt"
    "os"
)

func main() {
    fifo := "/var/run/composer/fifos/log_pipeline_egress"
    if len(os.Args) > 1 {
        fifo = os.Args[1]
    }

    f, err := os.Open(fifo)
    if err != nil {
        fmt.Fprintf(os.Stderr, "open egress: %v\n", err)
        os.Exit(1)
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
    count := 0
    for scanner.Scan() {
        // Process each line from the pipeline
        fmt.Println(scanner.Text())
        count++
    }
    fmt.Fprintf(os.Stderr, "egress: read %d records\n", count)
}
```

### systemd service: egress reader as a managed service

```ini
# /etc/systemd/system/pipeline-egress-reader.service
[Unit]
Description=Read PipeDream pipeline output and archive
After=composer-log_pipeline.service
Requires=composer-log_pipeline.service

[Service]
Type=simple
User=siem_collector
ExecStart=/usr/local/bin/egress_reader /var/run/composer/fifos/log_pipeline_egress
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

---

## End-to-End Patterns

### Pattern 1: Syslog to SIEM

An upstream syslog daemon writes raw logs into the pipeline. The pipeline sanitizes, enriches, and classifies them. A downstream SIEM collector reads the processed output.

```
  rsyslog ──> ingress FIFO ──> [sanitize → enrich → classify] ──> egress FIFO ──> SIEM agent
```

```yaml
pipeline:
  name: "syslog_to_siem"
  settings:
    ingress_writers: ["syslog"]
    egress_readers: ["siem_agent"]
  composables:
    - name: "sanitize"
      binary: "/usr/local/bin/redact_pii"
      sha256: "..."
    - name: "enrich"
      binary: "/usr/local/bin/add_geo_and_hostname"
      sha256: "..."
    - name: "classify"
      binary: "/usr/local/bin/severity_classifier"
      sha256: "..."
```

**Ingress side:**
```bash
# rsyslog action in /etc/rsyslog.d/pipeline.conf
action(type="ompipe" pipe="/var/run/composer/fifos/syslog_to_siem_ingress")
```

**Egress side:**
```bash
# SIEM agent reads processed logs
/usr/local/bin/siem_forwarder < /var/run/composer/fifos/syslog_to_siem_egress
```

### Pattern 2: Cross-domain data transfer

A high-side application pushes classified data into the pipeline. The pipeline applies content inspection, redaction, and format validation. A low-side service reads the sanitized output.

```
  high_side_app ──> ingress ──> [inspect → redact → validate] ──> egress ──> low_side_relay
```

```yaml
pipeline:
  name: "high_to_low"
  settings:
    hmac_signing: true
    ingress_writers: ["high_side_export"]
    egress_readers: ["low_side_import"]
  composables:
    - name: "inspect"
      binary: "/usr/local/bin/content_inspector"
      sha256: "..."
      required_files: ["/etc/cds/classification_rules.yaml"]
    - name: "redact"
      binary: "/usr/local/bin/pii_redactor"
      sha256: "..."
      required_files: ["/etc/cds/redaction_patterns.yaml"]
    - name: "validate"
      binary: "/usr/local/bin/schema_validator"
      sha256: "..."
      required_files: ["/etc/cds/output_schema.json"]
```

**Ingress writer (high-side application):**
```python
#!/usr/bin/env python3
"""High-side export service — writes documents to the CDS pipeline."""
import json

INGRESS = "/var/run/composer/fifos/high_to_low_ingress"

with open(INGRESS, "w") as fifo:
    for doc in get_approved_documents():  # your application logic
        fifo.write(json.dumps(doc) + "\n")
        fifo.flush()
```

**Egress reader (low-side relay):**
```python
#!/usr/bin/env python3
"""Low-side import service — reads sanitized documents from the CDS pipeline."""
import json

EGRESS = "/var/run/composer/fifos/high_to_low_egress"

with open(EGRESS, "r") as fifo:
    for line in fifo:
        doc = json.loads(line)
        deliver_to_low_side(doc)  # your application logic
```

### Pattern 3: IoT sensor pipeline

Edge sensors write readings into the pipeline. The pipeline validates, aggregates, and formats for cloud ingest. A cloud uploader reads the egress.

```
  sensor_daemon ──> ingress ──> [validate → aggregate → format] ──> egress ──> cloud_uploader
```

```yaml
pipeline:
  name: "sensor_ingest"
  settings:
    ingress_writers: ["sensor_daemon"]
    egress_readers: ["cloud_agent"]
  composables:
    - name: "validate"
      binary: "/usr/local/bin/sensor_validator"
      sha256: "..."
    - name: "aggregate"
      binary: "/usr/local/bin/rolling_average"
      sha256: "..."
    - name: "format"
      binary: "/usr/local/bin/cloud_formatter"
      sha256: "..."
```

---

## Pipeline Stage Composables

These are the processing stages that sit between the ingress and egress FIFOs. They read stdin and write stdout — PipeDream connects them via inter-stage FIFOs.

### Bash: grep filter

```bash
#!/bin/bash
set -euo pipefail
grep --line-buffered "ERROR" || true
```

### Bash: add timestamp

```bash
#!/bin/bash
set -euo pipefail
while IFS= read -r line; do
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${line}"
done
```

### Python: JSON severity filter

```python
#!/usr/bin/env python3
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

### Python: PII redactor

```python
#!/usr/bin/env python3
"""Redact email addresses and IP addresses from each line."""
import sys, re

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IP_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

for line in sys.stdin:
    line = EMAIL_RE.sub("[EMAIL_REDACTED]", line)
    line = IP_RE.sub("[IP_REDACTED]", line)
    sys.stdout.write(line)
    sys.stdout.flush()
```

### C: uppercase transformer

```c
/* uppercase.c — Convert all input to uppercase.
   Compile: gcc -O2 -o uppercase uppercase.c */
#include <stdio.h>
#include <ctype.h>

int main(void) {
    int c;
    while ((c = getchar()) != EOF)
        putchar(toupper(c));
    return 0;
}
```

### Go: JSON enricher

```go
// enrich.go — Add a hostname field to each JSON record.
// Build: CGO_ENABLED=0 go build -o enrich enrich.go
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

### Rust: hex encoder

```rust
// hexencode.rs — Hex-encode each line.
// Build: rustc -O -o hexencode hexencode.rs
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
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

### Native Linux tools as composables

Any tool that reads stdin and writes stdout works directly as a binary path in the pipeline YAML:

| Tool | Binary Path | What it does |
|------|------------|--------------|
| `cat` | `/bin/cat` | Passthrough |
| `grep` | `/bin/grep` | Filter lines by pattern |
| `sed` | `/bin/sed` | Stream editing / transforms |
| `awk` | `/bin/awk` | Field processing |
| `cut` | `/bin/cut` | Extract fields |
| `sort` | `/bin/sort` | Sort lines |
| `uniq` | `/bin/uniq` | Remove duplicate lines |
| `tr` | `/bin/tr` | Character translation |
| `gzip` | `/bin/gzip` | Compress stream |
| `base64` | `/bin/base64` | Encode/decode base64 |

---

## Tips

- **Flush output** — use `flush=True` in Python or line-buffered mode to avoid stalling the pipeline
- **Compiled binaries are fastest** — C/Go/Rust with buffered I/O can push 500+ MB/s through all security layers
- **`allow_fork: false`** for compiled binaries and native tools — tighter seccomp profile
- **`allow_network: false`** unless the composable genuinely needs network access
- **Ingress/egress FIFOs block** — a writer to the ingress will block until the pipeline is running and the first stage is reading; an egress reader will block until the last stage writes output
- **Multiple writers** — multiple processes can write to the ingress FIFO, but lines may interleave; for structured data, use a single writer or a multiplexer
- **Multiple readers** — only one process should read the egress FIFO at a time; if multiple consumers are needed, use a fan-out stage or tee to multiple files
