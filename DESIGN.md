# PipeDream — Design Document

## 1. Overview

PipeDream (pipeline_composer) is a security-hardened orchestrator for **unidirectional data processing pipelines** on RHEL-based Linux systems. It chains arbitrary executables together via named FIFOs, enforcing strict forward-only data flow through 12 independent security layers: DAC, SELinux MAC, seccomp-bpf, Linux namespaces, cgroups v2, HMAC signing, systemd hardening, binary integrity verification, supervisor privilege separation, stderr isolation, FD isolation, and required-files isolation.

Designed for **Cross Domain Solutions** and sensitive data processing where information must flow strictly forward through pipeline stages with no possibility of backward flow.

---

## 2. High-Level Architecture

```mermaid
graph TB
    subgraph User
        CONFIG[pipeline.yaml]
        CLI[pipeline-composer CLI]
    end

    subgraph "Orchestrator (Root → composer_sup)"
        PARSE[Config Parser]
        VALIDATE[Validator]
        SETUP_U[User Manager]
        SETUP_D[DAC Manager]
        SETUP_S[SELinux Manager]
        RUNNER[PipelineRunner]
    end

    subgraph "Runtime Artifacts"
        FIFOS[Named FIFOs]
        WRAPPERS[Wrapper Scripts]
        SECCOMP[Seccomp Profiles]
        HMAC_W[HMAC Wrappers]
        STDERR_L[Stderr Limiter]
        CGROUPS[cgroup Hierarchies]
    end

    subgraph "Execution Sandbox (per stage)"
        NS[Linux Namespaces]
        SP[setpriv — UID/GID Drop]
        RC[runcon — SELinux Domain]
        BPF[seccomp-bpf Filter]
        BIN[User Binary]
    end

    CONFIG --> CLI
    CLI --> PARSE --> VALIDATE
    VALIDATE --> SETUP_U --> SETUP_D --> SETUP_S --> RUNNER

    RUNNER --> WRAPPERS
    RUNNER --> SECCOMP
    RUNNER --> HMAC_W
    RUNNER --> STDERR_L
    RUNNER --> CGROUPS

    WRAPPERS --> NS --> SP --> RC --> BPF --> BIN

    BIN -- "stdin" --> FIFOS
    FIFOS -- "stdout" --> BIN
```

---

## 3. CLI Command Flow

```mermaid
flowchart LR
    subgraph Commands
        HASH[hash]
        VAL[validate]
        PLAN[plan]
        DEPLOY[deploy]
        RUN[run]
        TEAR[teardown]
        UNIT[generate-unit]
    end

    HASH -- "Print SHA-256 of binary" --> OUT1((stdout))
    VAL -- "Parse + verify config" --> OUT2((pass/fail))
    PLAN -- "Dry-run: show what deploy would do" --> OUT3((stdout))
    DEPLOY -- "Create users, FIFOs,\nSELinux policy, cgroups" --> SYS((System State))
    RUN -- "Deploy + execute pipeline" --> PROC((Running Pipeline))
    TEAR -- "Remove users, FIFOs,\nSELinux module, cgroups" --> CLEAN((Cleaned State))
    UNIT -- "Generate systemd\nservice file" --> UNITF((service file))
```

---

## 4. Pipeline Data Flow

```mermaid
flowchart LR
    SRC["stdin_source\n(/dev/null or file)"]

    subgraph "Stage 1 (UID 60001)"
        B1["Binary A\n(producer)"]
    end

    subgraph "Stage 2 (UID 60002)"
        B2["Binary B\n(transform)"]
    end

    subgraph "Stage 3 (UID 60003)"
        B3["Binary C\n(consumer)"]
    end

    SINK["stdout_sink\n(/dev/null or file)"]

    SRC --> B1
    B1 -- "FIFO 1→2\nowner=60001\ngroup=60002\nmode 0640" --> B2
    B2 -- "FIFO 2→3\nowner=60002\ngroup=60003\nmode 0640" --> B3
    B3 --> SINK

    style B1 fill:#2d6a4f,color:#fff
    style B2 fill:#2d6a4f,color:#fff
    style B3 fill:#2d6a4f,color:#fff
```

### With HMAC Signing Enabled

```mermaid
flowchart LR
    subgraph "Stage N"
        BN[Binary N] --> SIGN[HMAC Signer\nSHA-256]
    end

    SIGN -- "sig:data\nvia FIFO" --> VERIFY

    subgraph "Stage N+1"
        VERIFY[HMAC Verifier\nSHA-256] --> BN1[Binary N+1]
    end

    style SIGN fill:#e76f51,color:#fff
    style VERIFY fill:#e76f51,color:#fff
```

---

## 5. Setup & Deployment Sequence

```mermaid
sequenceDiagram
    actor User
    participant CLI as pipeline-composer
    participant OS as Linux Kernel / Subsystems
    participant SEL as SELinux

    User->>CLI: run pipeline.yaml

    rect rgb(40, 40, 60)
        Note over CLI: Phase 1 — Parse & Validate (as root)
        CLI->>CLI: parse_config(YAML)
        CLI->>CLI: validate_pipeline()
        CLI->>OS: sha256sum each binary
        OS-->>CLI: hash match ✓
    end

    rect rgb(40, 60, 40)
        Note over CLI: Phase 2 — System Setup (as root)
        CLI->>OS: useradd per-composable UIDs (60000+)
        CLI->>OS: mkfifo + chown + chmod 0640
        CLI->>OS: setfacl for required_files
        CLI->>SEL: generate_policy.sh → TE + FC + IF
        CLI->>SEL: checkmodule (compile + neverallow check)
        CLI->>SEL: semodule -i (load policy)
        CLI->>SEL: restorecon (label FIFOs, binaries, logs)
    end

    rect rgb(60, 40, 40)
        Note over CLI: Phase 3 — Generate Runtime Artifacts
        CLI->>CLI: seccomp profiles (OCI JSON)
        CLI->>CLI: seccomp loader (Python BPF)
        CLI->>CLI: HMAC sign/verify scripts
        CLI->>CLI: stderr rate limiter
        CLI->>CLI: per-stage wrapper scripts
    end

    rect rgb(60, 60, 40)
        Note over CLI: Phase 4 — Launch Pipeline
        loop For each composable
            CLI->>OS: setup cgroup (cpu, mem, pids)
            CLI->>OS: Popen(bash wrapper_script.sh)
        end
        CLI->>OS: drop privileges → composer_sup
    end

    Note over CLI: Phase 5 — Monitor & Cleanup
    CLI->>OS: wait() on all children
    CLI->>OS: remove FIFOs, cgroups, work dir
```

---

## 6. Per-Stage Wrapper Execution

Each composable runs inside a wrapper script that applies all isolation layers:

```mermaid
flowchart TD
    START([Wrapper Script Starts]) --> INTEGRITY

    INTEGRITY["1. Binary Integrity Check\nsha256sum == expected?"]
    INTEGRITY -- "Mismatch" --> ABORT([Exit 99])
    INTEGRITY -- "Match ✓" --> CGROUP

    CGROUP["2. Self-assign to cgroup\necho $$ > cgroup.procs"]
    CGROUP --> UNSHARE

    UNSHARE["3. unshare\n--pid --net --mount --ipc --uts"]
    UNSHARE --> SETPRIV

    SETPRIV["4. setpriv\n--reuid --regid --inh-caps=-all"]
    SETPRIV --> RUNCON

    RUNCON["5. runcon\ncomposer_{name}_t domain"]
    RUNCON --> INNER

    subgraph INNER["6. Inner Shell (unprivileged)"]
        ULIMIT["ulimit -n 64"]
        ULIMIT --> FIFO_OPEN["Open FIFOs\n(DAC + MAC enforced)"]
        FIFO_OPEN --> SECCOMP_LOAD["Apply seccomp-bpf\nvia Python loader"]
        SECCOMP_LOAD --> EXEC["exec binary\n< fifo_in > fifo_out\n2> stderr_limiter"]
    end

    style INTEGRITY fill:#264653,color:#fff
    style CGROUP fill:#2a9d8f,color:#fff
    style UNSHARE fill:#e9c46a,color:#000
    style SETPRIV fill:#f4a261,color:#000
    style RUNCON fill:#e76f51,color:#fff
    style INNER fill:#1a1a2e,color:#fff
```

---

## 7. Security Architecture — 12 Isolation Layers

```mermaid
graph TB
    subgraph "Layer 1: Binary Integrity"
        L1["SHA-256 verification\nat validate + launch"]
    end

    subgraph "Layer 2: DAC"
        L2["Per-stage UID/GID\nFIFO ownership 0640\nKernel-enforced at open()"]
    end

    subgraph "Layer 3: SELinux MAC"
        L3["Per-domain types\nneverallow rules\nCompile-time enforced"]
    end

    subgraph "Layer 4: seccomp-bpf"
        L4["Per-stage syscall whitelist\nOCI JSON → BPF filter"]
    end

    subgraph "Layer 5: Namespaces"
        L5["PID / Net / Mount / IPC / UTS\nPer-stage isolation"]
    end

    subgraph "Layer 6: cgroups v2"
        L6["CPU / Memory / PIDs\nPer-stage resource limits"]
    end

    subgraph "Layer 7: Supervisor Separation"
        L7["Root → composer_sup\nPrivilege drop after launch"]
    end

    subgraph "Layer 8: HMAC Signing"
        L8["SHA-256 HMAC per line\nInter-stage integrity"]
    end

    subgraph "Layer 9: Stderr Isolation"
        L9["Write-only logs\nRate limiting\nNo readback"]
    end

    subgraph "Layer 10: FD Isolation"
        L10["FIFOs opened post-drop\nNo inherited FDs"]
    end

    subgraph "Layer 11: systemd Hardening"
        L11["CapabilityBoundingSet\nProtectSystem=strict\nMemoryDenyWriteExecute"]
    end

    subgraph "Layer 12: Required Files"
        L12["POSIX ACLs\nSELinux data types\nPer-stage read-only"]
    end

    L1 --- L2 --- L3 --- L4 --- L5 --- L6
    L7 --- L8 --- L9 --- L10 --- L11 --- L12

    style L1 fill:#264653,color:#fff
    style L2 fill:#287271,color:#fff
    style L3 fill:#2a9d8f,color:#fff
    style L4 fill:#8ab17d,color:#000
    style L5 fill:#e9c46a,color:#000
    style L6 fill:#efb366,color:#000
    style L7 fill:#f4a261,color:#000
    style L8 fill:#ee8959,color:#fff
    style L9 fill:#e76f51,color:#fff
    style L10 fill:#d1495b,color:#fff
    style L11 fill:#9b2226,color:#fff
    style L12 fill:#6a040f,color:#fff
```

---

## 8. SELinux Policy Structure

```mermaid
graph LR
    subgraph "SELinux Domains"
        SUP["composer_supervisor_t"]
        D1["composer_stage1_t"]
        D2["composer_stage2_t"]
        D3["composer_stage3_t"]
    end

    subgraph "SELinux File Types"
        E1["composer_stage1_exec_t"]
        E2["composer_stage2_exec_t"]
        E3["composer_stage3_exec_t"]
        F12["composer_fifo_1_to_2_t"]
        F23["composer_fifo_2_to_3_t"]
        S1["composer_stderr_stage1_t"]
        S2["composer_stderr_stage2_t"]
        S3["composer_stderr_stage3_t"]
    end

    SUP -- "transition" --> D1
    SUP -- "transition" --> D2
    SUP -- "transition" --> D3

    D1 -- "entrypoint" --> E1
    D2 -- "entrypoint" --> E2
    D3 -- "entrypoint" --> E3

    D1 -- "write ✓" --> F12
    D2 -- "read ✓" --> F12
    D2 -- "write ✓" --> F23
    D3 -- "read ✓" --> F23

    D1 -- "append ✓" --> S1
    D2 -- "append ✓" --> S2
    D3 -- "append ✓" --> S3

    D1 -. "read ✗ (neverallow)" .-> F12
    D2 -. "write ✗ (neverallow)" .-> F12
    D3 -. "read/write ✗ (neverallow)" .-> F12
    D1 -. "read/write ✗ (neverallow)" .-> F23

    style SUP fill:#264653,color:#fff
    style D1 fill:#2a9d8f,color:#fff
    style D2 fill:#e9c46a,color:#000
    style D3 fill:#e76f51,color:#fff
```

### neverallow Rules (Compile-Time Enforced)

| Rule | Prevents |
|------|----------|
| No loopback reads | Stage cannot read its own output FIFO |
| No reverse flow | Stage cannot write to its input FIFO |
| No non-adjacent access | Stage cannot touch FIFOs it isn't connected to |
| No cross-stage exec | Stage cannot execute another stage's binary |
| No cross-stage data | Stage cannot read another stage's required_files |
| No stderr readback | Write-only log files per stage |
| No inter-stage signals | Stage cannot signal another stage's domain |

---

## 9. Configuration Data Model

```mermaid
classDiagram
    class Pipeline {
        +str name
        +str description
        +Settings settings
        +List~Composable~ composables
        +Reporting reporting
    }

    class Settings {
        +str fifo_dir = "/var/run/composer/fifos"
        +str log_dir = "/var/log/composer"
        +str run_dir = "/var/run/composer"
        +bool selinux_enforce = true
        +str fifo_mode = "0640"
        +str umask = "0077"
        +bool hmac_signing = true
        +bool continuous = false
    }

    class Composable {
        +str name
        +str binary
        +str sha256
        +List~str~ args
        +str description
        +str stdin_source
        +str stdout_sink
        +ResourceLimits resources
        +SeccompProfile seccomp
        +Dict namespaces
        +List~str~ env_whitelist
        +List~str~ required_files
    }

    class ResourceLimits {
        +int cpu_quota_percent = 50
        +int memory_max_mb = 256
        +int memory_high_mb = 200
        +int io_max_read_mbps = 50
        +int io_max_write_mbps = 50
        +int pids_max = 16
        +int nofile_soft = 64
        +int nofile_hard = 128
    }

    class SeccompProfile {
        +List~str~ allowed_syscalls
        +List~str~ extra_syscalls
        +bool allow_network = false
        +bool allow_fork = false
    }

    class Reporting {
        +str method = "file"
        +str path
        +bool per_stage = true
        +int rate_limit_bytes = 1048576
        +int rate_interval_sec = 60
    }

    Pipeline --> Settings
    Pipeline --> "2..*" Composable
    Pipeline --> Reporting
    Composable --> ResourceLimits
    Composable --> SeccompProfile
```

---

## 10. File System Layout

```mermaid
graph TD
    subgraph "/opt/composer (Installation)"
        SRC_DIR["src/composer.py"]
        SEL_DIR["selinux/generate_policy.sh"]
    end

    subgraph "/var/run/composer (Runtime)"
        FIFO_DIR["fifos/\nstage1_to_stage2\nstage2_to_stage3"]
        WORK_DIR["work/{pipeline}/\nwrappers/\nseccomp/\nhmac.key"]
    end

    subgraph "/var/log/composer (Logs)"
        LOG1["stage1.stderr.log"]
        LOG2["stage2.stderr.log"]
        LOG3["stage3.stderr.log"]
    end

    subgraph "/usr/local/bin"
        SYMLINK["pipeline-composer →\n/opt/composer/src/composer.py"]
    end

    style SRC_DIR fill:#264653,color:#fff
    style SEL_DIR fill:#264653,color:#fff
    style FIFO_DIR fill:#2a9d8f,color:#fff
    style WORK_DIR fill:#2a9d8f,color:#fff
    style LOG1 fill:#e76f51,color:#fff
    style LOG2 fill:#e76f51,color:#fff
    style LOG3 fill:#e76f51,color:#fff
```

---

## 11. Unidirectionality Enforcement — Three Independent Levels

```mermaid
flowchart LR
    subgraph "Level 1: DAC (Kernel)"
        DAC["FIFO owner = writer UID\nFIFO group = reader GID\nMode 0640\n→ Reverse write blocked by kernel"]
    end

    subgraph "Level 2: SELinux MAC (Policy)"
        MAC["neverallow rules compiled\ninto binary policy\n→ Reverse access denied\neven for root"]
    end

    subgraph "Level 3: Application Design"
        APP["FIFOs chained forward only\nNo backward stdin paths\nNo shared memory"]
    end

    DAC --> |"Independent"| MAC --> |"Independent"| APP

    style DAC fill:#2a9d8f,color:#fff
    style MAC fill:#e9c46a,color:#000
    style APP fill:#e76f51,color:#fff
```

Each level enforces unidirectionality **independently** — compromising one layer does not affect the others.

---

## 12. Multi-Host Deployment

```mermaid
flowchart LR
    subgraph "Host A"
        PA["PipeDream\nStage 1-2"]
    end

    subgraph "Data Diode (Hardware)"
        DD["One-way\nphysical link"]
    end

    subgraph "Host B"
        PB["PipeDream\nStage 3-4"]
    end

    PA -- "Forward only" --> DD -- "Forward only" --> PB

    style DD fill:#9b2226,color:#fff
```

For the highest assurance, stages can span physical hosts connected by a hardware data diode, with PipeDream enforcing software-level unidirectionality on each host independently.
