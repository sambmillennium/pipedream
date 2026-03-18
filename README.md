# PipeDream

### PipeDream is a Linux security cheat code to help users to rapidly chain Linux applications into a unidirectional pipeline of components connected by named FIFOs, with each stage isolated by DAC, SELinux MAC, seccomp filtering, namespace confinement, and cgroup enforcement.

Chaining applications together securely on Linux systems requires wrestling with SELinux policy, permissions and namespace isolation for hours. With PipeDream the isolation, enforcement and security layers are abstracted, it handles the plumbing and some of the security underneath so you can focus on security enforcing functions and other fun stuff at the application layer. 

You might us this for orchestrating components of a Cross Domain Solution, where information moves from one security context to another and absolutely cannot flow backwards. Or just for processing sensitive data through multiple stages where each stage needs to be isolated and tamper-proof. Whatever your use case all you do is describe your pipeline in YAML, Run a command and then get a pipeline of components.

## Security Model

Each pipeline stage ("composable") is configured with:

1. SHA-256 integrity verification during validation and wrapper pre-execution.

2. DAC isolation assigns per-composable UID and GID with FIFO permissions set to 0640.

3. SELinux MAC enforces per-domain types with compile-time neverallow rules.

4. Restricted syscalls through a per-composable whitelist in OCI JSON format.

5. Namespaces isolate PID, network, mount, IPC, and UTS via unshare.

6. cgroups v2 limits CPU, memory, and PID counts per stage.

7. Supervisor separation performs setup as root and then drops privileges to composer_sup.

8. HMAC signing validates inter-stage data with SHA-256 HMAC.

9. Stderr isolation separates stderr into per-stage files with rate limiting and SELinux types.

10. FD isolation opens FIFOs only after the privilege drop.

11. systemd hardening enables controls such as NoNewPrivileges, PrivateNetwork, PrivateTmp, PrivateIPC, ProtectProc, and MemoryDenyWriteExecute.

Unidirectionality is enforced at three independent levels: DAC (FIFO ownership checked at open), SELinux (`neverallow` reverse/non-adjacent FIFO access compile-time enforced), and application design (forward-only FIFO chaining).

### SELinux neverallow rules (compile-time enforced)

The generated policy includes `neverallow` rules verified by `checkmodule` at compile time. Any future policy change that would violate these constraints causes compilation to fail:

- No composable can **read** its own output FIFO (no loopback)
- No composable can **write** its own input FIFO (no reverse flow)
- No composable can access **non-adjacent** FIFOs (no skip-ahead/skip-back)
- No composable can **execute** another composable's binary
- No composable can **read or write** another composable's data files
- No composable can **read** its own stderr log (write-only, no readback)
- No composable can **access** another composable's stderr log
- No composable can **signal** another composable's process
- No composable can **execute** files labeled `var_run_t` (work dir scripts use `composer_wrapper_t`)
- The first composable cannot **write** to the ingress FIFO (read-only)
- No other composable can **access** the ingress FIFO at all
- The last composable cannot **read** from the egress FIFO (write-only)
- No other composable can **access** the egress FIFO at all

## Requirements

- RHEL 8+, CentOS Stream 8+, Rocky/Alma 8+, or Fedora
- SELinux in enforcing mode (permissive works but only logs violations)
- cgroups v2 (`systemd.unified_cgroup_hierarchy=1` — default on RHEL 9+, requires kernel cmdline on RHEL 8)
- Python 3.6+, bash
- Root access for installation and deployment

## Installation

```bash
sudo bash install.sh
```

This installs:
- `/usr/local/bin/pipeline-composer` (symlink to `/opt/composer/src/composer.py`)
- `/opt/composer/selinux/generate_policy.sh`
- Runtime dirs: `/var/run/composer/`, `/var/log/composer/`
- System user: `composer_sup`
- Dependencies: `policycoreutils-python-utils`, `selinux-policy-devel`, `checkpolicy`, `python3-libseccomp`, `acl`, PyYAML

## Usage

```
pipeline-composer <command> [options]
```

### Commands

| Command | Description |
|---------|-------------|
| `hash <binary>` | Print SHA-256 digest for use in pipeline YAML |
| `validate <config>` | Check config syntax, binary paths, and SHA-256 integrity |
| `plan <config>` | Dry-run showing users, DAC, SELinux setup without changes |
| `deploy <config> [--systemd]` | Create users, FIFOs, SELinux policy; optionally generate systemd unit |
| `run <config>` | Deploy + execute pipeline + wait for completion |
| `teardown <config>` | Remove users, FIFOs, SELinux module, cgroups, systemd unit |
| `generate-unit <config>` | Print systemd service unit to stdout |

Add `-v` for verbose logging.

### Typical workflow

```bash
# 1. Hash your binaries
pipeline-composer hash /usr/local/bin/my-stage-1
pipeline-composer hash /usr/local/bin/my-stage-2

# 2. Write pipeline.yaml (see Configuration below)

# 3. Validate
pipeline-composer validate pipeline.yaml

# 4. Deploy (creates users, FIFOs, SELinux policy, optional systemd unit)
sudo pipeline-composer deploy pipeline.yaml --systemd

# 5. Run
sudo pipeline-composer run pipeline.yaml
# or: sudo systemctl start composer-my_pipeline

# 6. Teardown when done
sudo pipeline-composer teardown pipeline.yaml
```

## Configuration

Pipelines are defined in YAML. Minimal example:

```yaml
pipeline:
  name: "my_pipeline"
  description: "Two-stage example"

  settings:
    fifo_dir: "/var/run/composer/fifos"
    log_dir: "/var/log/composer"
    run_dir: "/var/run/composer"
    selinux_enforce: true
    fifo_mode: "0640"
    umask: "0077"
    hmac_signing: false
    ingress_writers:            # Users allowed to write to the ingress FIFO (via POSIX ACLs)
      - "app_service"
      - "data_ingest"
    egress_readers:             # Users allowed to read from the egress FIFO (via POSIX ACLs)
      - "downstream_service"

  composables:
    - name: "producer"
      binary: "/usr/local/bin/my-producer"
      sha256: "abc123..."
      # stdin_source defaults to an ingress FIFO: {fifo_dir}/{pipeline_name}_ingress
      # Set explicitly to override (e.g., stdin_source: "/dev/null" for self-producing stages)

      resources:
        cpu_quota_percent: 50
        memory_max_mb: 256
        memory_high_mb: 200
        pids_max: 16
        nofile_soft: 64
        nofile_hard: 128

      seccomp:
        allow_network: false
        allow_fork: true

      namespaces:
        pid: true
        net: true
        mount: true
        ipc: true
        uts: true

    - name: "consumer"
      binary: "/usr/local/bin/my-consumer"
      sha256: "def456..."
      stdout_sink: "/dev/null"

      resources:
        cpu_quota_percent: 50
        memory_max_mb: 256
        memory_high_mb: 200
        pids_max: 16

      seccomp:
        allow_network: false
        allow_fork: true

      namespaces:
        pid: true
        net: true
        mount: true
        ipc: true
        uts: true

  reporting:
    method: "file"
    path: "/var/log/composer/pipeline-stderr.log"
    per_stage: true
    rate_limit_bytes: 1048576
    rate_interval_sec: 60
```

### Composable fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Alphanumeric + underscores only (no hyphens — SELinux constraint) |
| `binary` | yes | Absolute path to executable |
| `sha256` | yes | 64-char hex digest (use `pipeline-composer hash`) |
| `args` | no | List of CLI arguments |
| `description` | no | Human-readable description |
| `stdin_source` | no | Override stdin for first stage (default: ingress FIFO at `{fifo_dir}/{pipeline_name}_ingress`) |
| `stdout_sink` | no | Override stdout for last stage (default: egress FIFO at `{fifo_dir}/{pipeline_name}_egress`) |
| `resources` | no | CPU, memory, PID, nofile limits (see defaults below) |
| `seccomp` | no | Syscall whitelist config |
| `namespaces` | no | PID, net, mount, IPC, UTS isolation toggles |
| `env_whitelist` | no | Environment variables passed through (default: `PATH`, `LANG`, `LC_ALL`) |
| `required_files` | no | Files this stage needs read access to (POSIX ACL + SELinux labeled) |

### Resource defaults

```yaml
cpu_quota_percent: 50
memory_max_mb: 256
memory_high_mb: 200
pids_max: 16
nofile_soft: 64
nofile_hard: 128
```

Note: `io_max_read_mbps` and `io_max_write_mbps` are accepted in config but require block device specification in cgroups v2 (`MAJ:MIN`). They are reserved for future implementation.

### Seccomp defaults

Base syscall whitelist: `read`, `write`, `close`, `fstat`, `stat`, `lseek`, `mmap`, `mprotect`, `munmap`, `brk`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `ioctl`, `access`, `pipe`, `dup`, `dup2`, `nanosleep`, `clock_nanosleep`, `getpid`, `getppid`, `getpgrp`, `getuid`, `getgid`, `geteuid`, `getegid`, `arch_prctl`, `exit`, `exit_group`, `futex`, `openat`, `newfstatat`, `set_tid_address`, `set_robust_list`, `getrandom`, `pread64`, `pwrite64`, `sched_yield`, `mremap`, `prlimit64`, `rseq`, `fcntl`, `uname`, `sysinfo`.

`execve`/`execveat` are always allowed (needed by the seccomp loader to exec the target binary). SELinux `neverallow` rules independently block execution of unauthorized binaries at the MAC layer.

Set `allow_network: true` to add socket/connect/bind/listen/accept and related syscalls.
Set `allow_fork: true` to add clone/fork/wait syscalls (required for shell scripts).

## Writing Composables

Any executable that reads from stdin and writes to stdout works. PipeDream handles all plumbing via FIFOs.

**Shell scripts** work via `runcon` for SELinux domain entry. Set `allow_fork: true` in seccomp since bash needs `fork`/`execve`.

**Python scripts** work the same way. Use the script's absolute path as the binary.

**Compiled binaries** (C, Go, Rust) work directly. If statically linked, you can set `allow_fork: false` for tighter isolation — `execve` is still allowed for the seccomp loader, but SELinux prevents executing any binary other than the one declared.

Diagnostic output goes to stderr (per-stage log files with rate limiting). Only stdout data flows forward through the pipeline.

See [COMPOSABLE_EXAMPLES.md](COMPOSABLE_EXAMPLES.md) for ready-to-use examples in Bash, Python, C, Go, Rust, Perl, and AWK — including line-by-line processing, whole-document transforms, and native Linux tools used directly as composables.

## Test Pipeline

A 3-stage test pipeline is included: generate (20 JSON records) -> filter (pass warn/error only) -> store (write to file).

```bash
# 1. Install pipeline-composer
sudo bash install.sh

# 2. Install test scripts and get SHA-256 hashes
sudo bash test/setup_test.sh

# 3. Update test/pipeline_test.yaml with the printed hashes

# 4. Validate and run
pipeline-composer validate test/pipeline_test.yaml
sudo pipeline-composer run test/pipeline_test.yaml

# 5. Check output
cat /tmp/composer_test_output.jsonl

# 6. Check per-stage logs
cat /var/log/composer/generate.stderr.log
cat /var/log/composer/filter.stderr.log
cat /var/log/composer/store.stderr.log
```

Expected: 10 of 20 records pass the filter (5 warn + 5 error).

## Ingress and Egress FIFOs

By default, PipeDream creates named FIFOs at both ends of the pipeline so that external processes can feed data in and consume output without needing to know about the pipeline's internals.

### Ingress FIFO (pipeline input)

When no `stdin_source` is specified on the first composable, PipeDream creates an **ingress FIFO** at `{fifo_dir}/{pipeline_name}_ingress`. This is the entry point for feeding data into a running pipeline.

The ingress FIFO is owned by `composer_sup` (write) with the first stage's group (read), mode `0640`. By default only the `composer_sup` user can write to it.

To allow other system users to write to the ingress FIFO, use the `ingress_writers` setting:

```yaml
settings:
  ingress_writers:
    - "app_service"
    - "data_ingest"
```

**Feeding data into a running pipeline:**

```bash
cat input.txt > /var/run/composer/fifos/my_pipeline_ingress
```

To disable the ingress FIFO (e.g. for self-producing first stages), set `stdin_source: "/dev/null"` explicitly on the first composable.

### Egress FIFO (pipeline output)

When no `stdout_sink` is specified on the last composable, PipeDream creates an **egress FIFO** at `{fifo_dir}/{pipeline_name}_egress`. External processes read from this FIFO to consume pipeline output.

The egress FIFO is owned by the last stage's UID (write) with the `composer_sup` group (read), mode `0640`. By default only `composer_sup` can read from it.

To allow other system users to read from the egress FIFO, use the `egress_readers` setting:

```yaml
settings:
  egress_readers:
    - "downstream_service"
    - "log_collector"
```

**Reading output from a running pipeline:**

```bash
cat /var/run/composer/fifos/my_pipeline_egress > output.txt
```

To discard output explicitly, set `stdout_sink: "/dev/null"` on the last composable (a warning will be logged). To write to a file instead, set `stdout_sink: "/path/to/file"`.

### End-to-end configuration

With both ingress and egress FIFOs, you can define a complete data path in the YAML config — external writers push data into the pipeline, it flows through all stages, and external readers consume the result:

```yaml
settings:
  ingress_writers: ["ingest_service"]
  egress_readers: ["output_service"]
```

Both ingress and egress FIFOs use POSIX ACLs for fine-grained user access and SELinux MAC for domain-level enforcement. DAC/ACLs are the controlling access layer.

## Architecture

```
                    Named FIFOs (unidirectional)
                    owner=writer, group=reader, mode 0640

              Ingress                                                    Egress
              FIFO                                                       FIFO
  External ──────>  ┌──────────┐         ┌──────────┐         ┌──────────┐  ──────> External
  writers           │ Stage 1  │  FIFO   │ Stage 2  │  FIFO   │ Stage 3  │          readers
                    │ uid=60001│ ──────> │ uid=60002│ ──────> │ uid=60003│
                    │ domain_1 │         │ domain_2 │         │ domain_3 │
                    └──────────┘         └──────────┘         └──────────┘
                     seccomp_1            seccomp_2            seccomp_3
                     cgroup_1             cgroup_2             cgroup_3
                     ns: pid,net,...      ns: pid,net,...      ns: pid,net,...
```

### Wrapper execution chain

For each composable, a bash wrapper is generated at runtime:

```
Outer wrapper (runs as root):
  1. sha256sum binary == expected?      ← re-verify integrity at launch
  2. echo $$ > cgroup/cgroup.procs     ← self-assign to cgroup (no race)
  3. exec unshare [ns flags] --        ← enter namespaces
  4.   setpriv --reuid --regid --inh-caps=-all  ← drop to composable UID/GID
  5.     runcon composer_stage_t        ← enter SELinux domain
  6.       /bin/bash -c '              ← INNER shell (runs as composable)
             ulimit -n 64;                  ← apply nofile limits
             exec seccomp_loader profile.json  ← apply BPF filter
               binary                          ← exec target
               < fifo_in > fifo_out            ← FDs opened HERE
               2> >(stderr_limiter >> log)'    ← rate-limited stderr
```

The inner `/bin/bash -c` runs after `setpriv` + `runcon`, so all file opens (FIFOs, stderr) happen under the composable's UID and SELinux domain. Both DAC and MAC are enforced at open().

When HMAC is enabled, the wrapper uses `pipefail` and a pipe chain:
```
hmac_verify < fifo_in | binary | hmac_sign > fifo_out
```
Each pipe segment runs under its own privilege-dropped inner shell.

### Multi-host CDS deployment

For higher assurance, deploy pipeline stages across separate hosts connected by hardware data diodes. Each host runs one or more stages; the data diode physically enforces unidirectionality between hosts, eliminating all same-host covert channels (timing, cache, resource exhaustion).

```
  Host A              Data Diode           Host B
  ┌──────────┐       (hardware)          ┌──────────┐
  │ Stage 1  │ ════════════════════════> │ Stage 2  │
  └──────────┘    one-way only           └──────────┘
```

## RHEL Version Compatibility

| Feature | RHEL 8 (systemd 239) | RHEL 9 (systemd 252) |
|---------|---------------------|---------------------|
| Core pipeline | Yes | Yes |
| SELinux MAC | Yes | Yes |
| seccomp-bpf | Yes | Yes |
| Namespaces | Yes | Yes |
| cgroups v2 | Requires kernel cmdline | Default |
| systemd: ProtectProc | N/A (skipped) | Yes |
| systemd: PrivateIPC | N/A (skipped) | Yes |
| systemd: RestrictSUIDSGID | N/A (skipped) | Yes |

The systemd unit generator detects the systemd version and only includes compatible directives. Core security (DAC, SELinux, seccomp, namespaces) works on all supported versions.

## Project Structure

```
PipeDream/
├── README.md
├── install.sh                 # RHEL installer
├── src/
│   └── composer.py            # Main CLI + orchestrator
├── selinux/
│   └── generate_policy.sh     # SELinux policy generator (TE + FC + IF)
├── test/
│   ├── setup_test.sh          # Install test scripts + print hashes
│   ├── generate.sh            # Test stage 1: emit JSON
│   ├── filter.sh              # Test stage 2: severity filter
│   ├── store.sh               # Test stage 3: write to file
│   └── pipeline_test.yaml     # Test pipeline config
└── examples/
```

## License

MIT License
