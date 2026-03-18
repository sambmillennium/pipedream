#!/usr/bin/env python3
"""
pipeline_composer - Unidirectional pipeline orchestrator with zero-trust enforcement.

Building blocks for an open cross-domain solution (CDS) on RHEL-based systems.

Security layers per composable:
  1. Binary integrity (SHA-256 verified at validation AND launch)
  2. Per-composable UID/GID (DAC isolation between stages)
  3. SELinux MAC (per-domain types, neverallow reverse flow, per-stage stderr types)
  4. seccomp-bpf (per-composable syscall whitelist)
  5. Linux namespaces (PID, net, mount, IPC isolation per stage)
  6. cgroups v2 resource limits (CPU, memory, IO, PIDs per stage)
  7. Supervisor privilege separation (root for setup, drops to unprivileged)
  8. FIFO integrity (optional HMAC signing between stages)
  9. Stderr rate limiting and per-stage isolation
  10. FD isolation (FIFOs opened by child post-privilege-drop via runcon)
  11. systemd hardening (PrivateNetwork, PrivateIPC, ProtectProc, etc.)
  12. Required files isolation (POSIX ACLs + per-stage SELinux data types)
"""

import argparse
import grp
import hashlib
import json
import logging
import os
import pwd
import atexit
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)

LOG = logging.getLogger("composer")

SELINUX_DIR = Path(__file__).resolve().parent.parent / "selinux"
COMPOSER_BASE_UID = 60000
SUPERVISOR_USER = "composer_sup"
CGROUP_ROOT = "/sys/fs/cgroup"
HMAC_KEY_LEN = 32
STDERR_RATE_LIMIT_BYTES = 1048576  # 1MB per interval
STDERR_RATE_INTERVAL = 60


# ──────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────

@dataclass
class ResourceLimits:
    cpu_quota_percent: int = 50
    memory_max_mb: int = 256
    memory_high_mb: int = 200
    io_max_read_mbps: int = 50
    io_max_write_mbps: int = 50
    pids_max: int = 16
    nofile_soft: int = 64
    nofile_hard: int = 128


@dataclass
class SeccompProfile:
    allowed_syscalls: List[str] = field(default_factory=lambda: [
        "read", "write", "close", "fstat", "stat", "lseek", "mmap", "mprotect",
        "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "ioctl", "access", "pipe", "dup", "dup2", "nanosleep", "clock_nanosleep",
        "getpid", "getppid", "getpgrp", "getuid", "getgid", "geteuid", "getegid",
        "arch_prctl", "exit", "exit_group", "futex", "set_tid_address",
        "set_robust_list", "rseq", "getrandom", "openat", "newfstatat",
        "pread64", "pwrite64", "sched_yield", "mremap", "prlimit64",
        "fcntl", "uname", "sysinfo",
    ])
    extra_syscalls: List[str] = field(default_factory=list)
    allow_network: bool = False
    allow_fork: bool = False


@dataclass
class Composable:
    name: str
    binary: str
    sha256: str
    args: List[str] = field(default_factory=list)
    description: str = ""
    stdin_source: Optional[str] = None
    stdout_sink: Optional[str] = None
    resources: ResourceLimits = field(default_factory=ResourceLimits)
    seccomp: SeccompProfile = field(default_factory=SeccompProfile)
    env_whitelist: List[str] = field(default_factory=lambda: ["PATH", "LANG", "LC_ALL"])
    namespaces: Dict[str, bool] = field(default_factory=lambda: {
        "pid": True, "net": True, "mount": True, "ipc": True, "uts": True,
    })
    required_files: List[str] = field(default_factory=list)


@dataclass
class Settings:
    fifo_dir: str = "/var/run/composer/fifos"
    log_dir: str = "/var/log/composer"
    run_dir: str = "/var/run/composer"
    selinux_enforce: bool = True
    fifo_mode: int = 0o640
    umask: int = 0o077
    hmac_signing: bool = True
    continuous: bool = False
    ingress_writers: List[str] = field(default_factory=list)
    egress_readers: List[str] = field(default_factory=list)


@dataclass
class Reporting:
    method: str = "file"
    path: str = "/var/log/composer/pipeline-stderr.log"
    per_stage: bool = True
    rate_limit_bytes: int = STDERR_RATE_LIMIT_BYTES
    rate_interval_sec: int = STDERR_RATE_INTERVAL


@dataclass
class Pipeline:
    name: str
    composables: List[Composable]
    settings: Settings
    reporting: Reporting
    description: str = ""


# ──────────────────────────────────────────────────────
# Config parsing
# ──────────────────────────────────────────────────────

def _parse_resource_limits(raw: dict) -> ResourceLimits:
    if not raw:
        return ResourceLimits()
    return ResourceLimits(
        cpu_quota_percent=raw.get("cpu_quota_percent", 50),
        memory_max_mb=raw.get("memory_max_mb", 256),
        memory_high_mb=raw.get("memory_high_mb", 200),
        io_max_read_mbps=raw.get("io_max_read_mbps", 50),
        io_max_write_mbps=raw.get("io_max_write_mbps", 50),
        pids_max=raw.get("pids_max", 16),
        nofile_soft=raw.get("nofile_soft", 64),
        nofile_hard=raw.get("nofile_hard", 128),
    )


def _parse_seccomp(raw: dict) -> SeccompProfile:
    if not raw:
        return SeccompProfile()
    default = SeccompProfile()
    extra = raw.get("extra_syscalls", [])
    base = raw.get("allowed_syscalls", default.allowed_syscalls)
    return SeccompProfile(
        allowed_syscalls=list(set(base + extra)),
        extra_syscalls=extra,
        allow_network=raw.get("allow_network", False),
        allow_fork=raw.get("allow_fork", False),
    )


def parse_config(path: str) -> Pipeline:
    cfg_path = Path(path).resolve()

    # Reject world-writable config files
    try:
        st = cfg_path.stat()
        if st.st_mode & stat.S_IWOTH:
            LOG.error(f"Config file {cfg_path} is world-writable. Refusing to load.")
            sys.exit(1)
    except OSError as e:
        LOG.error(f"Cannot stat config file {cfg_path}: {e}")
        sys.exit(1)

    with open(cfg_path, "r") as f:
        raw = yaml.safe_load(f)

    p = raw["pipeline"]
    s = p.get("settings", {})
    r = p.get("reporting", {})

    settings = Settings(
        fifo_dir=s.get("fifo_dir", Settings.fifo_dir),
        log_dir=s.get("log_dir", Settings.log_dir),
        run_dir=s.get("run_dir", Settings.run_dir),
        selinux_enforce=s.get("selinux_enforce", True),
        fifo_mode=int(s.get("fifo_mode", "0640"), 8) if isinstance(s.get("fifo_mode"), str) else s.get("fifo_mode", 0o640),
        umask=int(s.get("umask", "0077"), 8) if isinstance(s.get("umask"), str) else s.get("umask", 0o077),
        hmac_signing=s.get("hmac_signing", True),
        continuous=s.get("continuous", False),
        ingress_writers=s.get("ingress_writers", []),
        egress_readers=s.get("egress_readers", []),
    )

    reporting = Reporting(
        method=r.get("method", "file"),
        path=r.get("path", Reporting.path),
        per_stage=r.get("per_stage", True),
        rate_limit_bytes=r.get("rate_limit_bytes", STDERR_RATE_LIMIT_BYTES),
        rate_interval_sec=r.get("rate_interval_sec", STDERR_RATE_INTERVAL),
    )

    composables = []
    for c in p["composables"]:
        composables.append(Composable(
            name=c["name"],
            binary=c["binary"],
            sha256=c.get("sha256", ""),
            args=c.get("args", []),
            description=c.get("description", ""),
            stdin_source=c.get("stdin_source"),
            stdout_sink=c.get("stdout_sink"),
            resources=_parse_resource_limits(c.get("resources")),
            seccomp=_parse_seccomp(c.get("seccomp")),
            env_whitelist=c.get("env_whitelist", ["PATH", "LANG", "LC_ALL"]),
            namespaces=c.get("namespaces", {
                "pid": True, "net": True, "mount": True, "ipc": True, "uts": True,
            }),
            required_files=c.get("required_files", []),
        ))

    return Pipeline(
        name=p["name"],
        composables=composables,
        settings=settings,
        reporting=reporting,
        description=p.get("description", ""),
    )


# ──────────────────────────────────────────────────────
# Integrity
# ──────────────────────────────────────────────────────

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ──────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────

def validate_pipeline(pipeline: Pipeline, check_binaries: bool = True) -> List[str]:
    errors = []

    if len(pipeline.composables) < 2:
        errors.append("Pipeline must have at least 2 composables.")

    names = [c.name for c in pipeline.composables]
    if len(names) != len(set(names)):
        errors.append("Composable names must be unique.")

    for c in pipeline.composables:
        if not Path(c.binary).is_absolute():
            errors.append(f"[{c.name}] Binary path must be absolute: {c.binary}")

        # SELinux type name safety
        if not c.name.replace("_", "").isalnum():
            errors.append(f"[{c.name}] Name must be alphanumeric with underscores only.")
        if "-" in c.name:
            errors.append(f"[{c.name}] Hyphens not allowed (invalid in SELinux type names).")

        if not c.sha256 or len(c.sha256) != 64:
            errors.append(f"[{c.name}] sha256 must be a 64-char hex digest. "
                          f"Generate with: pipeline-composer hash {c.binary}")

        if check_binaries:
            bp = Path(c.binary)
            if not bp.exists():
                errors.append(f"[{c.name}] Binary not found: {c.binary}")
            elif not os.access(c.binary, os.X_OK):
                errors.append(f"[{c.name}] Binary not executable: {c.binary}")
            else:
                actual = _sha256_file(c.binary)
                if actual != c.sha256:
                    errors.append(
                        f"[{c.name}] INTEGRITY FAILED: "
                        f"expected {c.sha256}, got {actual}"
                    )

        if c.resources.memory_high_mb >= c.resources.memory_max_mb:
            errors.append(
                f"[{c.name}] memory_high_mb ({c.resources.memory_high_mb}) "
                f"must be < memory_max_mb ({c.resources.memory_max_mb})"
            )

        for rf in c.required_files:
            if not Path(rf).is_absolute():
                errors.append(f"[{c.name}] required_file must be absolute: {rf}")
            elif check_binaries and not Path(rf).exists():
                errors.append(f"[{c.name}] required_file not found: {rf}")

    # ingress_writers validation
    for writer in pipeline.settings.ingress_writers:
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$', writer):
            errors.append(f"ingress_writers: invalid username '{writer}'")
        if check_binaries:
            try:
                pwd.getpwnam(writer)
            except KeyError:
                errors.append(f"ingress_writers: user '{writer}' does not exist")

    # egress_readers validation
    for reader in pipeline.settings.egress_readers:
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$', reader):
            errors.append(f"egress_readers: invalid username '{reader}'")
        if check_binaries:
            try:
                pwd.getpwnam(reader)
            except KeyError:
                errors.append(f"egress_readers: user '{reader}' does not exist")

    # stdin_source / stdout_sink position validation
    first = pipeline.composables[0]
    last = pipeline.composables[-1]
    for c in pipeline.composables:
        if c.stdin_source and c is not first:
            errors.append(f"[{c.name}] stdin_source is only valid on the first composable")
        if c.stdout_sink and c is not last:
            errors.append(f"[{c.name}] stdout_sink is only valid on the last composable")

    return errors


# ──────────────────────────────────────────────────────
# User management: per-composable UIDs
# ──────────────────────────────────────────────────────

def _composable_username(pipeline_name: str, composable_name: str) -> str:
    # Include a hash suffix to avoid collision when pipeline names share a prefix
    h = hashlib.sha256(f"{pipeline_name}:{composable_name}".encode()).hexdigest()[:6]
    return f"c_{pipeline_name[:8]}_{composable_name[:8]}_{h}"


def _ensure_system_user(username: str, comment: str):
    try:
        pwd.getpwnam(username)
    except KeyError:
        subprocess.run([
            "useradd", "-r", "-s", "/sbin/nologin",
            "-d", "/nonexistent", "-M",
            "-c", comment, username
        ], check=True)


def setup_users(pipeline: Pipeline, dry_run: bool = False) -> Dict[str, Tuple[int, int]]:
    user_map = {}

    sup_user = SUPERVISOR_USER
    if dry_run:
        LOG.info(f"[DRY-RUN] Create supervisor user: {sup_user}")
    else:
        _ensure_system_user(sup_user, "Composer supervisor")

    for i, comp in enumerate(pipeline.composables):
        username = _composable_username(pipeline.name, comp.name)
        if dry_run:
            LOG.info(f"[DRY-RUN] Create user: {username} for [{comp.name}]")
            user_map[comp.name] = (COMPOSER_BASE_UID + i, COMPOSER_BASE_UID + i)
        else:
            _ensure_system_user(username, f"Composer composable {comp.name}")
            # Add composable user to composer_sup group so setpriv --init-groups
            # includes it, allowing HMAC scripts to read the key file (mode 0640)
            subprocess.run(
                ["usermod", "-aG", sup_user, username],
                check=False, capture_output=True,
            )
            pw = pwd.getpwnam(username)
            user_map[comp.name] = (pw.pw_uid, pw.pw_gid)
            LOG.info(f"User {username} (uid={pw.pw_uid}) for [{comp.name}]")

    return user_map


# ──────────────────────────────────────────────────────
# DAC enforcement
# ──────────────────────────────────────────────────────

def _ingress_fifo_path(pipeline: Pipeline) -> Path:
    """Return the path for the pipeline's ingress FIFO."""
    return Path(pipeline.settings.fifo_dir) / f"{pipeline.name}_ingress"


def _egress_fifo_path(pipeline: Pipeline) -> Path:
    """Return the path for the pipeline's egress FIFO."""
    return Path(pipeline.settings.fifo_dir) / f"{pipeline.name}_egress"


def setup_dac(pipeline: Pipeline, user_map: Dict[str, Tuple[int, int]],
              dry_run: bool = False) -> List[Path]:
    """Create FIFOs with per-stage ownership.
    Each FIFO: owner=writer UID, group=reader GID, mode=0640.
    DAC independently enforces unidirectionality.
    """
    s = pipeline.settings
    fifo_dir = Path(s.fifo_dir)
    log_dir = Path(s.log_dir)
    run_dir = Path(s.run_dir)

    if not dry_run:
        sup_pw = pwd.getpwnam(SUPERVISOR_USER)
        sup_uid, sup_gid = sup_pw.pw_uid, sup_pw.pw_gid
    else:
        sup_uid, sup_gid = 0, 0

    old_umask = os.umask(s.umask)

    try:
        for d in [run_dir, fifo_dir, log_dir]:
            if dry_run:
                LOG.info(f"[DRY-RUN] mkdir {d} mode=0750 owner=root:{SUPERVISOR_USER}")
            else:
                d.mkdir(parents=True, exist_ok=True)
                os.chown(str(d), 0, sup_gid)
                os.chmod(str(d), 0o750)

        fifo_paths = []
        composables = pipeline.composables

        # Create ingress FIFO for first stage if no explicit stdin_source
        first = composables[0]
        if not first.stdin_source:
            ingress_path = fifo_dir / f"{pipeline.name}_ingress"
            _, first_gid = user_map[first.name]

            if dry_run:
                f_user = _composable_username(pipeline.name, first.name)
                LOG.info(f"[DRY-RUN] mkfifo {ingress_path} mode=0640 "
                         f"owner={SUPERVISOR_USER}(write) group={f_user}(read)")
            else:
                if ingress_path.exists():
                    if not stat.S_ISFIFO(ingress_path.stat().st_mode):
                        LOG.error(f"{ingress_path} exists but is not a FIFO. Refusing.")
                        sys.exit(1)
                    ingress_path.unlink()
                os.mkfifo(str(ingress_path), 0o640)
                os.chown(str(ingress_path), sup_uid, first_gid)
                os.chmod(str(ingress_path), 0o640)
                LOG.info(f"Ingress FIFO: {ingress_path} [0640 {SUPERVISOR_USER}:{first_gid}]")

            # Grant write access to ingress_writers via POSIX ACLs
            for writer in pipeline.settings.ingress_writers:
                if dry_run:
                    LOG.info(f"[DRY-RUN] setfacl -m u:{writer}:w {ingress_path}")
                else:
                    try:
                        subprocess.run(
                            ["setfacl", "-m", f"u:{writer}:w", str(ingress_path)],
                            check=True,
                        )
                        LOG.info(f"Ingress ACL: {ingress_path} -> write for {writer}")
                    except FileNotFoundError:
                        LOG.warning("setfacl not found. Install acl package.")

        # Create egress FIFO for last stage if no explicit stdout_sink
        last = composables[-1]
        if not last.stdout_sink:
            egress_path = fifo_dir / f"{pipeline.name}_egress"
            last_uid, _ = user_map[last.name]

            if dry_run:
                l_user = _composable_username(pipeline.name, last.name)
                LOG.info(f"[DRY-RUN] mkfifo {egress_path} mode=0640 "
                         f"owner={l_user}(write) group={SUPERVISOR_USER}(read)")
            else:
                if egress_path.exists():
                    if not stat.S_ISFIFO(egress_path.stat().st_mode):
                        LOG.error(f"{egress_path} exists but is not a FIFO. Refusing.")
                        sys.exit(1)
                    egress_path.unlink()
                os.mkfifo(str(egress_path), 0o640)
                os.chown(str(egress_path), last_uid, sup_gid)
                os.chmod(str(egress_path), 0o640)
                LOG.info(f"Egress FIFO: {egress_path} [0640 {last_uid}:{SUPERVISOR_USER}]")

            # Grant read access to egress_readers via POSIX ACLs
            for reader in pipeline.settings.egress_readers:
                if dry_run:
                    LOG.info(f"[DRY-RUN] setfacl -m u:{reader}:r {egress_path}")
                else:
                    try:
                        subprocess.run(
                            ["setfacl", "-m", f"u:{reader}:r", str(egress_path)],
                            check=True,
                        )
                        LOG.info(f"Egress ACL: {egress_path} -> read for {reader}")
                    except FileNotFoundError:
                        LOG.warning("setfacl not found. Install acl package.")
        elif last.stdout_sink == "/dev/null":
            LOG.warning(
                f"Last stage [{last.name}] stdout_sink is /dev/null — "
                f"pipeline output will be discarded. Consider using an egress FIFO "
                f"by removing stdout_sink, or set stdout_sink to a file path."
            )

        for i in range(len(composables) - 1):
            writer = composables[i]
            reader = composables[i + 1]
            fifo_path = fifo_dir / f"{writer.name}_to_{reader.name}"
            fifo_paths.append(fifo_path)

            writer_uid, _ = user_map[writer.name]
            _, reader_gid = user_map[reader.name]

            if dry_run:
                w_user = _composable_username(pipeline.name, writer.name)
                r_user = _composable_username(pipeline.name, reader.name)
                LOG.info(f"[DRY-RUN] mkfifo {fifo_path} mode=0640 "
                         f"owner={w_user}(write) group={r_user}(read)")
            else:
                if fifo_path.exists():
                    if not stat.S_ISFIFO(fifo_path.stat().st_mode):
                        LOG.error(f"{fifo_path} exists but is not a FIFO. Refusing.")
                        sys.exit(1)
                    fifo_path.unlink()
                os.mkfifo(str(fifo_path), 0o640)
                os.chown(str(fifo_path), writer_uid, reader_gid)
                os.chmod(str(fifo_path), 0o640)
                LOG.info(f"FIFO: {fifo_path} [0640 {writer_uid}:{reader_gid}]")

        # Set up required_files: POSIX ACLs for per-stage read access
        for comp in composables:
            comp_uid, comp_gid = user_map[comp.name]
            comp_user = _composable_username(pipeline.name, comp.name)
            for rf in comp.required_files:
                rf_path = Path(rf)
                if dry_run:
                    LOG.info(f"[DRY-RUN] setfacl -m u:{comp_user}:r {rf}")
                else:
                    if not rf_path.exists():
                        LOG.warning(f"[{comp.name}] required_file not found: {rf}")
                        continue
                    try:
                        subprocess.run(
                            ["setfacl", "-m", f"u:{comp_user}:r", str(rf_path)],
                            check=True,
                        )
                        LOG.info(f"ACL: {rf} -> read for {comp_user}")
                    except FileNotFoundError:
                        LOG.warning("setfacl not found. Install acl package.")
                    # Ensure parent directory traversal
                    for parent in rf_path.parents:
                        if str(parent) == "/":
                            break
                        subprocess.run(
                            ["setfacl", "-m", f"u:{comp_user}:x", str(parent)],
                            check=False, capture_output=True,
                        )

        # Create per-stage stderr log files
        if pipeline.reporting.per_stage and pipeline.reporting.method == "file":
            for comp in composables:
                comp_uid, comp_gid = user_map[comp.name]
                stderr_path = Path(log_dir) / f"{comp.name}.stderr.log"
                if dry_run:
                    LOG.info(f"[DRY-RUN] touch {stderr_path} owner={comp_uid} mode=0600")
                else:
                    if not stderr_path.exists():
                        stderr_path.touch()
                    os.chown(str(stderr_path), comp_uid, comp_gid)
                    os.chmod(str(stderr_path), 0o600)

        return fifo_paths

    finally:
        os.umask(old_umask)


# ──────────────────────────────────────────────────────
# SELinux
# ──────────────────────────────────────────────────────

def _selinux_available() -> bool:
    try:
        result = subprocess.run(["getenforce"], capture_output=True, text=True)
        return result.stdout.strip() not in ("Disabled", "")
    except FileNotFoundError:
        return False


def setup_selinux(pipeline: Pipeline, dry_run: bool = False):
    if not pipeline.settings.selinux_enforce:
        LOG.info("SELinux enforcement disabled in config.")
        return

    if not _selinux_available():
        LOG.warning("SELinux not available or disabled. Skipping MAC setup.")
        return

    script = SELINUX_DIR / "generate_policy.sh"
    if not script.exists():
        LOG.error(f"SELinux generator not found: {script}")
        sys.exit(1)

    cmd = ["bash", str(script), pipeline.name,
           pipeline.settings.fifo_dir, pipeline.settings.log_dir]
    for c in pipeline.composables:
        files_str = ",".join(c.required_files) if c.required_files else ""
        cmd.append(f"{c.name}:{c.binary}:{files_str}")

    if dry_run:
        LOG.info(f"[DRY-RUN] {' '.join(cmd)}")
        return

    LOG.info("Generating SELinux policy...")
    subprocess.run(cmd, check=True)

    gen_dir = SELINUX_DIR / "generated"
    te_file = gen_dir / f"{pipeline.name}.te"
    fc_file = gen_dir / f"{pipeline.name}.fc"
    mod_file = gen_dir / f"{pipeline.name}.mod"
    pp_file = gen_dir / f"{pipeline.name}.pp"

    LOG.info("Compiling SELinux module...")
    devel_makefile = Path("/usr/share/selinux/devel/Makefile")
    if devel_makefile.exists():
        # Use the devel Makefile for m4 macro preprocessing (policy_module, domain_type, etc.)
        subprocess.run(
            ["make", "-f", str(devel_makefile), "-C", str(gen_dir),
             f"{pipeline.name}.pp"],
            check=True,
        )
    else:
        # Fallback: raw checkmodule (only works if TE has no m4 macros)
        subprocess.run(
            ["checkmodule", "-M", "-m", "-o", str(mod_file), str(te_file)],
            check=True,
        )
        subprocess.run(
            ["semodule_package", "-o", str(pp_file), "-m", str(mod_file), "-f", str(fc_file)],
            check=True,
        )

    LOG.info("Loading SELinux module...")
    subprocess.run(["semodule", "-i", str(pp_file)], check=True)

    LOG.info("Restoring file contexts...")
    subprocess.run(["restorecon", "-Rv", pipeline.settings.fifo_dir], check=True)
    subprocess.run(["restorecon", "-Rv", pipeline.settings.log_dir], check=True)

    # Persistent labeling via semanage fcontext + restorecon
    for c in pipeline.composables:
        # Label binary
        ctx_type = f"composer_{c.name}_exec_t"
        _semanage_label(c.binary, ctx_type)

        # Label required_files with per-stage data type
        if c.required_files:
            data_type = f"composer_{c.name}_data_t"
            for rf in c.required_files:
                _semanage_label(rf, data_type)

    # Label per-stage stderr logs
    if pipeline.reporting.per_stage:
        for c in pipeline.composables:
            stderr_path = os.path.join(pipeline.settings.log_dir, f"{c.name}.stderr.log")
            _semanage_label(stderr_path, f"composer_stderr_{c.name}_t")

    # Label ingress FIFO if no explicit stdin_source on first stage
    first = pipeline.composables[0]
    if not first.stdin_source:
        ingress_path = str(_ingress_fifo_path(pipeline))
        _semanage_label(ingress_path, f"composer_fifo_{pipeline.name}_ingress_t")

    # Label egress FIFO if no explicit stdout_sink on last stage
    last = pipeline.composables[-1]
    if not last.stdout_sink:
        egress_path = str(_egress_fifo_path(pipeline))
        _semanage_label(egress_path, f"composer_fifo_{pipeline.name}_egress_t")

    LOG.info("SELinux policy loaded and contexts applied.")


def _semanage_label(path: str, setype: str):
    """Persistently label a file with semanage fcontext + restorecon.
    Paths are regex-escaped for semanage fcontext (which expects regex patterns).
    """
    # semanage fcontext treats paths as regex — escape special chars
    escaped = re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', path)
    LOG.info(f"Labeling {path} -> {setype}")
    subprocess.run(
        ["semanage", "fcontext", "-a", "-t", setype, escaped],
        check=False, capture_output=True,
    )
    subprocess.run(
        ["semanage", "fcontext", "-m", "-t", setype, escaped],
        check=False, capture_output=True,
    )
    if Path(path).exists():
        subprocess.run(["restorecon", "-v", path], check=True)


# ──────────────────────────────────────────────────────
# cgroups v2
# ──────────────────────────────────────────────────────

def setup_cgroup(pipeline_name: str, comp: Composable, dry_run: bool = False) -> str:
    cg_name = f"composer.{pipeline_name}.{comp.name}"
    cg_path = Path(CGROUP_ROOT) / cg_name
    r = comp.resources

    if dry_run:
        LOG.info(f"[DRY-RUN] cgroup {cg_path}: cpu={r.cpu_quota_percent}% "
                 f"mem={r.memory_max_mb}MB pids={r.pids_max}")
        return str(cg_path)

    cg_path.mkdir(parents=True, exist_ok=True)
    (cg_path / "cpu.max").write_text(f"{r.cpu_quota_percent * 1000} 100000\n")
    (cg_path / "memory.max").write_text(f"{r.memory_max_mb * 1024 * 1024}\n")
    (cg_path / "memory.high").write_text(f"{r.memory_high_mb * 1024 * 1024}\n")
    (cg_path / "pids.max").write_text(f"{r.pids_max}\n")

    LOG.info(f"cgroup {cg_path}: cpu={r.cpu_quota_percent}% "
             f"mem={r.memory_max_mb}MB pids={r.pids_max}")
    return str(cg_path)


def _move_to_cgroup(cg_path: str, pid: int):
    (Path(cg_path) / "cgroup.procs").write_text(str(pid) + "\n")


def cleanup_cgroup(pipeline_name: str, comp_name: str):
    cg_path = Path(CGROUP_ROOT) / f"composer.{pipeline_name}.{comp_name}"
    if cg_path.exists():
        try:
            cg_path.rmdir()
        except OSError:
            pass


# ──────────────────────────────────────────────────────
# seccomp-bpf profile generation
# ──────────────────────────────────────────────────────

def generate_seccomp_profile(comp: Composable, output_dir: Path) -> Path:
    syscalls = list(comp.seccomp.allowed_syscalls)

    # Always allow execve/execveat: the seccomp loader needs to exec the target
    # binary after applying the BPF filter. SELinux neverallow rules independently
    # prevent execution of unauthorized binaries (cross-stage exec blocked at MAC).
    syscalls.extend(["execve", "execveat"])

    if comp.seccomp.allow_network:
        syscalls.extend(["socket", "connect", "bind", "listen", "accept",
                         "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg",
                         "getsockopt", "setsockopt", "getpeername", "getsockname",
                         "shutdown", "poll", "ppoll", "epoll_create1", "epoll_ctl",
                         "epoll_wait", "select", "pselect6"])

    if comp.seccomp.allow_fork:
        syscalls.extend(["clone", "clone3", "fork", "vfork", "wait4", "waitid"])

    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [{
            "names": sorted(set(syscalls)),
            "action": "SCMP_ACT_ALLOW",
        }]
    }

    profile_path = output_dir / f"seccomp_{comp.name}.json"
    with open(profile_path, "w") as f:
        json.dump(profile, f, indent=2)
    # 0644: composable users need to read their profile via seccomp_loader.
    # Profile contents (syscall whitelist) are not secrets.
    os.chmod(str(profile_path), 0o644)

    LOG.info(f"Seccomp profile: {profile_path} ({len(set(syscalls))} syscalls)")
    return profile_path


def generate_seccomp_loader(output_dir: Path) -> Path:
    """Generate a Python seccomp loader that applies a BPF profile then execs the target.
    Requires python3-libseccomp on the host.
    """
    loader = output_dir / "seccomp_loader.py"
    loader.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        \"\"\"Apply a seccomp-bpf profile (OCI/docker JSON format) then exec the target.\"\"\"
        import json, os, sys
        try:
            import seccomp
        except ImportError:
            sys.stderr.write("WARN: python3-libseccomp not installed, skipping seccomp\\n")
            os.execvp(sys.argv[2], sys.argv[2:])

        # seccomp.ERRNO may be a function (newer bindings) or int (older bindings)
        _errno_val = seccomp.ERRNO(1) if callable(seccomp.ERRNO) else seccomp.ERRNO
        ACTIONS = {
            "SCMP_ACT_ALLOW": seccomp.ALLOW,
            "SCMP_ACT_ERRNO": _errno_val,
            "SCMP_ACT_KILL": seccomp.KILL,
            "SCMP_ACT_KILL_PROCESS": seccomp.KILL_PROCESS,
            "SCMP_ACT_LOG": seccomp.LOG,
            "SCMP_ACT_TRAP": seccomp.TRAP,
        }

        def main():
            if len(sys.argv) < 3:
                sys.stderr.write(f"Usage: {sys.argv[0]} <profile.json> <command> [args...]\\n")
                sys.exit(1)

            profile_path = sys.argv[1]
            cmd = sys.argv[2:]

            with open(profile_path) as f:
                profile = json.load(f)

            default_action = ACTIONS.get(profile.get("defaultAction", "SCMP_ACT_ERRNO"),
                                         _errno_val)
            filt = seccomp.SyscallFilter(default_action)

            for rule in profile.get("syscalls", []):
                action = ACTIONS.get(rule.get("action", "SCMP_ACT_ALLOW"), seccomp.ALLOW)
                for name in rule.get("names", []):
                    try:
                        filt.add_rule(action, name)
                    except Exception:
                        pass  # skip unknown syscalls on this kernel

            filt.load()
            os.execvp(cmd[0], cmd)

        if __name__ == "__main__":
            main()
    """))
    loader.chmod(0o755)
    return loader


# ──────────────────────────────────────────────────────
# HMAC wrapper generation
# ──────────────────────────────────────────────────────

def generate_hmac_wrappers(work_dir: Path) -> Tuple[Path, Path, Path]:
    """Generate HMAC signer/verifier scripts. Key is stored in a separate
    root-only file, not embedded in the scripts.
    Returns (signer_path, verifier_path, key_file_path).
    """
    key = secrets.token_hex(HMAC_KEY_LEN)
    key_file = work_dir / "hmac.key"
    key_file.write_text(key)
    # Mode 0640: root can read/write, composer_sup group can read.
    # Stage wrappers run under setpriv which preserves group membership,
    # allowing the HMAC scripts to read the key post-privilege-drop.
    os.chmod(str(key_file), 0o640)
    try:
        sup_gid = grp.getgrnam(SUPERVISOR_USER).gr_gid
        os.chown(str(key_file), 0, sup_gid)
    except (KeyError, PermissionError):
        pass  # fall back to current ownership

    signer = work_dir / "hmac_sign.py"
    signer.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import hashlib, hmac, sys
        KEY = open("{key_file}").read().strip()
        KEY = bytes.fromhex(KEY)
        try:
            for line in sys.stdin.buffer:
                mac = hmac.new(KEY, line.rstrip(b"\\n"), hashlib.sha256).hexdigest()
                sys.stdout.buffer.write(mac.encode() + b":" + line)
                sys.stdout.buffer.flush()
        except BrokenPipeError:
            pass
    """))
    signer.chmod(0o755)

    verifier = work_dir / "hmac_verify.py"
    verifier.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import hashlib, hmac, sys
        KEY = open("{key_file}").read().strip()
        KEY = bytes.fromhex(KEY)
        try:
            for line in sys.stdin.buffer:
                line = line.rstrip(b"\\n")
                if b":" not in line:
                    sys.stderr.write("HMAC FAIL: no signature\\n")
                    continue
                sig, _, payload = line.partition(b":")
                expected = hmac.new(KEY, payload, hashlib.sha256).hexdigest().encode()
                if not hmac.compare_digest(sig, expected):
                    sys.stderr.write("HMAC FAIL: signature mismatch\\n")
                    continue
                sys.stdout.buffer.write(payload + b"\\n")
                sys.stdout.buffer.flush()
        except BrokenPipeError:
            pass
    """))
    verifier.chmod(0o755)

    return signer, verifier, key_file


# ──────────────────────────────────────────────────────
# Stderr rate limiter
# ──────────────────────────────────────────────────────

def generate_stderr_limiter(output_dir: Path, rate_limit_bytes: int,
                            interval_sec: int) -> Path:
    limiter = output_dir / "stderr_limiter.py"
    limiter.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import sys, time
        LIMIT = {rate_limit_bytes}
        INTERVAL = {interval_sec}
        window_start = time.monotonic()
        window_bytes = 0
        dropped = 0
        try:
            for line in sys.stdin.buffer:
                now = time.monotonic()
                if now - window_start > INTERVAL:
                    if dropped > 0:
                        msg = f"[stderr-limiter] dropped {{dropped}} bytes in last {{INTERVAL}}s\\n"
                        sys.stdout.buffer.write(msg.encode())
                    window_start = now
                    window_bytes = 0
                    dropped = 0
                if window_bytes + len(line) <= LIMIT:
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                    window_bytes += len(line)
                else:
                    dropped += len(line)
        except BrokenPipeError:
            pass
    """))
    limiter.chmod(0o755)
    return limiter


# ──────────────────────────────────────────────────────
# Shell helpers
# ──────────────────────────────────────────────────────

def _shell_quote(s: str) -> str:
    if not s:
        return "''"
    return "'" + s.replace("'", "'\\''") + "'"


# ──────────────────────────────────────────────────────
# Wrapper script builder (FD isolation + runcon + namespaces)
# ──────────────────────────────────────────────────────

def _build_wrapper_script(comp: Composable, uid: int, gid: int,
                          fifo_in: Optional[str], fifo_out: Optional[str],
                          stderr_path: str, selinux_enforce: bool,
                          seccomp_profile: Optional[Path] = None,
                          seccomp_loader: Optional[Path] = None,
                          hmac_signer: Optional[Path] = None,
                          hmac_verifier: Optional[Path] = None,
                          stderr_limiter: Optional[Path] = None,
                          cgroup_path: Optional[str] = None,
                          stdin_source: Optional[str] = None,
                          stdout_sink: Optional[str] = None) -> str:
    """Build a shell wrapper that:
    1. Self-assigns to cgroup (eliminates race between fork and cgroup move)
    2. Enters Linux namespaces via unshare
    3. Drops privileges via setpriv (UID/GID + clear caps)
    4. Enters SELinux domain via runcon
    5. Opens FIFOs/files in an INNER shell running as the composable user/domain
       (so DAC and SELinux MAC checks are enforced on open())
    6. Applies seccomp-bpf via loader, sets nofile ulimit
    7. Optionally splices HMAC sign/verify as pipe chain stages
    8. Rate-limits stderr via process substitution
    """
    # Always use bash — needed for process substitution and pipefail
    # cd /tmp early so the CWD is accessible after privilege drop
    parts = ["#!/bin/bash", "set -e", "cd /tmp"]

    # Re-verify binary integrity at launch time (mitigates TOCTOU between validate and exec)
    parts.append(f'ACTUAL=$(sha256sum {_shell_quote(comp.binary)} | cut -d" " -f1)')
    parts.append(f'if [ "$ACTUAL" != {_shell_quote(comp.sha256)} ]; then')
    parts.append(f'  echo "INTEGRITY FAILURE: {comp.name} binary changed after validation" >&2')
    parts.append(f'  exit 99')
    parts.append(f'fi')

    # Self-assign to cgroup immediately (before any other work)
    if cgroup_path:
        parts.append(f"echo $$ > {_shell_quote(cgroup_path + '/cgroup.procs')} 2>/dev/null || true")

    # Build unshare flags from namespace config
    ns_flags = []
    for ns, enabled in comp.namespaces.items():
        if enabled:
            if ns == "pid":
                ns_flags.extend(["--pid", "--fork"])
            elif ns == "net":
                ns_flags.append("--net")
            elif ns == "mount":
                ns_flags.append("--mount")
            elif ns == "ipc":
                ns_flags.append("--ipc")
            elif ns == "uts":
                ns_flags.append("--uts")

    unshare_str = " ".join(ns_flags)

    # Build the core binary command (with seccomp loader prefix)
    binary_parts = [comp.binary] + [str(a) for a in comp.args]
    binary_str = " ".join(_shell_quote(p) for p in binary_parts)

    if seccomp_profile and seccomp_loader:
        binary_str = (f"python3 {_shell_quote(str(seccomp_loader))} "
                      f"{_shell_quote(str(seccomp_profile))} {binary_str}")

    # setpriv for privilege drop + capability clearing
    setpriv_str = (f"setpriv --reuid={uid} --regid={gid} "
                   f"--init-groups --inh-caps=-all")

    # SELinux domain entry via runcon
    if selinux_enforce and _selinux_available():
        domain = f"system_u:system_r:composer_{comp.name}_t:s0"
        runcon_str = f"runcon {_shell_quote(domain)} "
    else:
        runcon_str = ""

    # Build the privilege-dropping prefix (outer commands, run as root)
    if unshare_str:
        priv_prefix = f"unshare {unshare_str} -- {setpriv_str} {runcon_str}"
    else:
        priv_prefix = f"{setpriv_str} {runcon_str}"

    # stdin redirection (opened by INNER shell as composable user)
    if fifo_in:
        stdin_redir = f"< {_shell_quote(fifo_in)}"
    elif stdin_source and stdin_source != "/dev/null":
        stdin_redir = f"< {_shell_quote(stdin_source)}"
    else:
        stdin_redir = "< /dev/null"

    # stdout redirection (opened by INNER shell as composable user)
    if fifo_out:
        stdout_redir = f"> {_shell_quote(fifo_out)}"
    elif stdout_sink and stdout_sink != "/dev/null":
        stdout_redir = f"> {_shell_quote(stdout_sink)}"
    else:
        stdout_redir = "> /dev/null"

    # stderr redirection — use rate limiter via process substitution if available
    if stderr_limiter:
        stderr_redir = f"2> >(python3 {_shell_quote(str(stderr_limiter))} >> {_shell_quote(stderr_path)})"
    else:
        stderr_redir = f"2>> {_shell_quote(stderr_path)}"

    # nofile ulimit prefix for the inner shell
    r = comp.resources
    ulimit_str = f"ulimit -n {r.nofile_soft} 2>/dev/null; "

    # Determine if we need HMAC pipe chain
    use_hmac_in = hmac_verifier and fifo_in
    use_hmac_out = hmac_signer and fifo_out

    # Inner shell command builder: runs as composable user/domain, opens FDs
    def _inner_cmd(cmd: str, in_redir: str, out_redir: str, with_ulimit: bool = False) -> str:
        """Wrap a command in an inner bash -c so FDs are opened post-privilege-drop."""
        ul = ulimit_str if with_ulimit else ""
        # cd /tmp first — after setpriv drops privileges, the inherited CWD
        # (e.g. /root) may be inaccessible to the composable user.
        return (f"{priv_prefix}/bin/bash -c "
                f"{_shell_quote(f'cd /tmp; {ul}exec {cmd} {in_redir} {out_redir} {stderr_redir}')}")

    if use_hmac_in or use_hmac_out:
        parts[1] = "set -eo pipefail"

        pipe_parts = []

        if use_hmac_in:
            pipe_parts.append(_inner_cmd(
                f"python3 {_shell_quote(str(hmac_verifier))}",
                stdin_redir, "", with_ulimit=False,
            ))

        # The core binary
        if use_hmac_in and use_hmac_out:
            pipe_parts.append(_inner_cmd(binary_str, "", "", with_ulimit=True))
        elif use_hmac_in:
            pipe_parts.append(_inner_cmd(binary_str, "", stdout_redir, with_ulimit=True))
        elif use_hmac_out:
            pipe_parts.append(_inner_cmd(binary_str, stdin_redir, "", with_ulimit=True))

        if use_hmac_out:
            pipe_parts.append(_inner_cmd(
                f"python3 {_shell_quote(str(hmac_signer))}",
                "", stdout_redir, with_ulimit=False,
            ))

        parts.append(" | \\\n  ".join(pipe_parts))
    else:
        # Simple case — single exec via inner shell
        parts.append(
            f"exec {priv_prefix}/bin/bash -c "
            f"{_shell_quote(f'cd /tmp; {ulimit_str}exec {binary_str} {stdin_redir} {stdout_redir} {stderr_redir}')}"
        )

    return "\n".join(parts) + "\n"


# ──────────────────────────────────────────────────────
# Pipeline runner
# ──────────────────────────────────────────────────────

class PipelineRunner:
    def __init__(self, pipeline: Pipeline, fifo_paths: List[Path],
                 user_map: Dict[str, Tuple[int, int]], work_dir: Path):
        self.pipeline = pipeline
        self.fifo_paths = fifo_paths
        self.user_map = user_map
        self.work_dir = work_dir
        self.processes: List[subprocess.Popen] = []
        self.aux_processes: List[subprocess.Popen] = []
        self._shutdown = False

    def _verify_integrity(self):
        for comp in self.pipeline.composables:
            actual = _sha256_file(comp.binary)
            if actual != comp.sha256:
                raise RuntimeError(
                    f"INTEGRITY FAILURE [{comp.name}]: {comp.binary} "
                    f"expected={comp.sha256} actual={actual}"
                )
            LOG.info(f"Integrity OK [{comp.name}]: {comp.sha256[:16]}...")

    def _resolve_stderr_path(self, comp_name: str) -> str:
        r = self.pipeline.reporting
        if r.method == "journald":
            return "/dev/stderr"
        if r.per_stage:
            return os.path.join(str(Path(r.path).parent), f"{comp_name}.stderr.log")
        return r.path

    def start(self):
        self._verify_integrity()

        composables = self.pipeline.composables
        n = len(composables)
        s = self.pipeline.settings

        # Generate seccomp profiles and loader
        seccomp_dir = self.work_dir / "seccomp"
        seccomp_dir.mkdir(exist_ok=True)
        # Work dir and seccomp dir need to be traversable by composable users
        # (they read seccomp profiles and execute loader scripts post-privilege-drop).
        # Files inside are individually permission-restricted.
        os.chmod(str(self.work_dir), 0o755)
        os.chmod(str(seccomp_dir), 0o755)
        seccomp_loader = generate_seccomp_loader(seccomp_dir)

        # Generate HMAC wrappers if enabled
        hmac_signer = None
        hmac_verifier = None
        if s.hmac_signing:
            hmac_signer, hmac_verifier, _ = generate_hmac_wrappers(self.work_dir)
            LOG.info("HMAC inter-stage signing enabled.")

        # Generate stderr rate limiter
        stderr_limiter = generate_stderr_limiter(
            self.work_dir,
            self.pipeline.reporting.rate_limit_bytes,
            self.pipeline.reporting.rate_interval_sec,
        )

        # Create wrapper directory
        wrapper_dir = self.work_dir / "wrappers"
        wrapper_dir.mkdir(exist_ok=True)

        for i, comp in enumerate(composables):
            uid, gid = self.user_map[comp.name]

            # Determine FIFO paths
            fifo_in = str(self.fifo_paths[i - 1]) if i > 0 else None
            fifo_out = str(self.fifo_paths[i]) if i < n - 1 else None

            # Per-stage stderr
            stderr_path = self._resolve_stderr_path(comp.name)

            # Generate seccomp profile
            seccomp_profile = generate_seccomp_profile(comp, seccomp_dir)

            # Setup cgroup BEFORE starting process (wrapper self-assigns)
            cg_path_str = None
            try:
                cg_path_str = setup_cgroup(self.pipeline.name, comp)
            except (PermissionError, OSError) as e:
                LOG.warning(f"[{comp.name}] cgroup setup failed (non-fatal): {e}")

            # Build wrapper script
            wrapper_content = _build_wrapper_script(
                comp, uid, gid,
                fifo_in=fifo_in,
                fifo_out=fifo_out,
                stderr_path=stderr_path,
                selinux_enforce=s.selinux_enforce,
                seccomp_profile=seccomp_profile,
                seccomp_loader=seccomp_loader,
                hmac_signer=hmac_signer if i < n - 1 else None,
                hmac_verifier=hmac_verifier if i > 0 else None,
                stderr_limiter=stderr_limiter,
                cgroup_path=cg_path_str,
                stdin_source=(comp.stdin_source or str(_ingress_fifo_path(self.pipeline))) if i == 0 else None,
                stdout_sink=(comp.stdout_sink or str(_egress_fifo_path(self.pipeline))) if i == n - 1 else None,
            )

            wrapper_path = wrapper_dir / f"stage_{comp.name}.sh"
            wrapper_path.write_text(wrapper_content)
            wrapper_path.chmod(0o700)

            LOG.info(f"Starting [{comp.name}]: {comp.binary} "
                     f"(uid={uid} ns={','.join(k for k, v in comp.namespaces.items() if v)})")

            proc = subprocess.Popen(
                ["/bin/bash", str(wrapper_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                close_fds=True,
                env={k: os.environ.get(k, "") for k in comp.env_whitelist
                     if k in os.environ},
            )
            self.processes.append(proc)
            LOG.info(f"[{comp.name}] pid={proc.pid}"
                     f"{' -> cgroup ' + cg_path_str if cg_path_str else ''}")

        LOG.info(f"Pipeline '{self.pipeline.name}' running ({n} stages).")

    def wait(self) -> Dict[str, int]:
        results = {}
        for proc, comp in zip(self.processes, self.pipeline.composables):
            rc = proc.wait()
            results[comp.name] = rc
            if rc != 0:
                stderr_out = ""
                if proc.stderr:
                    stderr_out = proc.stderr.read().decode("utf-8", errors="replace").strip()
                if stderr_out:
                    LOG.error(f"[{comp.name}] exited rc={rc}: {stderr_out}")
                else:
                    LOG.error(f"[{comp.name}] exited rc={rc}")
            else:
                LOG.info(f"[{comp.name}] exited cleanly")
        return results

    def shutdown(self, signum=None, frame=None):
        if self._shutdown:
            return
        self._shutdown = True
        LOG.info("Shutting down pipeline...")

        all_procs = self.processes + self.aux_processes
        for proc in all_procs:
            if proc.poll() is None:
                proc.terminate()

        deadline = time.time() + 5
        for proc in all_procs:
            remaining = max(0.1, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def cleanup(self):
        for p in self.fifo_paths:
            try:
                p.unlink()
            except OSError:
                pass
        # Remove ingress FIFO if it was auto-created
        first = self.pipeline.composables[0]
        if not first.stdin_source:
            try:
                _ingress_fifo_path(self.pipeline).unlink()
            except OSError:
                pass
        # Remove egress FIFO if it was auto-created
        last = self.pipeline.composables[-1]
        if not last.stdout_sink:
            try:
                _egress_fifo_path(self.pipeline).unlink()
            except OSError:
                pass
        for comp in self.pipeline.composables:
            cleanup_cgroup(self.pipeline.name, comp.name)


# ──────────────────────────────────────────────────────
# Supervisor privilege separation
# ──────────────────────────────────────────────────────

def drop_to_supervisor():
    """After privileged setup, drop to the supervisor user.
    Supervisor only needs to: wait on children, handle signals, write logs.
    """
    try:
        pw = pwd.getpwnam(SUPERVISOR_USER)
    except KeyError:
        LOG.warning(f"Supervisor user {SUPERVISOR_USER} not found, continuing as current user.")
        return
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    LOG.info(f"Supervisor dropped to uid={pw.pw_uid} ({SUPERVISOR_USER})")


# ──────────────────────────────────────────────────────
# systemd unit generation
# ──────────────────────────────────────────────────────

def _systemd_version() -> int:
    """Return systemd major version, or 0 if unknown."""
    try:
        result = subprocess.run(["systemctl", "--version"],
                                capture_output=True, text=True, timeout=5)
        m = re.search(r'systemd\s+(\d+)', result.stdout)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


def generate_systemd_unit(pipeline: Pipeline, config_path: str) -> str:
    s = pipeline.settings
    sd_ver = _systemd_version()

    extra_rw = ""
    first = pipeline.composables[0]
    last = pipeline.composables[-1]
    if first.stdin_source:
        extra_rw += f" {first.stdin_source}"
    if last.stdout_sink:
        extra_rw += f" {Path(last.stdout_sink).parent}"

    # Base unit (compatible with systemd 239+ / RHEL 8+)
    unit = f"""[Unit]
Description=Composer Pipeline: {pipeline.name}
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pipeline-composer run {config_path}
ExecStop=/bin/kill -SIGTERM $MAINPID

# Root for setup phase only — supervisor drops to composer_sup after children launch
User=root
Group=root

# Capability bounding — minimum needed for setup + namespace creation
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN CAP_SYS_ADMIN CAP_KILL
AmbientCapabilities=

# ── Filesystem isolation ──
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths={s.fifo_dir} {s.log_dir} {s.run_dir} /sys/fs/cgroup{extra_rw}

# ── Network isolation ──
PrivateNetwork=yes

# ── Kernel hardening ──
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=no
ProtectClock=yes
ProtectHostname=yes

# ── Privilege hardening ──
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes

# ── Namespace: must allow for per-stage isolation ──
RestrictNamespaces=no

# ── Syscall restrictions ──
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service @process @signal @timer
SystemCallFilter=~@mount @swap @reboot @raw-io @module @debug
SystemCallArchitectures=native

# ── Device access ──
PrivateDevices=yes
DevicePolicy=closed

# ── Resource limits for supervisor ──
LimitNOFILE=4096
LimitNPROC=256

# ── Stderr ──
StandardError=journal
SyslogIdentifier=composer-{pipeline.name}

Restart=on-failure
RestartSec=5
"""

    # Directives requiring systemd 245+ (RHEL 9+)
    if sd_ver >= 245:
        unit += """
# ── systemd 245+ hardening ──
RestrictSUIDSGID=yes
"""

    # Directives requiring systemd 247+ (RHEL 9+)
    if sd_ver >= 247:
        unit += """# ── systemd 247+ process isolation ──
ProtectProc=invisible
ProcSubset=pid
"""

    # Directives requiring systemd 248+ (RHEL 9+)
    if sd_ver >= 248:
        unit += """# ── systemd 248+ IPC isolation ──
PrivateIPC=yes
"""

    unit += """
[Install]
WantedBy=multi-user.target
"""
    return unit


# ──────────────────────────────────────────────────────
# CLI commands
# ──────────────────────────────────────────────────────

def cmd_hash(args):
    h = _sha256_file(args.binary)
    print(f"{h}  {args.binary}")


def cmd_validate(args):
    pipeline = parse_config(args.config)
    errors = validate_pipeline(pipeline, check_binaries=not args.skip_integrity)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"Pipeline '{pipeline.name}' is valid "
          f"({len(pipeline.composables)} stages, all checks passed).")


def cmd_plan(args):
    pipeline = parse_config(args.config)
    errors = validate_pipeline(pipeline, check_binaries=False)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    composables = pipeline.composables
    n = len(composables)

    print(f"{'=' * 60}")
    print(f"Pipeline: {pipeline.name}")
    print(f"Stages: {n}")
    print(f"SELinux: {'ENFORCING' if pipeline.settings.selinux_enforce else 'disabled'}")
    print(f"HMAC signing: {'YES' if pipeline.settings.hmac_signing else 'no'}")
    print(f"Per-stage stderr: {'YES' if pipeline.reporting.per_stage else 'no'}")
    print(f"{'=' * 60}")

    print("\nData flow:")
    for i, c in enumerate(composables):
        user = _composable_username(pipeline.name, c.name)
        ns = ",".join(k for k, v in c.namespaces.items() if v)
        if i == 0:
            src = c.stdin_source or str(_ingress_fifo_path(pipeline))
            print(f"  [{src}]")
            if not c.stdin_source and pipeline.settings.ingress_writers:
                print(f"     writers: {', '.join(pipeline.settings.ingress_writers)}")
            print(f"     |")
        print(f"  [{c.name}] {c.binary}")
        print(f"     user={user} ns=[{ns}] "
              f"cpu={c.resources.cpu_quota_percent}% "
              f"mem={c.resources.memory_max_mb}MB "
              f"pids={c.resources.pids_max}")
        print(f"     sha256={c.sha256[:16]}...")
        if c.required_files:
            print(f"     files={c.required_files}")
        if i < n - 1:
            nxt = composables[i + 1].name
            label = f"FIFO: {c.name}_to_{nxt}"
            if pipeline.settings.hmac_signing:
                label += " [HMAC signed]"
            print(f"     | ({label})")
        else:
            sink = c.stdout_sink or str(_egress_fifo_path(pipeline))
            print(f"     |")
            print(f"  [{sink}]")
            if not c.stdout_sink and pipeline.settings.egress_readers:
                print(f"     readers: {', '.join(pipeline.settings.egress_readers)}")

    print(f"\nStderr: {pipeline.reporting.method} -> {pipeline.reporting.path}")
    if pipeline.reporting.per_stage:
        print("  (per-stage isolation enabled)")
    print(f"  Rate limit: {pipeline.reporting.rate_limit_bytes} bytes / "
          f"{pipeline.reporting.rate_interval_sec}s")
    print()

    print("--- Users (dry run) ---")
    setup_users(pipeline, dry_run=True)
    print("\n--- DAC (dry run) ---")
    fake_map = {c.name: (COMPOSER_BASE_UID + i, COMPOSER_BASE_UID + i)
                for i, c in enumerate(composables)}
    setup_dac(pipeline, fake_map, dry_run=True)
    print("\n--- SELinux (dry run) ---")
    setup_selinux(pipeline, dry_run=True)


def cmd_deploy(args):
    pipeline = parse_config(args.config)
    errors = validate_pipeline(pipeline, check_binaries=True)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    LOG.info(f"Deploying: {pipeline.name}")

    user_map = setup_users(pipeline)
    setup_dac(pipeline, user_map)
    setup_selinux(pipeline)

    if args.systemd:
        unit = generate_systemd_unit(pipeline, os.path.abspath(args.config))
        unit_path = f"/etc/systemd/system/composer-{pipeline.name}.service"
        with open(unit_path, "w") as f:
            f.write(unit)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        LOG.info(f"Systemd unit: {unit_path}")
        LOG.info(f"Enable with: systemctl enable --now composer-{pipeline.name}")

    LOG.info("Deployment complete.")


def cmd_run(args):
    pipeline = parse_config(args.config)
    errors = validate_pipeline(pipeline, check_binaries=True)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    LOG.info(f"Starting: {pipeline.name}")

    # Privileged setup phase
    user_map = setup_users(pipeline)
    fifo_paths = setup_dac(pipeline, user_map)
    setup_selinux(pipeline)

    work_dir = Path(pipeline.settings.run_dir) / "work" / pipeline.name
    work_dir.mkdir(parents=True, exist_ok=True)

    def _cleanup_work_dir():
        """Remove work dir (wrappers, seccomp profiles, HMAC keys) on exit."""
        try:
            if work_dir.exists():
                shutil.rmtree(str(work_dir), ignore_errors=True)
        except Exception:
            pass

    atexit.register(_cleanup_work_dir)

    runner = PipelineRunner(pipeline, fifo_paths, user_map, work_dir)
    signal.signal(signal.SIGTERM, runner.shutdown)
    signal.signal(signal.SIGINT, runner.shutdown)

    try:
        runner.start()

        # Drop supervisor privileges after children are launched
        drop_to_supervisor()

        results = runner.wait()
    except Exception as e:
        LOG.error(f"Pipeline error: {e}")
        runner.shutdown()
        sys.exit(1)
    finally:
        runner.cleanup()

    failed = {k: v for k, v in results.items() if v != 0}
    if failed:
        LOG.error(f"Failures: {failed}")
        sys.exit(1)
    LOG.info("Pipeline completed successfully.")


def cmd_teardown(args):
    pipeline = parse_config(args.config)
    LOG.info(f"Tearing down: {pipeline.name}")

    # SELinux: remove persistent fcontext entries before removing module
    for comp in pipeline.composables:
        escaped_bin = re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', comp.binary)
        subprocess.run(["semanage", "fcontext", "-d", escaped_bin],
                       capture_output=True, check=False)
        stderr_path = os.path.join(pipeline.settings.log_dir, f"{comp.name}.stderr.log")
        escaped_stderr = re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', stderr_path)
        subprocess.run(["semanage", "fcontext", "-d", escaped_stderr],
                       capture_output=True, check=False)
        for rf in comp.required_files:
            escaped_rf = re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', rf)
            subprocess.run(["semanage", "fcontext", "-d", escaped_rf],
                           capture_output=True, check=False)
    # Ingress FIFO fcontext
    ingress_path = str(_ingress_fifo_path(pipeline))
    escaped_ingress = re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', ingress_path)
    subprocess.run(["semanage", "fcontext", "-d", escaped_ingress],
                   capture_output=True, check=False)
    # Egress FIFO fcontext
    egress_path = str(_egress_fifo_path(pipeline))
    escaped_egress = re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', egress_path)
    subprocess.run(["semanage", "fcontext", "-d", escaped_egress],
                   capture_output=True, check=False)
    LOG.info("SELinux fcontext entries removed.")

    # SELinux module
    subprocess.run(["semodule", "-r", pipeline.name],
                   capture_output=True, check=False)
    LOG.info("SELinux module removed.")

    # Per-composable users
    for comp in pipeline.composables:
        username = _composable_username(pipeline.name, comp.name)
        subprocess.run(["userdel", "-f", username],
                       capture_output=True, check=False)
        LOG.info(f"Removed user: {username}")

    # FIFOs — only delete this pipeline's FIFOs, not other pipelines'
    fifo_dir = Path(pipeline.settings.fifo_dir)
    pipeline_fifo_names = set()
    pipeline_fifo_names.add(f"{pipeline.name}_ingress")
    pipeline_fifo_names.add(f"{pipeline.name}_egress")
    comps = pipeline.composables
    for i in range(len(comps) - 1):
        pipeline_fifo_names.add(f"{comps[i].name}_to_{comps[i + 1].name}")
    if fifo_dir.exists():
        for f in fifo_dir.iterdir():
            if f.name in pipeline_fifo_names:
                f.unlink()
                LOG.info(f"Removed FIFO: {f}")
        LOG.info("Pipeline FIFOs removed.")

    # cgroups
    for comp in pipeline.composables:
        cleanup_cgroup(pipeline.name, comp.name)

    # systemd unit
    unit_path = Path(f"/etc/systemd/system/composer-{pipeline.name}.service")
    if unit_path.exists():
        unit_path.unlink()
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        LOG.info("Systemd unit removed.")

    # Work dir
    work_dir = Path(pipeline.settings.run_dir) / "work" / pipeline.name
    if work_dir.exists():
        shutil.rmtree(str(work_dir), ignore_errors=True)

    LOG.info("Teardown complete.")


def cmd_generate_unit(args):
    pipeline = parse_config(args.config)
    print(generate_systemd_unit(pipeline, os.path.abspath(args.config)))


def main():
    parser = argparse.ArgumentParser(
        prog="pipeline-composer",
        description="Unidirectional pipeline orchestrator with zero-trust enforcement",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash", help="Compute SHA-256 of a binary")
    p_hash.add_argument("binary")
    p_hash.set_defaults(func=cmd_hash)

    p_val = sub.add_parser("validate", help="Validate config and integrity")
    p_val.add_argument("config")
    p_val.add_argument("--skip-integrity", action="store_true")
    p_val.set_defaults(func=cmd_validate)

    p_plan = sub.add_parser("plan", help="Show execution plan (dry run)")
    p_plan.add_argument("config")
    p_plan.set_defaults(func=cmd_plan)

    p_dep = sub.add_parser("deploy", help="Set up users/DAC/SELinux without running")
    p_dep.add_argument("config")
    p_dep.add_argument("--systemd", action="store_true")
    p_dep.set_defaults(func=cmd_deploy)

    p_run = sub.add_parser("run", help="Deploy and run pipeline")
    p_run.add_argument("config")
    p_run.set_defaults(func=cmd_run)

    p_td = sub.add_parser("teardown", help="Remove all pipeline artifacts")
    p_td.add_argument("config")
    p_td.set_defaults(func=cmd_teardown)

    p_unit = sub.add_parser("generate-unit", help="Print systemd unit to stdout")
    p_unit.add_argument("config")
    p_unit.set_defaults(func=cmd_generate_unit)

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    args.func(args)


if __name__ == "__main__":
    main()
