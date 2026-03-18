#!/usr/bin/env bash
# generate_policy.sh - Generate per-pipeline SELinux policy with full unidirectional enforcement.
#
# Usage: generate_policy.sh <policy_name> <fifo_dir> <log_dir> <name:binary:file1,file2,...>...
#
# Each composable gets:
#   - Its own domain type (composer_<n>_t)
#   - Its own exec type (composer_<n>_exec_t)
#   - Its own data type (composer_<n>_data_t) for required_files (read-only)
#   - Its own stderr type (composer_stderr_<n>_t) (write-only)
#   - Write-only access to its output FIFO type
#   - Read-only access to its input FIFO type
#   - NO access to any other FIFO, binary, data, stderr log, or domain
#
# neverallow rules are compile-time enforced by checkmodule.

set -euo pipefail

POLICY_NAME="${1:?Usage: generate_policy.sh <policy_name> <fifo_dir> <log_dir> <name:binary:files>...}"
FIFO_DIR="${2:?}"
LOG_DIR="${3:?}"
shift 3

# Parse name:binary:files tuples
declare -a NAMES=()
declare -a BINARIES=()
declare -a FILES=()
for tuple in "$@"; do
    name="${tuple%%:*}"
    rest="${tuple#*:}"
    binary="${rest%%:*}"
    files="${rest#*:}"
    if [ "$files" = "$binary" ]; then
        files=""
    fi
    # Validate composable name (alphanumeric + underscore only)
    if ! echo "$name" | grep -qE '^[a-zA-Z_][a-zA-Z0-9_]*$'; then
        echo "ERROR: Invalid composable name '$name'. Must be [a-zA-Z_][a-zA-Z0-9_]*" >&2
        exit 1
    fi
    # Validate binary path (must be absolute, no special chars that could break policy)
    if ! echo "$binary" | grep -qE '^/[a-zA-Z0-9_./-]+$'; then
        echo "ERROR: Invalid binary path '$binary'. Must be absolute with safe characters." >&2
        exit 1
    fi
    NAMES+=("$name")
    BINARIES+=("$binary")
    FILES+=("$files")
done

NUM=${#NAMES[@]}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="${SCRIPT_DIR}/generated"
mkdir -p "$OUTDIR"

TE_FILE="$OUTDIR/${POLICY_NAME}.te"
FC_FILE="$OUTDIR/${POLICY_NAME}.fc"
IF_FILE="$OUTDIR/${POLICY_NAME}.if"

# Path escaping for file_contexts regex
escape_path() {
    echo "$1" | sed 's/\./\\./g'
}

# ──────────────────────────────────────────────────────
# Type Enforcement
# ──────────────────────────────────────────────────────
cat > "$TE_FILE" <<HEADER
policy_module(${POLICY_NAME}, 2.0.0)

require {
    type bin_t;
    type var_run_t;
    type var_log_t;
    type init_t;
    type unconfined_t;
    type shell_exec_t;
    type proc_t;
    type sysfs_t;
    type devpts_t;
    type null_device_t;
    type urandom_device_t;
    type lib_t;
    type ld_so_t;
    type ld_so_cache_t;
    type locale_t;
    type etc_t;
    type usr_t;
    type tmp_t;
    type var_t;
    type cert_t;
    type fonts_t;
    type sssd_var_lib_t;
    type passwd_file_t;
    type sssd_public_t;
    type user_home_dir_t;
    class fifo_file { read write open getattr ioctl };
    class file { read write execute execute_no_trans entrypoint open getattr map create append ioctl lock };
    class dir { search getattr read open add_name remove_name write };
    class process { transition dyntransition sigchld signal sigkill fork setuid setgid setcurrent setrlimit nnp_nosuid_transition };
    class chr_file { read write open getattr };
    class lnk_file { read getattr };
    class fd { use };
    class filesystem { getattr associate };
}

########################################
# Base types
########################################

type composer_supervisor_t;
domain_type(composer_supervisor_t)
role system_r types composer_supervisor_t;

type composer_supervisor_exec_t;
files_type(composer_supervisor_exec_t)

type composer_fifo_dir_t;
files_type(composer_fifo_dir_t)

type composer_log_t;
logging_log_file(composer_log_t)

type composer_wrapper_t;
files_type(composer_wrapper_t)

# Ingress FIFO type (external input to first stage)
type composer_fifo_${POLICY_NAME}_ingress_t;
files_type(composer_fifo_${POLICY_NAME}_ingress_t)

# Egress FIFO type (pipeline output to external readers)
type composer_fifo_${POLICY_NAME}_egress_t;
files_type(composer_fifo_${POLICY_NAME}_egress_t)

HEADER

# Per-composable types
for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    has_files=false
    if [ -n "${FILES[$i]}" ]; then
        has_files=true
    fi

    cat >> "$TE_FILE" <<EOF
# ─── Composable: ${name} ───
type composer_${name}_t;
domain_type(composer_${name}_t)
role system_r types composer_${name}_t;

type composer_${name}_exec_t;
files_type(composer_${name}_exec_t)

# Per-stage stderr log type (write-only, no read)
type composer_stderr_${name}_t;
files_type(composer_stderr_${name}_t)

EOF

    if [ "$has_files" = true ]; then
        cat >> "$TE_FILE" <<EOF
# Data files type for ${name} (schemas, stylesheets, configs, etc.)
type composer_${name}_data_t;
files_type(composer_${name}_data_t)

EOF
    fi

    if [ "$i" -lt "$((NUM - 1))" ]; then
        next="${NAMES[$((i + 1))]}"
        cat >> "$TE_FILE" <<EOF
type composer_fifo_${name}_to_${next}_t;
files_type(composer_fifo_${name}_to_${next}_t)

EOF
    fi
done

# ──────────────────────────────────────────────────────
# Supervisor rules
# ──────────────────────────────────────────────────────
cat >> "$TE_FILE" <<EOF

########################################
# Supervisor entry and permissions
########################################

# Entry from init_t (systemd)
allow init_t composer_supervisor_exec_t:file { read execute open getattr };
type_transition init_t composer_supervisor_exec_t:process composer_supervisor_t;
allow init_t composer_supervisor_t:process { transition };
allow composer_supervisor_t init_t:fd { use };

# Entry from unconfined_t (manual CLI)
allow unconfined_t composer_supervisor_exec_t:file { read execute open getattr };
type_transition unconfined_t composer_supervisor_exec_t:process composer_supervisor_t;
allow unconfined_t composer_supervisor_t:process { transition };
allow composer_supervisor_t unconfined_t:fd { use };

# Supervisor can read/execute its own entry point
allow composer_supervisor_t composer_supervisor_exec_t:file { read execute execute_no_trans open getattr };

# Supervisor manages FIFO directory
allow composer_supervisor_t composer_fifo_dir_t:dir { search getattr read open add_name remove_name write };

# Supervisor can write to ingress FIFO (feed data into pipeline)
allow composer_supervisor_t composer_fifo_${POLICY_NAME}_ingress_t:fifo_file { write open getattr ioctl };

# Unconfined users can write to ingress FIFO (controlled by DAC/ACLs)
allow unconfined_t composer_fifo_${POLICY_NAME}_ingress_t:fifo_file { write open getattr };

# Supervisor can read from egress FIFO (consume pipeline output)
allow composer_supervisor_t composer_fifo_${POLICY_NAME}_egress_t:fifo_file { read open getattr ioctl };

# Unconfined users can read from egress FIFO (controlled by DAC/ACLs)
allow unconfined_t composer_fifo_${POLICY_NAME}_egress_t:fifo_file { read open getattr };

# Supervisor needs shell for wrapper scripts
allow composer_supervisor_t shell_exec_t:file { read execute open getattr };
allow composer_supervisor_t composer_wrapper_t:file { read execute open getattr };

# Supervisor privilege management
allow composer_supervisor_t self:process { fork setuid setgid signal };

# Supervisor log access
allow composer_supervisor_t composer_log_t:file { write open getattr create };
allow composer_supervisor_t composer_log_t:dir { search getattr read open write add_name };
allow composer_supervisor_t var_log_t:dir { search getattr read open };

# Supervisor device access
allow composer_supervisor_t null_device_t:chr_file { read write open };
allow composer_supervisor_t urandom_device_t:chr_file { read open };
allow composer_supervisor_t devpts_t:chr_file { read write open getattr };
allow composer_supervisor_t proc_t:file { read open getattr };

EOF

# Supervisor -> per-composable transition and stderr log management
for name in "${NAMES[@]}"; do
    cat >> "$TE_FILE" <<EOF
# Supervisor -> ${name} transition via runcon
allow composer_supervisor_t composer_${name}_t:process { transition dyntransition sigchld signal sigkill nnp_nosuid_transition };
allow composer_supervisor_t composer_${name}_exec_t:file { read execute open getattr };
allow composer_supervisor_t composer_stderr_${name}_t:file { write open getattr create };
EOF
done

# ──────────────────────────────────────────────────────
# Per-composable rules
# ──────────────────────────────────────────────────────
cat >> "$TE_FILE" <<EOF

########################################
# Per-composable domain rules
########################################

EOF

for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    has_files=false
    if [ -n "${FILES[$i]}" ]; then
        has_files=true
    fi

    cat >> "$TE_FILE" <<EOF
# ${name}: core permissions
allow composer_${name}_t composer_${name}_exec_t:file { read execute execute_no_trans entrypoint open getattr map };
allow composer_${name}_t composer_supervisor_t:fd { use };
allow composer_${name}_t shell_exec_t:file { read execute execute_no_trans entrypoint open getattr map };
allow composer_${name}_t bin_t:file { read execute execute_no_trans open getattr map };
allow composer_${name}_t composer_wrapper_t:file { read execute entrypoint open getattr map };
allow composer_${name}_t self:process { fork signal setcurrent setrlimit };
allow composer_${name}_t self:dir { read write add_name };
allow composer_${name}_t self:file { create read write getattr open ioctl };
allow composer_${name}_t proc_t:filesystem { associate };
allow composer_${name}_t user_home_dir_t:dir { getattr };
allow composer_${name}_t null_device_t:chr_file { read write open };
allow composer_${name}_t urandom_device_t:chr_file { read open };
allow composer_${name}_t devpts_t:chr_file { read write open getattr };
allow composer_${name}_t proc_t:file { read open getattr };
allow composer_${name}_t proc_t:dir { search getattr read open };

# ${name}: shared library, linker, and locale access
allow composer_${name}_t lib_t:file { read open getattr map execute };
allow composer_${name}_t lib_t:dir { search getattr read open };
allow composer_${name}_t lib_t:lnk_file { read getattr };
allow composer_${name}_t ld_so_t:file { read open getattr map execute };
allow composer_${name}_t ld_so_cache_t:file { read open getattr map };
allow composer_${name}_t locale_t:file { read open getattr map };
allow composer_${name}_t locale_t:dir { search getattr read open };
allow composer_${name}_t locale_t:lnk_file { read getattr };
allow composer_${name}_t etc_t:file { read open getattr };
allow composer_${name}_t etc_t:dir { search getattr read open };
allow composer_${name}_t etc_t:lnk_file { read getattr };
allow composer_${name}_t usr_t:file { read open getattr };
allow composer_${name}_t usr_t:dir { search getattr read open };
allow composer_${name}_t usr_t:lnk_file { read getattr };
# tmp_t: search/read + write allowed. In systemd mode, PrivateTmp=yes isolates /tmp.
# For non-systemd mode, use mount namespace (mount: true) to isolate /tmp per composable.
allow composer_${name}_t tmp_t:dir { search getattr read open add_name write };
allow composer_${name}_t tmp_t:file { read write open getattr create map };
allow composer_${name}_t var_t:dir { search getattr };
allow composer_${name}_t var_run_t:dir { search getattr };
allow composer_${name}_t sssd_var_lib_t:dir { search getattr };
allow composer_${name}_t sssd_var_lib_t:file { read open getattr map };
allow composer_${name}_t sssd_public_t:dir { search getattr };
allow composer_${name}_t passwd_file_t:file { read open getattr map };
allow composer_${name}_t var_run_t:file { read open getattr map ioctl };
allow composer_${name}_t bin_t:dir { search getattr read open };
allow composer_${name}_t bin_t:lnk_file { read getattr };
allow composer_${name}_t self:fifo_file { read write getattr ioctl };
allow composer_${name}_t composer_fifo_dir_t:dir { search getattr read open };

# ${name}: WRITE-ONLY to its own stderr log (no read)
allow composer_${name}_t composer_stderr_${name}_t:file { write open getattr append ioctl };
allow composer_${name}_t composer_log_t:dir { search getattr };

EOF

    if [ "$has_files" = true ]; then
        cat >> "$TE_FILE" <<EOF
# ${name}: READ-ONLY access to its required data files
allow composer_${name}_t composer_${name}_data_t:file { read open getattr };
allow composer_${name}_t composer_${name}_data_t:dir { search getattr read open };

EOF
    fi
done

# ──────────────────────────────────────────────────────
# Unidirectional FIFO rules
# ──────────────────────────────────────────────────────
cat >> "$TE_FILE" <<EOF

########################################
# Unidirectional data flow (FIFO rules)
########################################

EOF

first_name="${NAMES[0]}"
last_name="${NAMES[$((NUM - 1))]}"
cat >> "$TE_FILE" <<EOF
# Ingress FIFO: external -> ${first_name} (first stage reads from ingress)
allow composer_${first_name}_t composer_fifo_${POLICY_NAME}_ingress_t:fifo_file { read open getattr ioctl };

# Egress FIFO: ${last_name} -> external (last stage writes to egress)
allow composer_${last_name}_t composer_fifo_${POLICY_NAME}_egress_t:fifo_file { write open getattr ioctl };

EOF

for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"

    if [ "$i" -lt "$((NUM - 1))" ]; then
        next="${NAMES[$((i + 1))]}"
        fifo_type="composer_fifo_${name}_to_${next}_t"
        cat >> "$TE_FILE" <<EOF
# ${name} -> ${next}: forward only
allow composer_${name}_t ${fifo_type}:fifo_file { write open getattr ioctl };
allow composer_${next}_t ${fifo_type}:fifo_file { read open getattr ioctl };

EOF
    fi
done

# ──────────────────────────────────────────────────────
# neverallow rules (compile-time enforced)
# ──────────────────────────────────────────────────────
cat >> "$TE_FILE" <<EOF

########################################
# neverallow (compile-time enforced)
########################################
# These are verified by checkmodule at compile time.
# Adding a conflicting allow rule causes policy compilation to fail.

EOF

# Ingress FIFO neverallow: first stage cannot write (read-only), others have no access
for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    if [ "$i" -eq 0 ]; then
        echo "neverallow composer_${name}_t composer_fifo_${POLICY_NAME}_ingress_t:fifo_file { write };" >> "$TE_FILE"
    else
        echo "neverallow composer_${name}_t composer_fifo_${POLICY_NAME}_ingress_t:fifo_file { read write open };" >> "$TE_FILE"
    fi
done
echo "" >> "$TE_FILE"

# Egress FIFO neverallow: last stage cannot read (write-only), others have no access
for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    if [ "$i" -eq "$((NUM - 1))" ]; then
        echo "neverallow composer_${name}_t composer_fifo_${POLICY_NAME}_egress_t:fifo_file { read };" >> "$TE_FILE"
    else
        echo "neverallow composer_${name}_t composer_fifo_${POLICY_NAME}_egress_t:fifo_file { read write open };" >> "$TE_FILE"
    fi
done
echo "" >> "$TE_FILE"

for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"

    # Cannot read own output FIFO (no loopback)
    if [ "$i" -lt "$((NUM - 1))" ]; then
        next="${NAMES[$((i + 1))]}"
        fifo_type="composer_fifo_${name}_to_${next}_t"
        echo "neverallow composer_${name}_t ${fifo_type}:fifo_file { read };" >> "$TE_FILE"
    fi

    # Cannot write own input FIFO (no reverse flow)
    if [ "$i" -gt 0 ]; then
        prev="${NAMES[$((i - 1))]}"
        fifo_type="composer_fifo_${prev}_to_${name}_t"
        echo "neverallow composer_${name}_t ${fifo_type}:fifo_file { write };" >> "$TE_FILE"
    fi

    # Cannot access non-adjacent FIFOs at all
    for j in "${!NAMES[@]}"; do
        if [ "$j" -lt "$((NUM - 1))" ]; then
            src="${NAMES[$j]}"
            dst="${NAMES[$((j + 1))]}"
            remote_fifo="composer_fifo_${src}_to_${dst}_t"
            if [ "$j" -eq "$i" ] || [ "$((j + 1))" -eq "$i" ]; then
                continue
            fi
            echo "neverallow composer_${name}_t ${remote_fifo}:fifo_file { read write open };" >> "$TE_FILE"
        fi
    done

    # Cannot execute other composables' binaries
    for j in "${!NAMES[@]}"; do
        other="${NAMES[$j]}"
        if [ "$j" -ne "$i" ]; then
            echo "neverallow composer_${name}_t composer_${other}_exec_t:file { execute };" >> "$TE_FILE"
        fi
    done

    # Cannot access other composables' data files
    for j in "${!NAMES[@]}"; do
        other="${NAMES[$j]}"
        if [ "$j" -ne "$i" ] && [ -n "${FILES[$j]}" ]; then
            echo "neverallow composer_${name}_t composer_${other}_data_t:file { read write open };" >> "$TE_FILE"
        fi
    done

    # Cannot WRITE to own data files (read-only)
    if [ -n "${FILES[$i]}" ]; then
        echo "neverallow composer_${name}_t composer_${name}_data_t:file { write };" >> "$TE_FILE"
    fi

    # Cannot READ own stderr log (write-only, no readback)
    echo "neverallow composer_${name}_t composer_stderr_${name}_t:file { read };" >> "$TE_FILE"

    # Cannot access other stages' stderr logs
    for j in "${!NAMES[@]}"; do
        other="${NAMES[$j]}"
        if [ "$j" -ne "$i" ]; then
            echo "neverallow composer_${name}_t composer_stderr_${other}_t:file { read write open };" >> "$TE_FILE"
        fi
    done

    # Cannot signal other composable domains (isolation)
    for j in "${!NAMES[@]}"; do
        other="${NAMES[$j]}"
        if [ "$j" -ne "$i" ]; then
            echo "neverallow composer_${name}_t composer_${other}_t:process { signal sigkill sigchld };" >> "$TE_FILE"
        fi
    done

    # Note: tmp_t covert channel mitigated by PrivateTmp=yes (systemd) or
    # mount namespace isolation (mount: true). Per-composable tmp types would
    # provide MAC-level isolation but require mount namespace to bind-mount.

    # Cannot execute var_run_t files (work dir scripts use composer_wrapper_t)
    echo "neverallow composer_${name}_t var_run_t:file { execute execute_no_trans };" >> "$TE_FILE"
done

# ──────────────────────────────────────────────────────
# File Contexts
# ──────────────────────────────────────────────────────
FIFO_DIR_ESC=$(escape_path "$FIFO_DIR")
LOG_DIR_ESC=$(escape_path "$LOG_DIR")

cat > "$FC_FILE" <<EOF
# File contexts for ${POLICY_NAME}

# Supervisor entry points
/usr/local/bin/pipeline-composer    -- gen_context(system_u:object_r:composer_supervisor_exec_t,s0)
/opt/composer/src/composer\.py    -- gen_context(system_u:object_r:composer_supervisor_exec_t,s0)

# FIFO directory
${FIFO_DIR_ESC}(/.*)?    gen_context(system_u:object_r:composer_fifo_dir_t,s0)

# Ingress FIFO
${FIFO_DIR_ESC}/${POLICY_NAME}_ingress    -p gen_context(system_u:object_r:composer_fifo_${POLICY_NAME}_ingress_t,s0)

# Egress FIFO
${FIFO_DIR_ESC}/${POLICY_NAME}_egress    -p gen_context(system_u:object_r:composer_fifo_${POLICY_NAME}_egress_t,s0)

# Log directory (base type for directory itself)
${LOG_DIR_ESC}    gen_context(system_u:object_r:composer_log_t,s0)

# Wrapper scripts
/tmp/composer_wrappers_[^/]+(/.*)?    gen_context(system_u:object_r:composer_wrapper_t,s0)
/var/run/composer/work(/.*)?    gen_context(system_u:object_r:composer_wrapper_t,s0)

EOF

for i in "${!NAMES[@]}"; do
    name="${NAMES[$i]}"
    binary="${BINARIES[$i]}"
    escaped_binary=$(echo "$binary" | sed 's/[.[\*^$()+?{|]/\\&/g')

    # Binary file context
    echo "${escaped_binary}    -- gen_context(system_u:object_r:composer_${name}_exec_t,s0)" >> "$FC_FILE"

    # Per-stage stderr log
    STDERR_ESC=$(escape_path "${LOG_DIR}/${name}.stderr.log")
    echo "${STDERR_ESC}    -- gen_context(system_u:object_r:composer_stderr_${name}_t,s0)" >> "$FC_FILE"

    # FIFO file context
    if [ "$i" -lt "$((NUM - 1))" ]; then
        next="${NAMES[$((i + 1))]}"
        echo "${FIFO_DIR_ESC}/${name}_to_${next}    -p gen_context(system_u:object_r:composer_fifo_${name}_to_${next}_t,s0)" >> "$FC_FILE"
    fi

    # Required file contexts
    if [ -n "${FILES[$i]}" ]; then
        IFS=',' read -ra file_list <<< "${FILES[$i]}"
        for rf in "${file_list[@]}"; do
            if [ -n "$rf" ]; then
                escaped_rf=$(echo "$rf" | sed 's/[.[\*^$()+?{|]/\\&/g')
                echo "${escaped_rf}    -- gen_context(system_u:object_r:composer_${name}_data_t,s0)" >> "$FC_FILE"
            fi
        done
    fi
done

# Interface file
cat > "$IF_FILE" <<EOF
## <summary>Composer pipeline: ${POLICY_NAME}</summary>
## <desc><p>Unidirectional pipeline with per-stage isolation, neverallow enforcement,
## and per-stage stderr/data type isolation.</p></desc>

interface(\`composer_supervisor_entry',\`
    gen_require(\`
        type composer_supervisor_t;
        type composer_supervisor_exec_t;
    ')
    allow \$1 composer_supervisor_exec_t:file { read execute open getattr };
    type_transition \$1 composer_supervisor_exec_t:process composer_supervisor_t;
    allow \$1 composer_supervisor_t:process { transition };
')
EOF

echo "Generated SELinux policy:"
echo "  TE: $TE_FILE"
echo "  FC: $FC_FILE"
echo "  IF: $IF_FILE"
