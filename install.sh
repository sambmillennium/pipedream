#!/usr/bin/env bash
# install.sh - Install pipeline_composer on a RHEL-based system
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/composer"
BIN_LINK="/usr/local/bin/pipeline-composer"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

echo "============================================"
echo "  Pipeline Composer Installer"
echo "  Unidirectional Pipeline Orchestrator"
echo "============================================"
echo ""

# ── Preflight ──
if [ "$(id -u)" -ne 0 ]; then
    err "Must run as root."
    exit 1
fi

if ! command -v rpm &>/dev/null; then
    err "RHEL-based system required (RHEL, CentOS, Rocky, Alma, Fedora)."
    exit 1
fi

# Detect package manager
if command -v dnf &>/dev/null; then
    PKG="dnf"
elif command -v yum &>/dev/null; then
    PKG="yum"
else
    err "Neither dnf nor yum found."
    exit 1
fi

# ── Dependencies ──
log "Installing system dependencies..."
$PKG install -y \
    python3 \
    python3-pip \
    policycoreutils-python-utils \
    selinux-policy-devel \
    checkpolicy \
    acl \
    util-linux \
    coreutils \
    libseccomp-devel \
    2>&1 | tail -5

# python3-libseccomp may not exist as an RPM on all distros; try pip fallback
if ! python3 -c "import seccomp" 2>/dev/null; then
    log "Installing seccomp Python bindings..."
    $PKG install -y python3-libseccomp 2>/dev/null || \
        pip3 install seccomp 2>/dev/null || \
        warn "seccomp Python bindings not found. seccomp-bpf will log a warning but pipeline will still run."
fi

log "Installing Python dependencies..."
pip3 install pyyaml --break-system-packages 2>/dev/null || pip3 install pyyaml

# ── SELinux check ──
if command -v getenforce &>/dev/null; then
    SELINUX_MODE=$(getenforce)
    if [ "$SELINUX_MODE" = "Disabled" ]; then
        warn "SELinux is DISABLED. MAC enforcement will not function."
        warn "Enable SELinux for full security: edit /etc/selinux/config and reboot."
    elif [ "$SELINUX_MODE" = "Permissive" ]; then
        warn "SELinux is PERMISSIVE. MAC will log but not enforce."
        warn "Set to enforcing: setenforce 1"
    else
        log "SELinux: ${SELINUX_MODE}"
    fi
else
    warn "SELinux tools not found."
fi

# ── cgroups v2 check ──
if mount | grep -q "cgroup2"; then
    log "cgroups v2: available"
else
    warn "cgroups v2 not mounted. Resource limits may not function."
    warn "Ensure 'systemd.unified_cgroup_hierarchy=1' on kernel cmdline."
fi

# ── Supervisor user ──
if ! id -u composer_sup &>/dev/null; then
    log "Creating supervisor user: composer_sup"
    useradd -r -s /sbin/nologin -d /nonexistent -M -c "Composer supervisor" composer_sup
else
    log "Supervisor user composer_sup already exists."
fi

# ── Install files ──
log "Installing to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}/src"
mkdir -p "${INSTALL_DIR}/selinux/generated"
mkdir -p "${INSTALL_DIR}/examples"

cp "${SCRIPT_DIR}/src/composer.py" "${INSTALL_DIR}/src/composer.py"
chmod +x "${INSTALL_DIR}/src/composer.py"

cp "${SCRIPT_DIR}/selinux/generate_policy.sh" "${INSTALL_DIR}/selinux/generate_policy.sh"
chmod +x "${INSTALL_DIR}/selinux/generate_policy.sh"

if [ -d "${SCRIPT_DIR}/examples" ]; then
    cp "${SCRIPT_DIR}/examples/"*.yaml "${INSTALL_DIR}/examples/" 2>/dev/null || true
fi

# ── Symlink ──
ln -sf "${INSTALL_DIR}/src/composer.py" "${BIN_LINK}"
log "Binary: ${BIN_LINK}"

# ── Runtime directories ──
log "Creating runtime directories..."
SUP_GID=$(id -g composer_sup)
mkdir -p /var/run/composer/fifos
mkdir -p /var/run/composer/work
mkdir -p /var/log/composer

chown root:${SUP_GID} /var/run/composer /var/run/composer/fifos /var/run/composer/work
chmod 750 /var/run/composer /var/run/composer/fifos /var/run/composer/work
chown root:${SUP_GID} /var/log/composer
chmod 750 /var/log/composer

# ── tmpfiles.d ──
cat > /etc/tmpfiles.d/composer.conf <<EOF
d /var/run/composer       0750 root $(id -gn composer_sup) -
d /var/run/composer/fifos 0750 root $(id -gn composer_sup) -
d /var/run/composer/work  0750 root $(id -gn composer_sup) -
EOF
log "tmpfiles.d entry written."

# ── SELinux labeling ──
if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
    log "Setting SELinux context for composer binary..."
    semanage fcontext -a -t composer_supervisor_exec_t "${BIN_LINK}" 2>/dev/null || \
        semanage fcontext -m -t composer_supervisor_exec_t "${BIN_LINK}" 2>/dev/null || true
    semanage fcontext -a -t composer_supervisor_exec_t "${INSTALL_DIR}/src/composer.py" 2>/dev/null || \
        semanage fcontext -m -t composer_supervisor_exec_t "${INSTALL_DIR}/src/composer.py" 2>/dev/null || true
    restorecon -v "${BIN_LINK}" 2>/dev/null || true
    restorecon -v "${INSTALL_DIR}/src/composer.py" 2>/dev/null || true
fi

# ── Verify ──
log "Verifying installation..."
${BIN_LINK} --help >/dev/null 2>&1 || {
    err "Installation verification failed. Check Python3 and PyYAML."
    exit 1
}

echo ""
echo "============================================"
log "Installation complete."
echo "============================================"
echo ""
echo "Quick start:"
echo "  1. Hash your binaries:"
echo "     pipeline-composer hash /usr/local/bin/my-binary"
echo ""
echo "  2. Write your pipeline.yaml (see ${INSTALL_DIR}/examples/)"
echo ""
echo "  3. Validate:"
echo "     pipeline-composer validate pipeline.yaml"
echo ""
echo "  4. Deploy:"
echo "     pipeline-composer deploy pipeline.yaml --systemd"
echo ""
echo "  5. Run:"
echo "     pipeline-composer run pipeline.yaml"
echo ""
echo "  6. Teardown:"
echo "     pipeline-composer teardown pipeline.yaml"
