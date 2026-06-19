#!/usr/bin/env bash
# install.sh — PDTMJ-AI tool installer for Kali Linux

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALLED=0
SKIPPED=0
FAILED=0
FAILED_LIST=()

LOGFILE=$(mktemp /tmp/pdtmj-ai-install-XXXXXX.log)
trap 'echo -e "\n  Full log: ${LOGFILE}"' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── sudo ────────────────────────────────────────────────────────────────────
if [[ "$EUID" -eq 0 ]]; then
    SUDO=""
else
    SUDO="sudo"
fi
export SUDO   # subshells inherit it

# ─── pip: prefer venv, fall back to system pip + --break-system-packages ─────
PIP_FLAGS=""
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    PIP="$VIRTUAL_ENV/bin/pip"
else
    for _d in "$SCRIPT_DIR/venv" "$SCRIPT_DIR/.venv"; do
        if [[ -f "$_d/bin/pip" ]]; then
            # shellcheck disable=SC1091
            source "$_d/bin/activate"
            PIP="$_d/bin/pip"
            break
        fi
    done
fi

if [[ -z "${PIP:-}" ]]; then
    PIP="pip3"
    PIP_FLAGS="--break-system-packages"
fi
export PIP PIP_FLAGS

# ─────────────────────────────────────────────────────────────────────────────

section() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}"; }

spin() {
    local label="$1"
    shift
    local tmplog
    tmplog=$(mktemp)

    printf "  ${YELLOW}⋯${NC}  %-44s" "$label"

    "$@" >"$tmplog" 2>&1 &
    local pid=$!
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${YELLOW}%s${NC}  %-44s" "${frames[$i]}" "$label"
        i=$(( (i+1) % 10 ))
        sleep 0.1
    done

    wait "$pid"
    local rc=$?
    cat "$tmplog" >> "$LOGFILE"

    if [[ $rc -eq 0 ]]; then
        printf "\r  ${GREEN}✓${NC}  %-44s\n" "$label"
        ((INSTALLED++)) || true
    else
        printf "\r  ${RED}✗${NC}  %-44s\n" "$label"
        tail -3 "$tmplog" | while IFS= read -r line; do
            echo -e "      ${RED}${line}${NC}"
        done
        ((FAILED++)) || true
        FAILED_LIST+=("$label")
    fi

    rm -f "$tmplog"
    return $rc
}

already() {
    printf "  ${CYAN}=${NC}  %-44s  ${CYAN}already installed${NC}\n" "$1"
    ((SKIPPED++)) || true
}

has()    { command -v "$1" &>/dev/null; }
py_has() { "$PIP" show "$1" &>/dev/null 2>&1; }

apt_pkg() {
    local label="$1" pkg="$2" check="${3:-$2}"
    has "$check" && already "$label" || spin "$label" $SUDO apt-get install -y "$pkg" || true
}

pip_pkg() {
    local label="$1" pkg="$2" check="${3:-}"
    if { [[ -n "$check" ]] && has "$check"; } || py_has "$pkg"; then
        already "$label"
    else
        spin "$label" "$PIP" install --quiet $PIP_FLAGS "$pkg" || true
    fi
}

go_pkg() {
    local label="$1" bin="$2" pkg="$3"
    has "$bin" && already "$label" || spin "$label" go install "$pkg" || true
}

# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${BOLD}PDTMJ-AI${NC} — tool installer"
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    echo -e "  Venv:  ${CYAN}${VIRTUAL_ENV}${NC}"
else
    echo -e "  Pip:   ${YELLOW}system (--break-system-packages)${NC}"
fi
echo -e "  Log:   ${LOGFILE}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
section "System prerequisites"

spin "apt update" $SUDO apt-get update -qq

apt_pkg "golang"        golang      go
apt_pkg "python3-pip"   python3-pip pip3
apt_pkg "pipx"          pipx        pipx
# Clipboard backends so the TUI's copy (row-click, Ctrl+C on a selection, log
# modals) actually reaches the desktop clipboard — OSC 52 alone is unreliable.
apt_pkg "xclip"         xclip       xclip
apt_pkg "wl-clipboard"  wl-clipboard wl-copy

# ─────────────────────────────────────────────────────────────────────────────
section "Network scanning"

apt_pkg "nmap"      nmap    nmap
apt_pkg "masscan"   masscan masscan

# ─────────────────────────────────────────────────────────────────────────────
section "Web scanning"

apt_pkg "sslscan"       sslscan     sslscan
apt_pkg "testssl.sh"    testssl.sh  testssl
apt_pkg "sqlmap"        sqlmap      sqlmap
apt_pkg "tesseract-ocr" tesseract-ocr tesseract   # OCR backend for captcha_solve

go_pkg "nuclei"     nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_pkg "gobuster"   gobuster    "github.com/OJ/gobuster/v3@latest"
go_pkg "ffuf"       ffuf        "github.com/ffuf/ffuf/v2@latest"
go_pkg "dalfox"     dalfox      "github.com/hahwul/dalfox/v2@latest"

# ─────────────────────────────────────────────────────────────────────────────
section "Credential attacks"

apt_pkg "hydra" hydra hydra

# ─────────────────────────────────────────────────────────────────────────────
section "SMB / Windows"

if has nxc || has netexec; then
    already "netexec/nxc"
else
    pip_pkg "netexec" netexec nxc
fi

apt_pkg "smbclient"     smbclient       smbclient
apt_pkg "rpcclient"     samba-common    rpcclient

if has enum4linux-ng; then
    already "enum4linux-ng"
else
    spin "enum4linux-ng" "$PIP" install --quiet $PIP_FLAGS enum4linux-ng || \
    spin "enum4linux-ng (git)" bash -c '
        $SUDO git clone --quiet https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
        "$PIP" install --quiet $PIP_FLAGS -r /opt/enum4linux-ng/requirements.txt
        $SUDO ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng
        $SUDO chmod +x /opt/enum4linux-ng/enum4linux-ng.py
    ' || true
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Active Directory"

apt_pkg "ldap-utils" ldap-utils ldapsearch

py_has impacket && already "impacket" || pip_pkg "impacket" impacket

go_pkg "kerbrute" kerbrute "github.com/ropnop/kerbrute@latest"

pip_pkg "bloodhound-python" bloodhound bloodhound

if has certipy; then
    already "certipy-ad"
else
    spin "certipy-ad" "$PIP" install --quiet $PIP_FLAGS certipy-ad || true
fi

if has coercer; then
    already "coercer"
else
    spin "coercer" "$PIP" install --quiet $PIP_FLAGS coercer || true
fi

if [[ -f /opt/PetitPotam/PetitPotam.py ]] || has PetitPotam; then
    already "PetitPotam"
else
    spin "PetitPotam (git)" bash -c '
        $SUDO git clone --quiet https://github.com/topotam/PetitPotam.git /opt/PetitPotam
        $SUDO ln -sf /opt/PetitPotam/PetitPotam.py /usr/local/bin/PetitPotam
        $SUDO chmod +x /opt/PetitPotam/PetitPotam.py
    ' || true
fi

# ─────────────────────────────────────────────────────────────────────────────
section "SNMP"

apt_pkg "snmp"                  snmp                    snmpwalk
apt_pkg "snmp-mibs-downloader"  snmp-mibs-downloader    snmp-mibs-downloader
apt_pkg "onesixtyone"           onesixtyone             onesixtyone

# ─────────────────────────────────────────────────────────────────────────────
section "Databases"

apt_pkg "redis-tools" redis-tools redis-cli

if has mongosh; then
    already "mongosh"
else
    spin "mongosh (tarball)" bash -c '
        ARCH=$(uname -m)
        [[ "$ARCH" == "aarch64" ]] && MARCH="arm64" || MARCH="x64"
        VER=$(curl -s https://api.github.com/repos/mongodb-js/mongosh/releases/latest \
            | grep -o "\"tag_name\": \"v[^\"]*\"" | grep -o "[0-9][^\"]*")
        if [[ -z "$VER" ]]; then echo "could not resolve mongosh version"; exit 1; fi
        curl -fsSL "https://downloads.mongodb.com/compass/mongosh-${VER}-linux-${MARCH}.tgz" \
            -o /tmp/mongosh.tgz
        tar -xzf /tmp/mongosh.tgz -C /tmp
        $SUDO cp /tmp/mongosh-*/bin/mongosh /usr/local/bin/
        $SUDO chmod +x /usr/local/bin/mongosh
        rm -f /tmp/mongosh.tgz && rm -rf /tmp/mongosh-*/
    ' || true
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Exploit lookup"

apt_pkg "exploitdb (searchsploit)" exploitdb searchsploit

# ─────────────────────────────────────────────────────────────────────────────
section "SAST / secrets scanning"

pip_pkg "semgrep"   semgrep     semgrep
pip_pkg "bandit"    bandit      bandit
pip_pkg "safety"    safety      safety

if has trufflehog; then
    already "trufflehog"
else
    spin "trufflehog" bash -c \
        'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | $SUDO sh -s -- -b /usr/local/bin' || true
fi

go_pkg "gitleaks" gitleaks "github.com/zricethezav/gitleaks/v8@latest"

if has trivy; then
    already "trivy"
else
    spin "trivy" bash -c \
        'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b /usr/local/bin' || true
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Reverse engineering / binary"

apt_pkg "binwalk"   binwalk                     binwalk
apt_pkg "yara"      yara                        yara
apt_pkg "strace"    strace                      strace
apt_pkg "ltrace"    ltrace                      ltrace
apt_pkg "binutils"  binutils                    readelf
apt_pkg "file"      file                        file
apt_pkg "exiftool"  libimage-exiftool-perl      exiftool

# ─────────────────────────────────────────────────────────────────────────────
section "Cloud tools"

if has aws; then
    already "awscli"
else
    ARCH=$(uname -m)
    [[ "$ARCH" == "aarch64" ]] \
        && AWS_URL="https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" \
        || AWS_URL="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
    spin "awscli v2" bash -c "
        TMP=\$(mktemp -d)
        curl -sSfL '$AWS_URL' -o \"\$TMP/awscliv2.zip\"
        unzip -q \"\$TMP/awscliv2.zip\" -d \"\$TMP\"
        \$SUDO \"\$TMP/aws/install\"
        rm -rf \"\$TMP\"
    " || true
fi

if has gcloud; then
    already "gcloud"
else
    spin "gcloud (adding Google repo)" bash -c '
        curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
            $SUDO gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
            $SUDO tee /etc/apt/sources.list.d/google-cloud-sdk.list >/dev/null
        $SUDO apt-get update -qq
        $SUDO apt-get install -y google-cloud-cli
    ' || true
fi

# ─────────────────────────────────────────────────────────────────────────────
section "Python requirements"

pip_pkg "paramiko"  paramiko  ""

if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
    spin "requirements.txt" "$PIP" install --quiet $PIP_FLAGS -r "$SCRIPT_DIR/requirements.txt" || true
fi

# ─────────────────────────────────────────────────────────────────────────────
# Go bin to PATH
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
    echo ""
    echo -e "  ${YELLOW}!${NC}  Added \$HOME/go/bin to PATH — run: ${BOLD}source ~/.bashrc${NC}"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
printf   "  ${GREEN}✓${NC}  Installed:  %d\n" "$INSTALLED"
printf   "  ${CYAN}=${NC}  Skipped:    %d  (already present)\n" "$SKIPPED"
if [[ $FAILED -gt 0 ]]; then
    printf "  ${RED}✗${NC}  Failed:     %d\n" "$FAILED"
    for t in "${FAILED_LIST[@]}"; do
        echo -e "       ${RED}•${NC} $t"
    done
    echo ""
    echo -e "  See full log: ${BOLD}${LOGFILE}${NC}"
fi
echo -e "  ${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
