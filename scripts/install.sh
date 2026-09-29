#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  JOCKY Installer — Linux / macOS                                        ║
# ║                                                                          ║
# ║  Usage (one-liner):                                                      ║
# ║    curl -fsSL https://raw.githubusercontent.com/Aditya-180404/JOCKY/   ║
# ║         main/scripts/install.sh | bash                                   ║
# ║                                                                          ║
# ║  Or download and run locally:                                            ║
# ║    bash install.sh [--prefix /usr/local] [--uninstall] [--version X.Y.Z]║
# ╚══════════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
REPO="Aditya-180404/JOCKY"
BINARY_NAME="jocky"
INSTALL_PREFIX="${JOCKY_PREFIX:-/usr/local}"
INSTALL_DIR="${INSTALL_PREFIX}/bin"
VERSION="${JOCKY_VERSION:-latest}"
UNINSTALL=false
NO_MODIFY_PATH=false

# ─── Colors ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

log()  { echo -e "${BOLD}${CYAN}[JOCKY]${RESET} $*"; }
ok()   { echo -e "${GREEN}  ✓${RESET} $*"; }
warn() { echo -e "${YELLOW}  ⚠${RESET} $*"; }
err()  { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }
step() { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)         INSTALL_PREFIX="$2"; INSTALL_DIR="${INSTALL_PREFIX}/bin"; shift 2 ;;
    --version)        VERSION="$2"; shift 2 ;;
    --uninstall)      UNINSTALL=true; shift ;;
    --no-modify-path) NO_MODIFY_PATH=true; shift ;;
    --help|-h)
      echo "Usage: install.sh [OPTIONS]"
      echo "Options:"
      echo "  --prefix DIR       Install directory prefix (default: /usr/local)"
      echo "  --version VERSION  Install a specific version (default: latest)"
      echo "  --uninstall        Remove JOCKY from your system"
      echo "  --no-modify-path   Do not modify shell profile PATH"
      echo "  --help             Show this message"
      exit 0 ;;
    *) err "Unknown argument: $1" ;;
  esac
done

# ─── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   JOCKY Forensic Language Compiler   ║"
if $UNINSTALL; then
  echo "  ║          Uninstaller                 ║"
else
  echo "  ║           Installer                  ║"
fi
echo "  ╚══════════════════════════════════════╝"
echo -e "${RESET}"

# ─── Uninstall ────────────────────────────────────────────────────────────────
if $UNINSTALL; then
  step "Uninstalling JOCKY"
  BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
  if [ -f "$BINARY_PATH" ]; then
    rm -f "$BINARY_PATH"
    ok "Removed ${BINARY_PATH}"
  else
    warn "${BINARY_PATH} not found — skipping"
  fi
  for profile in ~/.bashrc ~/.bash_profile ~/.zshrc ~/.profile; do
    if [ -f "$profile" ] && grep -q "JOCKY" "$profile" 2>/dev/null; then
      sed -i '/# JOCKY/,+1d' "$profile"
      ok "Cleaned PATH entry from ${profile}"
    fi
  done
  echo ""
  ok "JOCKY has been uninstalled."
  exit 0
fi

# ─── Platform detection ───────────────────────────────────────────────────────
step "Detecting platform"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *)      err "Unsupported OS: $OS. Use install.ps1 on Windows." ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH_TAG="x86_64" ;;
  aarch64|arm64) ARCH_TAG="aarch64" ;;
  *)             err "Unsupported architecture: $ARCH" ;;
esac

ok "OS: ${OS} / Arch: ${ARCH}"

# ─── Dependency check ─────────────────────────────────────────────────────────
step "Checking dependencies"
MISSING_DEPS=()
for cmd in curl tar; do
  command -v "$cmd" &>/dev/null || MISSING_DEPS+=("$cmd")
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
  warn "Missing tools: ${MISSING_DEPS[*]} — attempting auto-install..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq "${MISSING_DEPS[@]}"
  elif command -v yum &>/dev/null; then
    sudo yum install -y -q "${MISSING_DEPS[@]}"
  elif command -v brew &>/dev/null; then
    brew install "${MISSING_DEPS[@]}"
  else
    err "Cannot auto-install dependencies. Please install: ${MISSING_DEPS[*]}"
  fi
fi
ok "All dependencies present"

# ─── Resolve version ──────────────────────────────────────────────────────────
step "Resolving version"
if [ "$VERSION" = "latest" ]; then
  log "Fetching latest release from GitHub..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' \
    | head -1)"
  [ -z "$VERSION" ] && err "Could not determine latest version. Check your connection."
fi
ok "Version: ${VERSION}"

# ─── Download ─────────────────────────────────────────────────────────────────
step "Downloading JOCKY ${VERSION}"

VER_STRIPPED="${VERSION#v}"
ASSET_NAME="jocky_${VER_STRIPPED}_${PLATFORM}_${ARCH_TAG}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

log "URL: ${DOWNLOAD_URL}"
HTTP_CODE="$(curl -fsSL -w "%{http_code}" -o "${TMP_DIR}/${ASSET_NAME}" "${DOWNLOAD_URL}" 2>/dev/null || echo "000")"

if [ "$HTTP_CODE" = "200" ]; then
  ok "Downloaded ${ASSET_NAME}"
  tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "${TMP_DIR}"
  EXTRACTED_BIN="$(find "${TMP_DIR}" -name "${BINARY_NAME}" -not -name "*.tar.gz" -type f | head -1)"
  [ -z "$EXTRACTED_BIN" ] && err "Binary '${BINARY_NAME}' not found inside archive."
else
  # Fallback: try raw binary without tarball
  RAW_URL="https://github.com/${REPO}/releases/download/${VERSION}/jocky-${PLATFORM}-${ARCH_TAG}"
  log "Archive not found (${HTTP_CODE}), trying raw binary: ${RAW_URL}"
  HTTP_CODE2="$(curl -fsSL -w "%{http_code}" -o "${TMP_DIR}/${BINARY_NAME}" "${RAW_URL}" 2>/dev/null || echo "000")"
  [ "$HTTP_CODE2" != "200" ] && err "Download failed (HTTP ${HTTP_CODE2}).\nVisit: https://github.com/${REPO}/releases"
  ok "Downloaded raw binary"
  EXTRACTED_BIN="${TMP_DIR}/${BINARY_NAME}"
fi

chmod +x "${EXTRACTED_BIN}"

# ─── Install ──────────────────────────────────────────────────────────────────
step "Installing to ${INSTALL_DIR}"

if [ -w "${INSTALL_DIR}" ] || mkdir -p "${INSTALL_DIR}" 2>/dev/null; then
  SUDO=""
else
  command -v sudo &>/dev/null || err "Cannot write to ${INSTALL_DIR}. Try: --prefix ~/.local"
  SUDO="sudo"
  warn "Need sudo to write to ${INSTALL_DIR}"
fi

$SUDO mkdir -p "${INSTALL_DIR}"
$SUDO cp "${EXTRACTED_BIN}" "${INSTALL_DIR}/${BINARY_NAME}"
$SUDO chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
ok "Installed → ${INSTALL_DIR}/${BINARY_NAME}"

# ─── PATH setup ───────────────────────────────────────────────────────────────
step "Configuring PATH"

if echo ":${PATH}:" | grep -q ":${INSTALL_DIR}:"; then
  ok "${INSTALL_DIR} already in PATH"
elif $NO_MODIFY_PATH; then
  warn "Skipping PATH modification. Add manually:"
  echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
else
  SHELL_NAME="$(basename "${SHELL:-bash}")"
  case "$SHELL_NAME" in
    zsh)  PROFILE="$HOME/.zshrc" ;;
    fish) PROFILE="$HOME/.config/fish/config.fish" ;;
    *)    PROFILE="$HOME/.bashrc" ;;
  esac

  if grep -q "JOCKY" "$PROFILE" 2>/dev/null; then
    ok "PATH already configured in ${PROFILE}"
  else
    printf '\n# JOCKY\nexport PATH="%s:$PATH"\n' "${INSTALL_DIR}" >> "$PROFILE"
    ok "Added to ${PROFILE}"
    warn "Reload with: source ${PROFILE}  (or open a new terminal)"
  fi
fi

# ─── Verify ───────────────────────────────────────────────────────────────────
step "Verifying installation"
export PATH="${INSTALL_DIR}:${PATH}"

if command -v "${BINARY_NAME}" &>/dev/null; then
  INSTALLED_VER="$("${BINARY_NAME}" --version 2>/dev/null || echo "installed")"
  ok "Command: $(command -v ${BINARY_NAME})"
  ok "Version: ${INSTALLED_VER}"
else
  warn "jocky installed but not in current PATH — open a new terminal"
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔════════════════════════════════════════╗"
echo "  ║  JOCKY installed successfully! 🎉      ║"
echo "  ╠════════════════════════════════════════╣"
echo "  ║  Quick start:                          ║"
echo "  ║    jocky --help                        ║"
echo "  ║    jocky --version                     ║"
echo "  ║    jocky script.jy                     ║"
echo "  ╚════════════════════════════════════════╝"
echo -e "${RESET}"
