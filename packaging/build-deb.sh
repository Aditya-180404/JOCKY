#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STAGING_DIR="${JOCKY_DEB_STAGING_DIR:-${SCRIPT_DIR}/debian-stage}"
PACKAGE_OUTPUT="${JOCKY_DEB_OUTPUT:-${ROOT_DIR}/jocky_0.1.0_amd64.deb}"

echo "Building release binary for jocky-cli..."
cargo build --release -p jocky-cli

echo "Setting up staging directory..."
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/usr/bin"
cp -r "${SCRIPT_DIR}/debian/DEBIAN" "${STAGING_DIR}/DEBIAN"
cp "${ROOT_DIR}/target/release/jocky" "${STAGING_DIR}/usr/bin/jocky"

chmod 755 "${STAGING_DIR}/DEBIAN"
chmod 755 "${STAGING_DIR}/usr" "${STAGING_DIR}/usr/bin"
chmod 755 "${STAGING_DIR}/usr/bin/jocky"
chmod 644 "${STAGING_DIR}/DEBIAN/control"

echo "Building Debian package..."
mkdir -p "$(dirname "${PACKAGE_OUTPUT}")"
dpkg-deb --build "${STAGING_DIR}" "${PACKAGE_OUTPUT}"

echo "Package successfully generated at: ${PACKAGE_OUTPUT}"
