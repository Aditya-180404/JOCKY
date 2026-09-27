#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STAGING_DIR="${JOCKEY_DEB_STAGING_DIR:-${SCRIPT_DIR}/debian-stage}"
PACKAGE_OUTPUT="${JOCKEY_DEB_OUTPUT:-${ROOT_DIR}/jockey_0.1.0_amd64.deb}"

echo "Building release binary for jockey-cli..."
cargo build --release -p jockey-cli

echo "Setting up staging directory..."
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/usr/bin"
cp -r "${SCRIPT_DIR}/debian/DEBIAN" "${STAGING_DIR}/DEBIAN"
cp "${ROOT_DIR}/target/release/jockey" "${STAGING_DIR}/usr/bin/jockey"

chmod 755 "${STAGING_DIR}/DEBIAN"
chmod 755 "${STAGING_DIR}/usr" "${STAGING_DIR}/usr/bin"
chmod 755 "${STAGING_DIR}/usr/bin/jockey"
chmod 644 "${STAGING_DIR}/DEBIAN/control"

echo "Building Debian package..."
mkdir -p "$(dirname "${PACKAGE_OUTPUT}")"
dpkg-deb --build "${STAGING_DIR}" "${PACKAGE_OUTPUT}"

echo "Package successfully generated at: ${PACKAGE_OUTPUT}"
