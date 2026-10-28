#!/usr/bin/env bash
# ==============================================================================
# Build openmediavault-ro-api_1.0.0-1_all.deb
# Usage:
#   ./build-deb.sh [/output/dir]
#   DEFAULT_OMV_RO_TOKEN="<64-hex>" ./build-deb.sh [/output/dir]
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/dist}"
PKG_NAME="openmediavault-ro-api"
PKG_VER="1.0.0-1"
DEB_FILE="${OUT_DIR}/${PKG_NAME}_${PKG_VER}_all.deb"

STAGE_DIR="$(mktemp -d "/tmp/${PKG_NAME}-build.XXXXXX")"
trap 'rm -rf "${STAGE_DIR}"' EXIT

ROOT_DIR="${STAGE_DIR}/${PKG_NAME}_${PKG_VER}_all"
mkdir -p "${ROOT_DIR}/DEBIAN"
cp -a "${SCRIPT_DIR}/DEBIAN/." "${ROOT_DIR}/DEBIAN/"
cp -a "${SCRIPT_DIR}/src/." "${ROOT_DIR}/"

# Optional build-time initial token injection (keeps git source secret-free)
if [ -n "${DEFAULT_OMV_RO_TOKEN:-}" ]; then
    sed -i "s|__INITIAL_RO_TOKEN__|${DEFAULT_OMV_RO_TOKEN}|g" \
        "${ROOT_DIR}/usr/share/openmediavault/confdb/create.d/conf.service.roapi.sh"
fi

# Install Debian changelog & copyright required by OMV's package viewer
DOC_DIR="${ROOT_DIR}/usr/share/doc/${PKG_NAME}"
mkdir -p "${DOC_DIR}"
gzip -9nc "${SCRIPT_DIR}/debian/changelog" > "${DOC_DIR}/changelog.Debian.gz"
cp -a "${SCRIPT_DIR}/debian/copyright" "${DOC_DIR}/copyright"

# Normalize permissions
find "${ROOT_DIR}" -type d -exec chmod 0755 {} +
find "${ROOT_DIR}/usr" "${ROOT_DIR}/var" -type f -exec chmod 0644 {} +
chmod 0644 "${ROOT_DIR}/DEBIAN/control" "${ROOT_DIR}/DEBIAN/triggers"
chmod 0755 "${ROOT_DIR}/DEBIAN/postinst" "${ROOT_DIR}/DEBIAN/postrm"
chmod 0755 "${ROOT_DIR}/usr/share/openmediavault/confdb/create.d/conf.service.roapi.sh"

mkdir -p "${OUT_DIR}"
dpkg-deb -Zxz --root-owner-group --build "${ROOT_DIR}" "${DEB_FILE}"
echo "Built Debian package: ${DEB_FILE}"
dpkg-deb --info "${DEB_FILE}"
