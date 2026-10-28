#!/usr/bin/env bash
# ==============================================================================
# Build openmediavault-ro-api_1.0.0-1_all.deb from canonical OMV repo layout
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

# Generate binary DEBIAN/control from canonical debian/control
cat << 'EOF' > "${ROOT_DIR}/DEBIAN/control"
Package: openmediavault-ro-api
Version: 1.0.0-1
Section: utils
Plugin-Section: utilities
Priority: optional
Architecture: all
Depends: openmediavault (>= 7.0)
Maintainer: shurushetr <shurushetr@gmail.com>
Homepage: https://github.com/shurushetr/openmediavault-ro-api
Description: openmediavault Read-Only API plugin
 Read-only JSON-RPC and REST API plugin for OpenMediaVault 7/8 with
 granular per-scope access controls, automatic password and secret
 redaction, IP/CIDR allowlisting, native System Logs integration,
 and optional Infisical Universal Auth token synchronization.
EOF

sed '/^#DEBHELPER#/d' "${SCRIPT_DIR}/debian/openmediavault-ro-api.postinst" > "${ROOT_DIR}/DEBIAN/postinst"
sed '/^#DEBHELPER#/d' "${SCRIPT_DIR}/debian/openmediavault-ro-api.postrm" > "${ROOT_DIR}/DEBIAN/postrm"
cp -a "${SCRIPT_DIR}/debian/openmediavault-ro-api.triggers" "${ROOT_DIR}/DEBIAN/triggers"

# Copy canonical filesystem trees installed by debian/install
for dir in etc srv usr var; do
    if [ -d "${SCRIPT_DIR}/${dir}" ]; then
        cp -a "${SCRIPT_DIR}/${dir}" "${ROOT_DIR}/"
    fi
done

# Optional build-time initial token injection (keeps git source 100% secret-free)
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
find "${ROOT_DIR}/etc" "${ROOT_DIR}/srv" "${ROOT_DIR}/usr" "${ROOT_DIR}/var" -type f -exec chmod 0644 {} +
chmod 0644 "${ROOT_DIR}/DEBIAN/control" "${ROOT_DIR}/DEBIAN/triggers"
chmod 0755 "${ROOT_DIR}/DEBIAN/postinst" "${ROOT_DIR}/DEBIAN/postrm"
chmod 0755 "${ROOT_DIR}/usr/share/openmediavault/confdb/create.d/conf.service.roapi.sh"

mkdir -p "${OUT_DIR}"
dpkg-deb -Zxz --root-owner-group --build "${ROOT_DIR}" "${DEB_FILE}"
echo "Built Debian package: ${DEB_FILE}"
dpkg-deb --info "${DEB_FILE}"
