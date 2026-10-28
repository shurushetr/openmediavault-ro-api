#!/usr/bin/env bash
# ==============================================================================
# Build a standard GPG-signed Debian APT repository for openmediavault-ro-api
# Compatible with:
#   1. OpenMediaVault 7/8 `openmediavault-apt` UI (DEB822 URIs / Suites / Components / Key)
#   2. `omv-extras`-style 1-line installer (`wget -O - <REPO_URL>/install | sudo bash`)
#   3. Direct `.deb` download (`<REPO_URL>/openmediavault-ro-api_1.0.0-1_all.deb`)
#
# Usage:
#   ./scripts/build-apt-repo.sh <deb_file> <output_repo_dir> [public_repo_url]
# ==============================================================================
set -euo pipefail

DEB_INPUT="${1:?Usage: $0 <deb_file> <output_repo_dir> [public_repo_url]}"
REPO_OUT="${2:?Usage: $0 <deb_file> <output_repo_dir> [public_repo_url]}"
PUBLIC_URL="${3:-https://shurushetr.github.io/openmediavault-ro-api}"
PUBLIC_URL="${PUBLIC_URL%/}"

DEB_BASENAME="$(basename "${DEB_INPUT}")"
POOL_REL="pool/main/o/openmediavault-ro-api/${DEB_BASENAME}"

mkdir -p "${REPO_OUT}/pool/main/o/openmediavault-ro-api"
if [ "$(realpath "${DEB_INPUT}")" != "$(realpath "${REPO_OUT}/${DEB_BASENAME}" 2>/dev/null || true)" ]; then
    cp -f "${DEB_INPUT}" "${REPO_OUT}/${DEB_BASENAME}"
fi
cp -f "${DEB_INPUT}" "${REPO_OUT}/${POOL_REL}"

# Ephemeral or persistent GPG signing key for APT repository metadata
GNUPG_DIR="${GNUPGHOME:-${REPO_OUT}/.gnupg- build}"
trap 'rm -rf "${REPO_OUT}/.gnupg- build"' EXIT
mkdir -p "${GNUPG_DIR}"
chmod 0700 "${GNUPG_DIR}"

if ! gpg --homedir "${GNUPG_DIR}" --list-secret-keys "openmediavault-ro-api" >/dev/null 2>&1; then
    gpg --homedir "${GNUPG_DIR}" --batch --gen-key << 'EOF'
%no-protection
Key-Type: RSA
Key-Length: 3072
Name-Real: openmediavault-ro-api Archive Automatic Signing Key
Name-Email: shurushetr@gmail.com
Expire-Date: 0
%commit
EOF
fi

gpg --homedir "${GNUPG_DIR}" --batch --yes --export "openmediavault-ro-api" > "${REPO_OUT}/openmediavault-ro-api-keyring.gpg"
gpg --homedir "${GNUPG_DIR}" --batch --yes --armor --export "openmediavault-ro-api" \
    | sed '2s/^$/./' > "${REPO_OUT}/openmediavault-ro-api.asc"

# Generate Packages, Packages.gz, Release, InRelease, and Release.gpg for each OMV / Debian suite
python3 - "${REPO_OUT}" "${POOL_REL}" << 'PYEOF'
import datetime, gzip, hashlib, os, subprocess, sys

repo_out = sys.argv[1]
pool_rel = sys.argv[2]
deb_path = os.path.join(repo_out, pool_rel)

ctrl = subprocess.check_output(["dpkg-deb", "-f", deb_path], text=True).strip()
data = open(deb_path, "rb").read()

pkg_stanza = (
    ctrl + "\n"
    f"Filename: {pool_rel}\n"
    f"Size: {len(data)}\n"
    f"MD5sum: {hashlib.md5(data).hexdigest()}\n"
    f"SHA1: {hashlib.sha1(data).hexdigest()}\n"
    f"SHA256: {hashlib.sha256(data).hexdigest()}\n\n"
)

suites = ["sandworm", "bookworm", "synchrony", "trixie", "stable"]
archs = ["binary-amd64", "binary-arm64", "binary-armhf", "binary-i386", "binary-all"]
now_rfc2822 = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S UTC")

for suite in suites:
    suite_dir = os.path.join(repo_out, "dists", suite)
    rel_files = []
    for arch in archs:
        arch_dir = os.path.join(suite_dir, "main", arch)
        os.makedirs(arch_dir, exist_ok=True)
        p_raw = pkg_stanza.encode("utf-8")
        p_gz = gzip.compress(p_raw, compresslevel=9)
        open(os.path.join(arch_dir, "Packages"), "wb").write(p_raw)
        open(os.path.join(arch_dir, "Packages.gz"), "wb").write(p_gz)
        for fname, content in [(f"main/{arch}/Packages", p_raw), (f"main/{arch}/Packages.gz", p_gz)]:
            rel_files.append((
                fname,
                len(content),
                hashlib.md5(content).hexdigest(),
                hashlib.sha1(content).hexdigest(),
                hashlib.sha256(content).hexdigest(),
            ))

    release_lines = [
        "Origin: openmediavault-ro-api",
        "Label: openmediavault-ro-api",
        f"Suite: {suite}",
        f"Codename: {suite}",
        f"Date: {now_rfc2822}",
        "Architectures: amd64 arm64 armhf i386 all",
        "Components: main",
        "Description: OpenMediaVault Read-Only API Plugin Repository",
        "MD5Sum:",
    ]
    for fname, sz, md5, _, _ in rel_files:
        release_lines.append(f" {md5} {sz:8d} {fname}")
    release_lines.append("SHA1:")
    for fname, sz, _, sha1, _ in rel_files:
        release_lines.append(f" {sha1} {sz:8d} {fname}")
    release_lines.append("SHA256:")
    for fname, sz, _, _, sha256 in rel_files:
        release_lines.append(f" {sha256} {sz:8d} {fname}")

    release_content = "\n".join(release_lines) + "\n"
    open(os.path.join(suite_dir, "Release"), "w", encoding="utf-8").write(release_content)
PYEOF

for suite in sandworm bookworm synchrony trixie stable; do
    SUITE_DIR="${REPO_OUT}/dists/${suite}"
    gpg --homedir "${GNUPG_DIR}" --batch --yes --detach-sign -abs \
        -o "${SUITE_DIR}/Release.gpg" "${SUITE_DIR}/Release"
    gpg --homedir "${GNUPG_DIR}" --batch --yes --clearsign \
        -o "${SUITE_DIR}/InRelease" "${SUITE_DIR}/Release"
done

# Generate omv-extras style 1-line bootstrap script (`wget -O - <PUBLIC_URL>/install | sudo bash`)
cat << EOF > "${REPO_OUT}/install"
#!/usr/bin/env bash
set -euo pipefail

REPO_URL="\${OMV_RO_REPO_URL:-${PUBLIC_URL}}"
KEYRING="/usr/share/keyrings/openmediavault-ro-api-keyring.gpg"
SOURCES_FILE="/etc/apt/sources.list.d/openmediavault-ro-api.sources"

echo ":: Installing openmediavault-ro-api APT keyring..."
curl -fsSL "\${REPO_URL}/openmediavault-ro-api-keyring.gpg" -o "\${KEYRING}"
chmod 0644 "\${KEYRING}"

echo ":: Configuring DEB822 APT source (\${SOURCES_FILE})..."
cat << DEB822 > "\${SOURCES_FILE}"
Types: deb
URIs: \${REPO_URL}
Suites: sandworm
Components: main
Signed-By: \${KEYRING}
DEB822

echo ":: Updating APT cache and installing openmediavault-ro-api..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y openmediavault-ro-api
echo ":: openmediavault-ro-api installed successfully! Refresh your OpenMediaVault Web UI (Services -> Read-Only API)."
EOF
chmod 0755 "${REPO_OUT}/install"

echo "Built signed Debian APT repository at: ${REPO_OUT} (URL: ${PUBLIC_URL})"
