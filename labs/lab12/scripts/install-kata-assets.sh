#!/usr/bin/env bash
# install-kata-assets.sh — Download Kata Containers static assets
set -euo pipefail

KATA_VERSION="${KATA_VERSION:-3.32.0}"
KATA_PREFIX="/opt/kata"

echo "==> Installing Kata Containers v${KATA_VERSION} to ${KATA_PREFIX}"

mkdir -p "${KATA_PREFIX}"

# Download the kata-static tarball (zstd compressed since 3.x)
KATA_TARBALL="kata-static-${KATA_VERSION}-amd64.tar.zst"
KATA_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/${KATA_TARBALL}"

echo "==> Downloading ${KATA_URL}"
curl -fSL "${KATA_URL}" -o "/tmp/${KATA_TARBALL}"

echo "==> Extracting to ${KATA_PREFIX}"
# Extract zstd tarball
tar --zstd -xf "/tmp/${KATA_TARBALL}" -C /
rm -f "/tmp/${KATA_TARBALL}"

# Write version file
echo "${KATA_VERSION}" > "${KATA_PREFIX}/VERSION"

echo "==> Kata v${KATA_VERSION} installed."
echo "==> VERSION: $(cat ${KATA_PREFIX}/VERSION)"
ls -la "${KATA_PREFIX}/bin/" 2>/dev/null | head -10 || echo "(bin/ may be at a different path)"
