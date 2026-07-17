#!/usr/bin/env bash
# configure-containerd-kata.sh — Register Kata as a containerd runtime
set -euo pipefail

CONFIG="/etc/containerd/config.toml"

echo "==> Generating default containerd config"
mkdir -p /etc/containerd
containerd config default > "${CONFIG}"

echo "==> Backing up ${CONFIG} to ${CONFIG}.bak"
cp "${CONFIG}" "${CONFIG}.bak"

# Check if kata runtime is already configured
if grep -q "runtimes.kata" "${CONFIG}"; then
    echo "==> Kata runtime already registered in ${CONFIG}"
    exit 0
fi

# Append kata runtime block
cat >> "${CONFIG}" << 'TOML'

[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]
  runtime_type = 'io.containerd.kata.v2'
  [plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration.toml"
TOML

echo "==> Kata runtime registered in ${CONFIG}"
echo "==> Verifying:"
grep -A 3 'runtimes.kata' "${CONFIG}"
