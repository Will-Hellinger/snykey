#!/bin/bash
set -euo pipefail

# Get script and volume paths
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
vol="${dir}/../.container_volumes"

# Check for required commands
dependencies=(cp chmod mkdir)
for cmd in "${dependencies[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd is required." >&2; exit 1; }
done

echo ">>> Initializing required directories..."

# Create necessary directories
for d in certs app/logs openbao/logs openbao/data openbao/config openbao/certs openbao/file; do
    mkdir -p "$vol/$d"
done

# Copy configuration files for OpenBao
echo "Transferring OpenBao config..."
config_src="$dir/../configs/bao_config.hcl"
config_dst="$vol/openbao/config/config.hcl"
if [ -f "$config_src" ]; then
    cp "$config_src" "$config_dst"
    echo "OpenBao config copied"
else
    echo "OpenBao config not found at $config_src" >&2
fi

# Set permissions safely
chmod -R 755 "$vol"
[ -f "$config_dst" ] && chmod 644 "$config_dst"

# Generate certificates
if [ -x "$dir/generate_certificates.sh" ]; then
    "$dir/generate_certificates.sh"
else
    echo "Warning: generate_certificates.sh not found or not executable." >&2
fi

echo "All setup steps completed."
echo "You may now start the stack with: docker-compose up"