#!/usr/bin/env bash
set -euo pipefail

echo "==> Building omavault (release, LTO, hardened)..."
cargo build --release

BIN_DIR="${HOME}/.local/bin"
SYSTEMD_DIR="${HOME}/.config/systemd/user"
HYPR_DIR="${HOME}/.config/hypr"

mkdir -p "${BIN_DIR}" "${SYSTEMD_DIR}" "${HYPR_DIR}"

install -m 0700 target/release/omavault "${BIN_DIR}/omavault"
echo "==> Installed binary to ${BIN_DIR}/omavault"

install -m 0644 omarchy/omavaultd.service "${SYSTEMD_DIR}/omavaultd.service"
echo "==> Installed systemd user unit to ${SYSTEMD_DIR}/omavaultd.service"

install -m 0644 omarchy/hypr-omavault.conf "${HYPR_DIR}/omavault.conf"
echo "==> Installed Hyprland config snippet to ${HYPR_DIR}/omavault.conf"

if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload || true
    systemctl --user enable --now omavaultd.service || true
    echo "==> Enabled and started omavaultd.service"
fi

echo ""
echo "Next steps on your Omarchy laptop:"
echo "  1. Add this line to ~/.config/hypr/hyprland.conf:"
echo "       source = ~/.config/hypr/omavault.conf"
echo "  2. (Optional) Add omavault lock hooks from omarchy/hypridle-hook.conf to ~/.config/hypr/hypridle.conf"
echo "  3. (Optional, for YubiKey FIDO2) Install libfido2:"
echo "       sudo pacman -S libfido2"
echo "  4. Initialize your vault:"
echo "       omavault init"
echo "  5. Press Super + Shift + P anywhere in Hyprland to open omavault!"
