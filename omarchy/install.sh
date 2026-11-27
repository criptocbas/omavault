#!/usr/bin/env bash
set -euo pipefail
umask 077

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "==> Building omavault (release, locked, LTO, hardened)..."
cargo build --release --locked

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN_DIR="${HOME}/.local/bin"
SYSTEMD_DIR="${HOME}/.config/systemd/user"
HYPR_DIR="${HOME}/.config/hypr"

mkdir -p "${BIN_DIR}" "${SYSTEMD_DIR}" "${HYPR_DIR}"

# A packaged unit at /usr/lib is the one that should run. A leftover user unit
# shadows it and keeps ExecStart pointed at ~/.local/bin/omavault.
if [[ -e /usr/lib/systemd/user/omavaultd.service && -e "${SYSTEMD_DIR}/omavaultd.service" ]]; then
    echo "Warning: ${SYSTEMD_DIR}/omavaultd.service shadows the packaged unit" >&2
    echo "         (/usr/lib/systemd/user/omavaultd.service) and points at ~/.local/bin/omavault." >&2
    echo "         Remove the user unit if you want the packaged service:" >&2
    echo "         rm ${SYSTEMD_DIR}/omavaultd.service && systemctl --user daemon-reload" >&2
fi
if [[ -e /usr/bin/omavault && -e "${BIN_DIR}/omavault" ]]; then
    echo "Warning: both /usr/bin/omavault and ${BIN_DIR}/omavault exist." >&2
    echo "         Hyprland launches /usr/bin/omavault when it is present; the copy under ~/.local/bin is separate." >&2
fi

install -m 0700 "${TARGET_DIR}/release/omavault" "${BIN_DIR}/omavault"
echo "==> Installed binary to ${BIN_DIR}/omavault (0700)"

install -m 0600 omarchy/omavaultd.service "${SYSTEMD_DIR}/omavaultd.service"
echo "==> Installed systemd user unit to ${SYSTEMD_DIR}/omavaultd.service (0600)"

USE_LUA=false
if [[ -f "${HYPR_DIR}/hyprland.lua" || -f "/usr/share/omarchy/default/hypr/bootstrap.lua" ]]; then
    USE_LUA=true
fi

if [[ "${USE_LUA}" == "true" ]]; then
    install -m 0600 omarchy/omavault.lua "${HYPR_DIR}/omavault.lua"
    echo "==> Installed Omarchy Lua Hyprland module to ${HYPR_DIR}/omavault.lua (0600)"
else
    install -m 0600 omarchy/hypr-omavault.conf "${HYPR_DIR}/omavault.conf"
    echo "==> Installed Hyprland config snippet to ${HYPR_DIR}/omavault.conf (0600)"
fi

if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user daemon-reload && systemctl --user enable omavaultd.service && systemctl --user restart omavaultd.service; then
        echo "==> Enabled and restarted omavaultd.service"
    else
        echo "Warning: could not reload/restart omavaultd.service via systemd --user (start manually with: omavault daemon)" >&2
    fi
fi

echo ""
echo "Next steps on your Omarchy laptop:"
if [[ "${USE_LUA}" == "true" ]]; then
    echo "  1. Add this line to ~/.config/hypr/hyprland.lua:"
    echo '       require("hypr.omavault")'
    echo "     Then reload and validate: hyprctl reload && hyprctl configerrors"
    echo "     (omavaultd automatically detects Omarchy's lock screen via Hyprland IPC.)"
else
    echo "  1. Add this line to ~/.config/hypr/hyprland.conf:"
    echo "       source = ~/.config/hypr/omavault.conf"
    echo "  2. (Optional) Add omavault lock hooks from omarchy/hypridle-hook.conf to ~/.config/hypr/hypridle.conf"
fi
echo "  - (Optional, for YubiKey FIDO2) Ensure libfido2 is installed:"
echo "       sudo pacman -S libfido2"
echo "  - Initialize your vault:"
echo "       omavault init"
if [[ "${USE_LUA}" == "true" ]]; then
    echo "  - Press Super + Shift + / anywhere in Hyprland to open omavault!"
else
    echo "  - Press Super + Shift + P anywhere in Hyprland to open omavault!"
fi
