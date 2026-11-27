-- Omarchy 4.5+ / Hyprland Lua integration for omavault
-- Installed to ~/.config/hypr/omavault.lua
-- Load from ~/.config/hypr/hyprland.lua:
--   require("hypr.omavault")

local home = os.getenv("HOME") or ""
local omavault_bin = o.cmd_present("/usr/bin/omavault")
    and "/usr/bin/omavault"
  or (home ~= "" and (home .. "/.local/bin/omavault") or "omavault")

-- Floating, centered, screen-share-blocked window rules for the omavault TUI.
-- Using the `org.omarchy.omavault` app-id also matches Omarchy's `+terminal`
-- tag (see /usr/share/omarchy/default/hypr/apps/terminals.lua) so theme opacity
-- and styling follow your active Omarchy theme automatically.
o.window("^org\\.omarchy\\.omavault$", {
  float = true,
  center = true,
  size = { 1080, 680 },
  stay_focused = true,
  no_screen_share = true,
})

-- Prefer launching directly in `foot` with scrollback, primary-selection copy,
-- and OSC-52 clipboard writes all disabled so secrets shown in the TUI can
-- never leak into terminal scrollback or unsensitive selections.
local function omavault_launch_cmd()
  local quoted_bin = o.shell_quote(omavault_bin)
  if o.cmd_present("foot") then
    return "uwsm-app -- foot --app-id=org.omarchy.omavault --title=omavault"
      .. " -o scrollback.lines=0 -o main.selection-target=none -o security.osc52=disabled -- "
      .. quoted_bin
      .. " tui"
  elseif o.cmd_present("ghostty") then
    -- Ghostty 1.4 renamed --scrollback-limit to --scrollback-limit-bytes
    -- (compat alias). Set both byte and line limits to 0 so neither the 50 MB
    -- default nor unlimited lines keeps history. copy-on-select=none is the
    -- current name (false remains an alias). clipboard-write=deny is unchanged.
    return "uwsm-app -- ghostty --gtk-single-instance=false --class=org.omarchy.omavault"
      .. " --title=omavault --scrollback-limit-lines=0 --scrollback-limit-bytes=0"
      .. " --copy-on-select=none --clipboard-write=deny -e "
      .. quoted_bin
      .. " tui"
  elseif o.cmd_present("alacritty") then
    return "uwsm-app -- alacritty --class org.omarchy.omavault --title omavault"
      .. " -o scrolling.history=0 -o 'terminal.osc52=\"Disabled\"'"
      .. " -o selection.save_to_clipboard=false -e "
      .. quoted_bin
      .. " tui"
  else
    return "omarchy-launch-tui --app-id=org.omarchy.omavault " .. quoted_bin .. " tui"
  end
end

-- Replace SUPER + SHIFT + SLASH (Omarchy default: Passwords / 1Password) with omavault TUI.
o.rebind("SUPER + SHIFT + SLASH", "Password Vault (omavault)", omavault_launch_cmd())

-- Immediately lock omavault & wipe RAM/clipboard anywhere in Hyprland.
o.bind("SUPER + CTRL + SHIFT + L", "Lock omavault immediately", o.shell_quote(omavault_bin) .. " lock")
