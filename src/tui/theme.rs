use ratatui::style::{Color, Modifier, Style};

/// Omarchy-inspired Tokyo Night dark palette.
pub const BG_PRIMARY: Color = Color::Rgb(26, 27, 38);
pub const BG_ELEVATED: Color = Color::Rgb(36, 40, 59);
pub const FG_PRIMARY: Color = Color::Rgb(192, 202, 245);
pub const FG_MUTED: Color = Color::Rgb(120, 124, 153);
pub const ACCENT_CYAN: Color = Color::Rgb(125, 207, 255);
pub const ACCENT_BLUE: Color = Color::Rgb(122, 162, 247);
pub const ACCENT_MAGENTA: Color = Color::Rgb(187, 154, 247);
pub const ACCENT_GREEN: Color = Color::Rgb(158, 206, 106);
pub const ACCENT_YELLOW: Color = Color::Rgb(224, 175, 104);
pub const ACCENT_RED: Color = Color::Rgb(247, 118, 142);
pub const BORDER_DIM: Color = Color::Rgb(65, 72, 104);

pub fn title_style() -> Style {
    Style::default()
        .fg(ACCENT_CYAN)
        .add_modifier(Modifier::BOLD)
}

pub fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(ACCENT_BLUE)
    } else {
        Style::default().fg(BORDER_DIM)
    }
}

pub fn selected_style() -> Style {
    Style::default()
        .bg(BG_ELEVATED)
        .fg(ACCENT_CYAN)
        .add_modifier(Modifier::BOLD)
}

pub fn muted_style() -> Style {
    Style::default().fg(FG_MUTED)
}

pub fn ok_style() -> Style {
    Style::default()
        .fg(ACCENT_GREEN)
        .add_modifier(Modifier::BOLD)
}

pub fn warn_style() -> Style {
    Style::default()
        .fg(ACCENT_YELLOW)
        .add_modifier(Modifier::BOLD)
}

pub fn danger_style() -> Style {
    Style::default().fg(ACCENT_RED).add_modifier(Modifier::BOLD)
}
