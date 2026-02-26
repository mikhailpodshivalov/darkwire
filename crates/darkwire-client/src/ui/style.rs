use crossterm::style::Color;

#[derive(Debug, Clone, Copy)]
pub(super) struct UiTheme {
    pub(super) you: Color,
    pub(super) system: Color,
    pub(super) error: Color,
    pub(super) fallback: Color,
    pub(super) hash_palette: [Color; 5],
}

impl Default for UiTheme {
    fn default() -> Self {
        Self {
            you: Color::Yellow,
            system: Color::DarkGrey,
            error: Color::Red,
            fallback: Color::White,
            hash_palette: [
                Color::Cyan,
                Color::Green,
                Color::Blue,
                Color::Magenta,
                Color::White,
            ],
        }
    }
}

impl UiTheme {
    pub(super) fn sender_color(&self, sender: &str) -> Option<Color> {
        let normalized = sender.trim().trim_start_matches('@').to_ascii_lowercase();
        if normalized.starts_with("fp:") {
            return Some(self.fallback);
        }
        if let Some(color) = known_sender_color(self, &normalized) {
            return Some(color);
        }
        color_from_name_hash(&normalized, &self.hash_palette)
    }
}

fn known_sender_color(theme: &UiTheme, normalized: &str) -> Option<Color> {
    match normalized {
        "mike" => Some(Color::Green),
        "yura" => Some(Color::Blue),
        "anna" => Some(Color::Magenta),
        "bot" => Some(Color::Yellow),
        "you" | "me" => Some(theme.you),
        "sys" => Some(theme.fallback),
        "ready" | "event" => Some(theme.system),
        "err" | "error" => Some(theme.error),
        "peer" => Some(theme.fallback),
        "trust" => Some(Color::Yellow),
        "e2e" => Some(Color::Cyan),
        "keys" => Some(Color::Magenta),
        "login" => Some(Color::Green),
        "session" => Some(Color::Blue),
        "invite" => Some(theme.fallback),
        "rate" => Some(Color::DarkYellow),
        _ => None,
    }
}

fn color_from_name_hash(value: &str, palette: &[Color]) -> Option<Color> {
    if value.is_empty() {
        return None;
    }

    let mut hash = 2166136261_u32;
    for byte in value.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16777619);
    }

    Some(palette[(hash as usize) % palette.len()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_color_uses_fixed_mapping_for_known_names() {
        let theme = UiTheme::default();
        assert_eq!(theme.sender_color("mike"), Some(Color::Green));
        assert_eq!(theme.sender_color("yura"), Some(Color::Blue));
        assert_eq!(theme.sender_color("anna"), Some(Color::Magenta));
        assert_eq!(theme.sender_color("bot"), Some(Color::Yellow));
    }

    #[test]
    fn sender_color_hash_mapping_is_stable_for_unknown_names() {
        let theme = UiTheme::default();
        assert_eq!(
            theme.sender_color("unknown_user"),
            theme.sender_color("unknown_user")
        );
    }

    #[test]
    fn theme_can_override_you_color() {
        let theme = UiTheme {
            you: Color::Green,
            ..UiTheme::default()
        };
        assert_eq!(theme.sender_color("you"), Some(Color::Green));
    }
}
