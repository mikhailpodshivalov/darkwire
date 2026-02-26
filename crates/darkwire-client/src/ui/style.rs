use crossterm::style::Color;

pub(super) fn sender_color(sender: &str) -> Option<Color> {
    let normalized = sender.trim().trim_start_matches('@').to_ascii_lowercase();
    if normalized.starts_with("fp:") {
        return Some(Color::White);
    }
    match normalized.as_str() {
        "mike" => Some(Color::Green),
        "yura" => Some(Color::Blue),
        "anna" => Some(Color::Magenta),
        "bot" => Some(Color::Yellow),
        "you" | "me" => Some(Color::Cyan),
        "sys" | "ready" | "event" => Some(Color::DarkGrey),
        "err" => Some(Color::Red),
        "peer" => Some(Color::White),
        "trust" => Some(Color::Yellow),
        "e2e" => Some(Color::Cyan),
        "keys" => Some(Color::Magenta),
        "login" => Some(Color::Green),
        "session" => Some(Color::Blue),
        "invite" => Some(Color::White),
        "rate" => Some(Color::DarkYellow),
        "error" => Some(Color::Red),
        _ => color_from_name_hash(&normalized),
    }
}

fn color_from_name_hash(value: &str) -> Option<Color> {
    if value.is_empty() {
        return None;
    }

    let mut hash = 2166136261_u32;
    for byte in value.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16777619);
    }

    const PALETTE: &[Color] = &[
        Color::Cyan,
        Color::Green,
        Color::Blue,
        Color::Magenta,
        Color::Yellow,
        Color::White,
    ];

    Some(PALETTE[(hash as usize) % PALETTE.len()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_color_uses_fixed_mapping_for_known_names() {
        assert_eq!(sender_color("mike"), Some(Color::Green));
        assert_eq!(sender_color("yura"), Some(Color::Blue));
        assert_eq!(sender_color("anna"), Some(Color::Magenta));
        assert_eq!(sender_color("bot"), Some(Color::Yellow));
    }

    #[test]
    fn sender_color_hash_mapping_is_stable_for_unknown_names() {
        assert_eq!(sender_color("unknown_user"), sender_color("unknown_user"));
    }
}
