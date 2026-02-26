use super::ChatLine;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn truncate_chars(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let mut out = String::with_capacity(input.len().min(max_chars));
    for ch in input.chars().take(max_chars) {
        out.push(ch);
    }
    out
}

pub(super) fn truncate_with_marker(input: &str, max_chars: usize) -> String {
    let total = input.chars().count();
    if total <= max_chars {
        return input.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }

    let mut out = truncate_chars(input, max_chars - 3);
    out.push_str("...");
    out
}

pub(super) fn tail_chars(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let count = input.chars().count();
    if count <= max_chars {
        return input.to_string();
    }

    input.chars().skip(count - max_chars).collect()
}

pub(super) fn pad_or_trim(input: &str, width: usize) -> String {
    let trimmed = truncate_chars(input, width);
    let len = trimmed.chars().count();
    if len >= width {
        return trimmed;
    }

    format!("{trimmed}{}", " ".repeat(width - len))
}

pub(super) fn hhmm_utc() -> String {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let day_secs = now_secs % 86_400;
    let hours = day_secs / 3_600;
    let mins = (day_secs % 3_600) / 60;
    format!("{hours:02}:{mins:02}")
}

pub(super) fn compact_history_row(line: &ChatLine, width: usize) -> String {
    let sender = truncate_with_marker(&line.sender, 10);
    let content = truncate_with_marker(&line.text, width.saturating_sub(19));
    truncate_with_marker(
        &format!("{} {}: {}", line.timestamp, sender, content),
        width,
    )
}

pub(super) fn wrap_chars(input: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    if input.is_empty() {
        return vec![String::new()];
    }

    let mut out = Vec::new();
    let mut current = String::new();
    let mut count = 0usize;

    for ch in input.chars() {
        if ch == '\n' {
            out.push(std::mem::take(&mut current));
            count = 0;
            continue;
        }

        current.push(ch);
        count += 1;

        if count >= width {
            out.push(std::mem::take(&mut current));
            count = 0;
        }
    }

    if !current.is_empty() {
        out.push(current);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_chars_keeps_end_of_long_input() {
        assert_eq!(tail_chars("abcdef", 3), "def");
        assert_eq!(tail_chars("abc", 5), "abc");
    }

    #[test]
    fn truncate_with_marker_appends_ascii_ellipsis() {
        assert_eq!(truncate_with_marker("abcdef", 5), "ab...");
        assert_eq!(truncate_with_marker("abc", 5), "abc");
        assert_eq!(truncate_with_marker("abcdef", 2), "..");
    }

    #[test]
    fn wrap_chars_splits_long_lines_by_width() {
        assert_eq!(
            wrap_chars("ABCDEFGHIJ", 4),
            vec!["ABCD".to_string(), "EFGH".to_string(), "IJ".to_string()]
        );
        assert_eq!(
            wrap_chars("ab\ncd", 8),
            vec!["ab".to_string(), "cd".to_string()]
        );
    }
}
