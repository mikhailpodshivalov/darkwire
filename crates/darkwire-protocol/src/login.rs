const LOGIN_MIN_LEN: usize = 3;
const LOGIN_MAX_LEN: usize = 24;
const BIND_CONTEXT: &str = "darkwire-login-bind-v1";

pub fn normalize_login(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_prefix = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let login = without_prefix.to_ascii_lowercase();
    if !(LOGIN_MIN_LEN..=LOGIN_MAX_LEN).contains(&login.len()) {
        return None;
    }

    if !login
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
    {
        return None;
    }

    Some(login)
}

pub fn format_login(login: &str) -> String {
    let normalized = normalize_login(login).unwrap_or_else(|| login.trim().to_ascii_lowercase());
    format!("@{normalized}")
}

pub fn login_bind_transcript(login: &str, ik_ed25519: &str) -> Vec<u8> {
    let normalized = normalize_login(login).unwrap_or_else(|| login.trim().to_ascii_lowercase());
    format!("{BIND_CONTEXT}\n{normalized}\n{ik_ed25519}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_login_accepts_expected_charset() {
        assert_eq!(normalize_login("@Mike-42"), Some("mike-42".to_string()));
        assert_eq!(normalize_login("user.name"), Some("user.name".to_string()));
        assert_eq!(normalize_login("x_y"), Some("x_y".to_string()));
    }

    #[test]
    fn normalize_login_rejects_invalid_values() {
        assert_eq!(normalize_login("ab"), None);
        assert_eq!(normalize_login("bad space"), None);
        assert_eq!(normalize_login("bad!"), None);
    }

    #[test]
    fn login_bind_transcript_is_stable() {
        let transcript = login_bind_transcript("@Mike", "ik123");
        assert_eq!(
            String::from_utf8(transcript).expect("utf8"),
            "darkwire-login-bind-v1\nmike\nik123"
        );
    }
}
