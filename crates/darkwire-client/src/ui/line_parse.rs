pub(super) fn parse_sender_line(line: &str) -> Option<(String, &str)> {
    if line.starts_with('[') {
        return None;
    }

    let (sender, body) = line.split_once("> ")?;
    if sender.is_empty() || sender.contains(' ') {
        return None;
    }

    Some((sender.to_string(), body))
}

pub(super) fn parse_bracketed_system_line(line: &str) -> Option<(String, String)> {
    if !line.starts_with('[') {
        return None;
    }

    let end = line.find(']')?;
    let raw_tag = line.get(1..end)?.trim();
    let sender = raw_tag.split(':').next().unwrap_or("sys").trim();
    let sender = if sender.is_empty() { "sys" } else { sender };

    let payload = line.get(end + 1..).unwrap_or_default().trim();
    let text = if payload.is_empty() {
        line.to_string()
    } else {
        payload.to_string()
    };

    Some((sender.to_string(), text))
}

pub(super) fn parse_trust_login(line: &str) -> Option<String> {
    if !line.starts_with("[trust] state=") {
        return None;
    }

    let login_key = " login=";
    let start = line.find(login_key)? + login_key.len();
    let value = line[start..].split_whitespace().next()?;
    if value.is_empty() {
        return None;
    }

    Some(value.to_string())
}

pub(super) fn is_outgoing_sender(sender: &str) -> bool {
    sender.eq_ignore_ascii_case("you") || sender.eq_ignore_ascii_case("me")
}

pub(super) fn normalize_sender(sender: &str) -> String {
    sender.trim().trim_end_matches('>').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sender_line_recognizes_chat_labels_only() {
        assert_eq!(
            parse_sender_line("@mike> hello"),
            Some(("@mike".to_string(), "hello"))
        );
        assert!(parse_sender_line("[ready:cli-1] server_time=1").is_none());
    }

    #[test]
    fn parse_bracketed_system_line_extracts_tag_and_payload() {
        assert_eq!(
            parse_bracketed_system_line("[trust] state=verified fp=123"),
            Some(("trust".to_string(), "state=verified fp=123".to_string()))
        );
        assert_eq!(
            parse_bracketed_system_line("[e2e:cli-4] handshake.init.recv"),
            Some(("e2e".to_string(), "handshake.init.recv".to_string()))
        );
    }

    #[test]
    fn parse_trust_login_extracts_login() {
        assert_eq!(
            parse_trust_login("[trust] state=verified login=@mike fp=abc"),
            Some("@mike".to_string())
        );
        assert!(parse_trust_login("[trust] state=verified fp=abc").is_none());
    }
}
