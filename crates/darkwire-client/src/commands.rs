#[derive(Debug, PartialEq, Eq)]
pub enum UserCommand {
    Help,
    CreateInviteAndCopy,
    ConnectInvite(String),
    SetUsername(String),
    AcceptKey,
    TrustStatus,
    ToggleDetails,
    Quit,
    SendMessage(String),
    Ignore,
    Unknown,
}

pub fn parse_user_command(line: &str) -> UserCommand {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return UserCommand::Ignore;
    }

    if trimmed == "/help" {
        return UserCommand::Help;
    }

    if trimmed == "/my invite copy" {
        return UserCommand::CreateInviteAndCopy;
    }

    if trimmed.starts_with("/invite") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let invite = parts.next();
        let extra = parts.next();
        if command == Some("/invite") && extra.is_none() {
            if let Some(invite) = invite {
                return UserCommand::ConnectInvite(invite.to_string());
            }
            return UserCommand::Unknown;
        }
    }

    if trimmed.starts_with("/login") {
        let mut parts = trimmed.split_whitespace();
        let login_command = parts.next();
        let login_value = parts.next();
        let extra = parts.next();
        if login_command == Some("/login")
            && matches!(login_value, Some(value) if value.starts_with('@'))
            && extra.is_none()
        {
            return UserCommand::SetUsername(login_value.unwrap_or_default().to_string());
        }
    }

    if trimmed == "/trust" {
        return UserCommand::TrustStatus;
    }

    if trimmed == "/details" || trimmed == "+" {
        return UserCommand::ToggleDetails;
    }

    if trimmed == "/accept-key" {
        return UserCommand::AcceptKey;
    }

    if trimmed == "/q" {
        return UserCommand::Quit;
    }

    if trimmed.starts_with('/') {
        return UserCommand::Unknown;
    }

    UserCommand::SendMessage(line.to_string())
}

pub fn command_help_basic_lines() -> &'static [&'static str] {
    &[
        "/help - show commands",
        "/my invite copy - create invite and copy to clipboard",
        "/invite CODE - connect by invite code",
        "/accept-key - accept peer key change and continue",
        "/login @name - set or change your username",
        "/trust - show active peer trust status",
        "/details (+) - toggle verbose system diagnostics",
        "/q - quit",
        "<text> - send encrypted message in active secure session",
    ]
}

pub fn command_palette_items() -> &'static [&'static str] {
    &[
        "/help",
        "/my invite copy",
        "/invite ",
        "/accept-key",
        "/login @",
        "/trust",
        "/details",
        "/q",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_help() {
        assert_eq!(parse_user_command("/help"), UserCommand::Help);
    }

    #[test]
    fn parse_command_my_invite_copy() {
        assert_eq!(
            parse_user_command("/my invite copy"),
            UserCommand::CreateInviteAndCopy
        );
    }

    #[test]
    fn parse_command_invite_connect() {
        assert_eq!(
            parse_user_command("/invite DL1:abc.def"),
            UserCommand::ConnectInvite("DL1:abc.def".to_string())
        );
    }

    #[test]
    fn parse_command_login() {
        assert_eq!(
            parse_user_command("/login @mike"),
            UserCommand::SetUsername("@mike".to_string())
        );
    }

    #[test]
    fn parse_command_trust() {
        assert_eq!(parse_user_command("/trust"), UserCommand::TrustStatus);
    }

    #[test]
    fn parse_command_accept_key() {
        assert_eq!(parse_user_command("/accept-key"), UserCommand::AcceptKey);
    }

    #[test]
    fn parse_command_quit() {
        assert_eq!(parse_user_command("/q"), UserCommand::Quit);
    }

    #[test]
    fn parse_command_toggle_details() {
        assert_eq!(parse_user_command("/details"), UserCommand::ToggleDetails);
        assert_eq!(parse_user_command("+"), UserCommand::ToggleDetails);
    }

    #[test]
    fn parse_command_message() {
        assert_eq!(
            parse_user_command("hello"),
            UserCommand::SendMessage("hello".to_string())
        );
    }

    #[test]
    fn parse_command_rejects_duplicates_and_legacy_aliases() {
        for line in [
            "/help all",
            "/new",
            "/i",
            "/new copy",
            "/i copy",
            "/copy",
            "/copy invite",
            "/c DL1:abc.def",
            "/me @mike",
            "/me@mike",
            "/keys",
            "/keys rotate",
            "/keys refill",
            "/keys revoke",
            "/trust verify",
            "/trust unverify",
            "/trust list",
            "/login",
            "/login set @mike",
            "/login lookup @mike",
            "/login lookup@mike",
            "/invite",
            "/login mike",
        ] {
            assert_eq!(parse_user_command(line), UserCommand::Unknown, "{line}");
        }
    }

    #[test]
    fn help_lines_match_simple_surface() {
        let help = command_help_basic_lines().join("\n");
        assert!(help.contains("/my invite copy"));
        assert!(help.contains("/invite CODE"));
        assert!(help.contains("/login @name"));
        assert!(help.contains("/trust"));
        assert!(help.contains("/accept-key"));
        assert!(help.contains("/details (+)"));
        assert!(help.contains("/q"));
        assert!(!help.contains("/keys rotate"));
        assert!(!help.contains("/trust verify"));
        assert!(!help.contains("/help all"));
    }

    #[test]
    fn command_palette_contains_only_primary_commands() {
        let entries = command_palette_items();
        assert_eq!(
            entries,
            &[
                "/help",
                "/my invite copy",
                "/invite ",
                "/accept-key",
                "/login @",
                "/trust",
                "/details",
                "/q",
            ]
        );
    }
}
