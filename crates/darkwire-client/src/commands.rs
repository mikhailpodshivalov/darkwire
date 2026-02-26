#[derive(Debug, PartialEq, Eq)]
pub enum UserCommand {
    Help,
    HelpAll,
    CreateInvite,
    CreateInviteAndCopy,
    CopyLastInvite,
    ConnectInvite(String),
    SetUsername(String),
    AcceptKey,
    KeyStatus,
    KeyRotate,
    KeyRefill,
    KeyRevoke,
    TrustStatus,
    TrustVerify,
    TrustUnverify,
    TrustList,
    LoginStatus,
    LoginLookup(String),
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

    if trimmed.starts_with("/help") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let arg = parts.next();
        let extra = parts.next();

        if command == Some("/help") && extra.is_none() {
            if arg.is_none() {
                return UserCommand::Help;
            }
            if arg == Some("all") {
                return UserCommand::HelpAll;
            }
        }
    }

    if trimmed.starts_with("/my") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let scope = parts.next();
        let action = parts.next();
        let extra = parts.next();
        if command == Some("/my")
            && scope == Some("invite")
            && action == Some("copy")
            && extra.is_none()
        {
            return UserCommand::CreateInviteAndCopy;
        }
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

    if trimmed.starts_with("/login ") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let login = parts.next();
        let extra = parts.next();
        if command == Some("/login")
            && extra.is_none()
            && matches!(login, Some(value) if value.starts_with('@'))
        {
            return UserCommand::SetUsername(login.unwrap_or_default().to_string());
        }
    }

    if trimmed == "/new" || trimmed == "/i" {
        return UserCommand::CreateInvite;
    }

    if trimmed == "/new copy" || trimmed == "/i copy" {
        return UserCommand::CreateInviteAndCopy;
    }

    if trimmed == "/copy" || trimmed == "/copy invite" {
        return UserCommand::CopyLastInvite;
    }

    if trimmed == "/q" {
        return UserCommand::Quit;
    }

    if trimmed == "/accept-key" {
        return UserCommand::AcceptKey;
    }

    if trimmed.starts_with("/me") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let username = parts.next();
        let extra = parts.next();

        if command == Some("/me") && extra.is_none() {
            if let Some(username) = username {
                return UserCommand::SetUsername(username.to_string());
            }
        }

        if trimmed.starts_with("/me@") && trimmed.len() > 4 {
            return UserCommand::SetUsername(format!("@{}", &trimmed[4..]));
        }
    }

    if trimmed == "/keys" {
        return UserCommand::KeyStatus;
    }

    if trimmed == "/keys rotate" {
        return UserCommand::KeyRotate;
    }

    if trimmed == "/keys refill" {
        return UserCommand::KeyRefill;
    }

    if trimmed == "/keys revoke" {
        return UserCommand::KeyRevoke;
    }

    if trimmed == "/trust" {
        return UserCommand::TrustStatus;
    }

    if trimmed == "/trust verify" {
        return UserCommand::TrustVerify;
    }

    if trimmed == "/trust unverify" {
        return UserCommand::TrustUnverify;
    }

    if trimmed == "/trust list" {
        return UserCommand::TrustList;
    }

    if trimmed.starts_with("/login") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let action = parts.next();
        let value = parts.next();
        let extra = parts.next();

        if command == Some("/login") && extra.is_none() {
            match (action, value) {
                (None, None) => return UserCommand::LoginStatus,
                (Some("set"), Some(login)) => {
                    return UserCommand::SetUsername(login.to_string());
                }
                (Some("lookup"), Some(login)) => {
                    return UserCommand::LoginLookup(login.to_string());
                }
                (Some(compact), None) if compact.starts_with("set@") && compact.len() > 4 => {
                    return UserCommand::SetUsername(format!("@{}", &compact[4..]));
                }
                (Some(compact), None) if compact.starts_with("lookup@") && compact.len() > 7 => {
                    return UserCommand::LoginLookup(format!("@{}", &compact[7..]));
                }
                _ => {}
            }
        }
    }

    if trimmed.starts_with("/c") {
        let mut parts = trimmed.split_whitespace();
        let command = parts.next();
        let invite = parts.next();

        if command == Some("/c") {
            if let Some(invite) = invite {
                return UserCommand::ConnectInvite(invite.to_string());
            }
            return UserCommand::Unknown;
        }
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
        "/login @name - set or change your username",
        "/accept-key - accept peer key change and continue",
        "/trust - show active peer trust status",
        "/q - quit",
        "<text> - send encrypted message in active secure session",
    ]
}

pub fn command_help_all_lines() -> &'static [&'static str] {
    command_help_basic_lines()
}

pub fn command_palette_items() -> &'static [&'static str] {
    &[
        "/help",
        "/my invite copy",
        "/invite ",
        "/login @",
        "/trust",
        "/accept-key",
        "/q",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_invite_create() {
        assert_eq!(parse_user_command("/new"), UserCommand::CreateInvite);
    }

    #[test]
    fn parse_command_invite_create_and_copy() {
        assert_eq!(
            parse_user_command("/new copy"),
            UserCommand::CreateInviteAndCopy
        );
    }

    #[test]
    fn parse_command_invite_create_and_copy_new_name() {
        assert_eq!(
            parse_user_command("/my invite copy"),
            UserCommand::CreateInviteAndCopy
        );
    }

    #[test]
    fn parse_command_help() {
        assert_eq!(parse_user_command("/help"), UserCommand::Help);
    }

    #[test]
    fn parse_command_help_all() {
        assert_eq!(parse_user_command("/help all"), UserCommand::HelpAll);
    }

    #[test]
    fn parse_command_invite_create_legacy_alias() {
        assert_eq!(parse_user_command("/i"), UserCommand::CreateInvite);
    }

    #[test]
    fn parse_command_invite_create_and_copy_legacy_alias() {
        assert_eq!(
            parse_user_command("/i copy"),
            UserCommand::CreateInviteAndCopy
        );
    }

    #[test]
    fn parse_command_copy_last_invite() {
        assert_eq!(parse_user_command("/copy"), UserCommand::CopyLastInvite);
        assert_eq!(
            parse_user_command("/copy invite"),
            UserCommand::CopyLastInvite
        );
    }

    #[test]
    fn parse_command_invite_connect() {
        assert_eq!(
            parse_user_command("/c DL1:abc.def"),
            UserCommand::ConnectInvite("DL1:abc.def".to_string())
        );
    }

    #[test]
    fn parse_command_invite_connect_new_name() {
        assert_eq!(
            parse_user_command("/invite DL1:abc.def"),
            UserCommand::ConnectInvite("DL1:abc.def".to_string())
        );
    }

    #[test]
    fn parse_command_quit() {
        assert_eq!(parse_user_command("/q"), UserCommand::Quit);
    }

    #[test]
    fn parse_command_message() {
        assert_eq!(
            parse_user_command("hello"),
            UserCommand::SendMessage("hello".to_string())
        );
    }

    #[test]
    fn parse_command_unknown_for_bad_connect() {
        assert_eq!(parse_user_command("/c"), UserCommand::Unknown);
    }

    #[test]
    fn parse_command_key_status() {
        assert_eq!(parse_user_command("/keys"), UserCommand::KeyStatus);
    }

    #[test]
    fn parse_command_key_rotate() {
        assert_eq!(parse_user_command("/keys rotate"), UserCommand::KeyRotate);
    }

    #[test]
    fn parse_command_key_refill() {
        assert_eq!(parse_user_command("/keys refill"), UserCommand::KeyRefill);
    }

    #[test]
    fn parse_command_key_revoke() {
        assert_eq!(parse_user_command("/keys revoke"), UserCommand::KeyRevoke);
    }

    #[test]
    fn parse_command_set_username() {
        assert_eq!(
            parse_user_command("/me @mike"),
            UserCommand::SetUsername("@mike".to_string())
        );
    }

    #[test]
    fn parse_command_set_username_new_name() {
        assert_eq!(
            parse_user_command("/login @mike"),
            UserCommand::SetUsername("@mike".to_string())
        );
    }

    #[test]
    fn parse_command_set_username_compact() {
        assert_eq!(
            parse_user_command("/me@mike"),
            UserCommand::SetUsername("@mike".to_string())
        );
    }

    #[test]
    fn parse_command_accept_key() {
        assert_eq!(parse_user_command("/accept-key"), UserCommand::AcceptKey);
    }

    #[test]
    fn parse_command_trust_status() {
        assert_eq!(parse_user_command("/trust"), UserCommand::TrustStatus);
    }

    #[test]
    fn parse_command_trust_verify() {
        assert_eq!(
            parse_user_command("/trust verify"),
            UserCommand::TrustVerify
        );
    }

    #[test]
    fn parse_command_trust_unverify() {
        assert_eq!(
            parse_user_command("/trust unverify"),
            UserCommand::TrustUnverify
        );
    }

    #[test]
    fn parse_command_trust_list() {
        assert_eq!(parse_user_command("/trust list"), UserCommand::TrustList);
    }

    #[test]
    fn parse_command_login_status() {
        assert_eq!(parse_user_command("/login"), UserCommand::LoginStatus);
    }

    #[test]
    fn parse_command_login_set() {
        assert_eq!(
            parse_user_command("/login set @mike"),
            UserCommand::SetUsername("@mike".to_string())
        );
    }

    #[test]
    fn parse_command_login_lookup() {
        assert_eq!(
            parse_user_command("/login lookup mike"),
            UserCommand::LoginLookup("mike".to_string())
        );
    }

    #[test]
    fn parse_command_login_set_compact() {
        assert_eq!(
            parse_user_command("/login set@mike"),
            UserCommand::SetUsername("@mike".to_string())
        );
    }

    #[test]
    fn parse_command_login_lookup_compact() {
        assert_eq!(
            parse_user_command("/login lookup@mike"),
            UserCommand::LoginLookup("@mike".to_string())
        );
    }

    #[test]
    fn basic_help_lines_hide_advanced_commands() {
        let help = command_help_basic_lines().join("\n");
        assert!(!help.contains("/keys rotate"));
        assert!(!help.contains("/trust verify"));
    }

    #[test]
    fn all_help_lines_include_advanced_commands() {
        let help = command_help_all_lines().join("\n");
        assert!(help.contains("/my invite copy"));
        assert!(help.contains("/invite CODE"));
        assert!(help.contains("/login @name"));
        assert!(help.contains("/accept-key"));
        assert!(!help.contains("/keys rotate"));
        assert!(!help.contains("/trust verify"));
    }

    #[test]
    fn command_palette_includes_common_entries() {
        let entries = command_palette_items();
        assert!(entries.contains(&"/help"));
        assert!(entries.contains(&"/my invite copy"));
        assert!(entries.contains(&"/invite "));
        assert!(entries.contains(&"/login @"));
        assert!(entries.contains(&"/q"));
    }
}
