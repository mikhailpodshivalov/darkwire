#[derive(Debug, PartialEq, Eq)]
pub enum UserCommand {
    Help,
    HelpAll,
    CreateInvite,
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

    if trimmed == "/new" || trimmed == "/i" {
        return UserCommand::CreateInvite;
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
        "/help - show basic help",
        "/help all - show full command list",
        "/new (/i) - create new invite",
        "/c CODE - connect by invite code",
        "/me @name - set or change your username",
        "/accept-key - accept peer key change and continue",
        "/q - quit",
        "<text> - send encrypted message in active secure session",
    ]
}

pub fn command_help_all_lines() -> &'static [&'static str] {
    &[
        "/help - show basic help",
        "/help all - show full command list",
        "/new (/i) - create new invite",
        "/c CODE - connect by invite code",
        "/me @name - set or change your username",
        "/accept-key - accept peer key change and continue",
        "/keys - show local key status",
        "/keys rotate - rotate signed prekey",
        "/keys refill - refill one-time prekeys",
        "/keys revoke - regenerate identity + prekeys",
        "/trust - show active peer trust status",
        "/trust verify - mark active peer as verified",
        "/trust unverify - remove verification for active peer",
        "/trust list - list verified peers",
        "/login - show local login binding status",
        "/login set @name - bind login to local identity key",
        "/login lookup @name - resolve login to identity fingerprint",
        "/q - quit",
        "<text> - send encrypted message in active secure session",
    ]
}

pub fn command_palette_items() -> &'static [&'static str] {
    &[
        "/help",
        "/help all",
        "/new",
        "/i",
        "/c ",
        "/me @",
        "/accept-key",
        "/keys",
        "/keys rotate",
        "/keys refill",
        "/keys revoke",
        "/trust",
        "/trust verify",
        "/trust unverify",
        "/trust list",
        "/login",
        "/login lookup ",
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
    fn parse_command_invite_connect() {
        assert_eq!(
            parse_user_command("/c DL1:abc.def"),
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
        assert!(help.contains("/me @name"));
        assert!(help.contains("/accept-key"));
        assert!(help.contains("/keys rotate"));
        assert!(help.contains("/trust verify"));
        assert!(help.contains("/login set @name"));
    }

    #[test]
    fn command_palette_includes_common_entries() {
        let entries = command_palette_items();
        assert!(entries.contains(&"/help"));
        assert!(entries.contains(&"/c "));
        assert!(entries.contains(&"/me @"));
        assert!(entries.contains(&"/q"));
    }
}
