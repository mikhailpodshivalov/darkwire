#[derive(Debug, PartialEq, Eq)]
pub enum UserCommand {
    CreateInvite,
    ConnectInvite(String),
    KeyStatus,
    KeyRotate,
    KeyRefill,
    KeyRevoke,
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

    if trimmed == "/new" || trimmed == "/i" {
        return UserCommand::CreateInvite;
    }

    if trimmed == "/q" {
        return UserCommand::Quit;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_command_invite_create() {
        assert_eq!(parse_user_command("/new"), UserCommand::CreateInvite);
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
}
