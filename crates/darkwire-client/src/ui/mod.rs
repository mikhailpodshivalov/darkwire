mod line_parse;
mod render;
mod style;
mod text;

use crate::commands::command_palette_items;
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine as _};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    queue,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use std::{
    collections::VecDeque,
    io::{self, Write},
    process::{Command, Stdio},
};

pub(super) const MAX_HISTORY_LINES: usize = 600;
pub(super) const MAX_COMMAND_MENU_ITEMS: usize = 4;
pub(super) const MIN_TERMINAL_WIDTH: usize = 28;
pub(super) const MIN_TERMINAL_HEIGHT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChatLineKind {
    Incoming,
    Outgoing,
    System,
    Error,
}

#[derive(Debug, Clone)]
pub(super) struct ChatLine {
    pub(super) timestamp: String,
    pub(super) sender: String,
    pub(super) text: String,
    pub(super) kind: ChatLineKind,
}

#[derive(Debug)]
pub struct TerminalUi {
    interactive: bool,
    theme: style::UiTheme,
    show_details: bool,
    input_buffer: String,
    command_matches: Vec<&'static str>,
    command_selected: usize,
    history: VecDeque<ChatLine>,
    active_peer: Option<String>,
}

impl TerminalUi {
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            theme: style::UiTheme::default(),
            show_details: false,
            input_buffer: String::new(),
            command_matches: Vec::new(),
            command_selected: 0,
            history: VecDeque::with_capacity(256),
            active_peer: None,
        }
    }

    pub fn toggle_details(&mut self) -> bool {
        self.show_details = !self.show_details;
        if self.interactive {
            self.render();
        }
        self.show_details
    }

    pub fn print_line(&mut self, line: &str) {
        if self.interactive {
            self.track_context_from_line(line);
            if let Some(display_line) = display_line_for_mode(line, false, self.show_details) {
                self.push_history_line(&display_line, false);
            }
            self.render();
            return;
        }

        println!("{line}");
    }

    pub fn print_error(&mut self, line: &str) {
        if self.interactive {
            self.track_context_from_line(line);
            if let Some(display_line) = display_line_for_mode(line, true, self.show_details) {
                self.push_history_line(&display_line, true);
            }
            self.render();
            return;
        }

        eprintln!("{line}");
    }

    pub fn redraw_prompt(&mut self) {
        if !self.interactive {
            return;
        }

        self.render();
    }

    pub fn clear_line(&mut self) {
        if !self.interactive {
            return;
        }

        let _ = clear_screen_and_show_cursor();
    }

    pub fn copy_to_clipboard(&mut self, text: &str) -> io::Result<()> {
        if copy_to_clipboard_with_system_command(text).is_ok() {
            if self.interactive {
                self.render();
            }
            return Ok(());
        }

        let osc52_result = copy_to_clipboard_with_osc52(text);
        if self.interactive {
            self.render();
        }
        match osc52_result {
            Ok(()) => Err(io::Error::new(
                io::ErrorKind::Other,
                "system clipboard command unavailable; terminal OSC52 copy attempted (paste may be blocked)",
            )),
            Err(err) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "clipboard command unavailable and OSC52 failed: {err}",
                ),
            )),
        }
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) -> Option<String> {
        if key.kind == KeyEventKind::Release {
            return None;
        }

        match key.code {
            KeyCode::Enter => {
                if self.consume_enter_for_command_menu() {
                    return None;
                }

                let submitted = std::mem::take(&mut self.input_buffer);
                self.update_command_matches();
                self.render();
                Some(submitted)
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
                self.update_command_matches();
                self.render();
                None
            }
            KeyCode::Up => {
                if self.command_menu_visible() {
                    if self.command_selected == 0 {
                        self.command_selected = self.command_matches.len().saturating_sub(1);
                    } else {
                        self.command_selected -= 1;
                    }
                    self.render();
                }
                None
            }
            KeyCode::Down => {
                if self.command_menu_visible() {
                    self.command_selected =
                        (self.command_selected + 1) % self.command_matches.len();
                    self.render();
                }
                None
            }
            KeyCode::Esc => {
                if self.command_menu_visible() {
                    self.command_matches.clear();
                    self.command_selected = 0;
                    self.render();
                }
                None
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Some("/q".to_string())
            }
            KeyCode::Char(ch) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    return None;
                }

                self.input_buffer.push(ch);
                self.update_command_matches();
                self.render();
                None
            }
            _ => None,
        }
    }

    pub fn handle_paste(&mut self, text: &str) {
        for ch in text.chars() {
            if ch == '\r' || ch == '\n' || ch.is_control() {
                continue;
            }
            self.input_buffer.push(ch);
        }

        self.update_command_matches();
        if self.interactive {
            self.render();
        }
    }

    fn command_menu_visible(&self) -> bool {
        !self.command_matches.is_empty()
    }

    fn update_command_matches(&mut self) {
        if !self.input_buffer.starts_with('/') {
            self.command_matches.clear();
            self.command_selected = 0;
            return;
        }

        let query = self.input_buffer.to_ascii_lowercase();
        self.command_matches = command_palette_items()
            .iter()
            .copied()
            .filter(|command| command.to_ascii_lowercase().starts_with(&query))
            .collect();

        if self.command_matches.is_empty() || self.command_selected >= self.command_matches.len() {
            self.command_selected = 0;
        }
    }

    fn consume_enter_for_command_menu(&mut self) -> bool {
        if !self.command_menu_visible() {
            return false;
        }

        let selected = self.command_matches[self.command_selected];
        if self.input_buffer == selected {
            // For templates requiring args (trailing space), do not submit yet.
            return selected.ends_with(' ');
        }

        self.input_buffer = selected.to_string();
        self.update_command_matches();
        self.render();
        true
    }

    fn track_context_from_line(&mut self, line: &str) {
        if line.starts_with("[session:") && line.contains("ended") {
            self.active_peer = None;
            return;
        }

        if let Some(login) = line_parse::parse_trust_login(line) {
            self.active_peer = Some(login);
            return;
        }

        if let Some((sender, _)) = line_parse::parse_sender_line(line) {
            let sender = line_parse::normalize_sender(&sender);
            if !line_parse::is_outgoing_sender(&sender) {
                self.active_peer = Some(normalize_peer_display_name(&sender));
            }
        }
    }

    fn push_history_line(&mut self, line: &str, is_error: bool) {
        let timestamp = text::hhmm_utc();

        let entry = if let Some((sender, text)) = line_parse::parse_sender_line(line) {
            let sender = line_parse::normalize_sender(&sender);
            let kind = if line_parse::is_outgoing_sender(&sender) {
                ChatLineKind::Outgoing
            } else {
                ChatLineKind::Incoming
            };
            ChatLine {
                timestamp,
                sender: normalize_peer_display_name(&sender),
                text: text.to_string(),
                kind,
            }
        } else if let Some((sender, text)) = line_parse::parse_bracketed_system_line(line) {
            ChatLine {
                timestamp,
                sender,
                text,
                kind: if is_error {
                    ChatLineKind::Error
                } else {
                    ChatLineKind::System
                },
            }
        } else {
            ChatLine {
                timestamp,
                sender: if is_error {
                    "err".to_string()
                } else {
                    "sys".to_string()
                },
                text: line.to_string(),
                kind: if is_error {
                    ChatLineKind::Error
                } else {
                    ChatLineKind::System
                },
            }
        };

        if self.history.len() >= MAX_HISTORY_LINES {
            let _ = self.history.pop_front();
        }
        self.history.push_back(entry);
    }
}

fn display_line_for_mode(line: &str, is_error: bool, show_details: bool) -> Option<String> {
    if is_error || show_details {
        return Some(line.to_string());
    }

    let Some((sender, payload)) = line_parse::parse_bracketed_system_line(line) else {
        return Some(line.to_string());
    };

    match sender.as_str() {
        "ready" | "keys" | "resume" => None,
        "invite" => sanitize_invite_line(&payload),
        "session" => Some(sanitize_session_line(&payload)),
        "e2e" => sanitize_e2e_line(&payload),
        "trust" => sanitize_trust_line(&payload),
        "login" => Some(sanitize_login_line(&payload)),
        _ => Some(line.to_string()),
    }
}

fn sanitize_invite_line(payload: &str) -> Option<String> {
    if payload.starts_with("DL1:") {
        return Some("[invite] new invite ready (use /my invite copy)".to_string());
    }

    if payload.is_empty() {
        return None;
    }

    Some(format!("[invite] {payload}"))
}

fn sanitize_session_line(payload: &str) -> String {
    if payload.starts_with("started id=") {
        return "[session] started".to_string();
    }

    if payload.starts_with("ended reason=") {
        return format!("[session] {payload}");
    }

    format!("[session] {payload}")
}

fn sanitize_e2e_line(payload: &str) -> Option<String> {
    if payload.starts_with("secure session established") {
        return Some("[e2e] secure session established".to_string());
    }

    if payload.starts_with("secure session resumed") {
        return Some("[e2e] secure session resumed".to_string());
    }

    if payload.starts_with("resume unavailable, requesting prekey bundle for recovery") {
        return Some("[e2e] attempting secure recovery".to_string());
    }

    None
}

fn sanitize_trust_line(payload: &str) -> Option<String> {
    if payload.starts_with("verified_contacts=") {
        return None;
    }

    if let Some(rest) = payload.strip_prefix("state=") {
        let state = rest.split_whitespace().next().unwrap_or("unknown");
        return Some(format!("[trust] state={state}"));
    }

    if payload.is_empty() {
        return None;
    }

    Some(format!("[trust] {payload}"))
}

fn sanitize_login_line(payload: &str) -> String {
    if let Some((prefix, _)) = payload.split_once(" fp=") {
        return format!("[login] {prefix}");
    }

    format!("[login] {payload}")
}

fn copy_to_clipboard_with_osc52(text: &str) -> io::Result<()> {
    let encoded = BASE64_STD.encode(text.as_bytes());
    let mut stdout = io::stdout();
    write!(stdout, "\x1b]52;c;{encoded}\x07")?;
    stdout.flush()
}

fn copy_to_clipboard_with_system_command(text: &str) -> io::Result<()> {
    let mut last_error: Option<io::Error> = None;

    for (program, args) in clipboard_command_candidates() {
        match run_clipboard_command(program, args, text) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no clipboard command available")
    }))
}

fn run_clipboard_command(program: &str, args: &[&str], text: &str) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(text.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let message = if stderr.is_empty() {
        format!("{program} exited with status {}", output.status)
    } else {
        format!("{program}: {stderr}")
    };
    Err(io::Error::new(io::ErrorKind::Other, message))
}

#[cfg(target_os = "macos")]
fn clipboard_command_candidates() -> &'static [(&'static str, &'static [&'static str])] {
    &[("pbcopy", &[])]
}

#[cfg(target_os = "windows")]
fn clipboard_command_candidates() -> &'static [(&'static str, &'static [&'static str])] {
    &[
        ("clip.exe", &[]),
        ("powershell", &["-NoProfile", "-Command", "Set-Clipboard"]),
    ]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn clipboard_command_candidates() -> &'static [(&'static str, &'static [&'static str])] {
    &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ]
}

fn normalize_peer_display_name(sender: &str) -> String {
    let trimmed = sender.trim();
    if trimmed.starts_with("fp:") {
        return "peer".to_string();
    }
    trimmed.to_string()
}

pub struct RawModeGuard;

impl RawModeGuard {
    pub fn activate(enabled: bool) -> io::Result<Option<Self>> {
        if !enabled {
            return Ok(None);
        }

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        queue!(stdout, Hide)?;
        stdout.flush()?;
        Ok(Some(Self))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = clear_screen_and_show_cursor();
    }
}

fn clear_screen_and_show_cursor() -> io::Result<()> {
    let mut stdout = io::stdout();
    queue!(stdout, MoveTo(0, 0), Clear(ClearType::All), Show)?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn terminal_ui_enter_submits_buffer_without_losing_text() {
        let mut ui = TerminalUi::new(false);

        assert_eq!(
            ui.handle_key_event(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE)),
            None
        );
        assert_eq!(
            ui.handle_key_event(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE)),
            None
        );

        let submitted = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(submitted.as_deref(), Some("hi"));
        assert!(ui.input_buffer.is_empty());
    }

    #[test]
    fn terminal_ui_backspace_edits_buffer() {
        let mut ui = TerminalUi::new(false);
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));

        let submitted = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(submitted.as_deref(), Some("a"));
    }

    #[test]
    fn terminal_ui_paste_appends_text_without_newlines() {
        let mut ui = TerminalUi::new(false);
        ui.handle_paste("ab\ncd\r\nef");
        let submitted = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(submitted.as_deref(), Some("abcdef"));
    }

    #[test]
    fn slash_menu_opens_and_closes_when_slash_deleted() {
        let mut ui = TerminalUi::new(false);
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(ui.command_menu_visible());
        assert!(!ui.command_matches.is_empty());

        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(!ui.command_menu_visible());
        assert!(ui.command_matches.is_empty());
    }

    #[test]
    fn slash_menu_enter_autofills_then_submits_command() {
        let mut ui = TerminalUi::new(false);
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));

        let first_enter = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(first_enter.is_none());
        assert_eq!(ui.input_buffer, "/help");

        let second_enter = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(second_enter.as_deref(), Some("/help"));
    }

    #[test]
    fn slash_menu_allows_arrow_selection() {
        let mut ui = TerminalUi::new(false);
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));

        let enter = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(enter.is_none());
        assert_eq!(ui.input_buffer, "/my invite copy");
    }

    #[test]
    fn slash_menu_argument_template_waits_for_argument() {
        let mut ui = TerminalUi::new(false);
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));

        let first_enter = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(first_enter.is_none());
        assert_eq!(ui.input_buffer, "/invite ");

        let second_enter = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(second_enter.is_none());

        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
        let submitted = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(submitted.as_deref(), Some("/invite X"));
    }

    #[test]
    fn normalize_peer_display_name_hides_fingerprint_label() {
        assert_eq!(normalize_peer_display_name("fp:123456"), "peer");
        assert_eq!(normalize_peer_display_name("@mike"), "@mike");
    }

    #[test]
    fn clean_mode_hides_noisy_system_lines() {
        assert_eq!(
            display_line_for_mode("[ready:cli-1] server_time=1", false, false),
            None
        );
        assert_eq!(
            display_line_for_mode("[keys:cli-2] published spk_id=1 opk_count=64", false, false),
            None
        );
        assert_eq!(
            display_line_for_mode("[e2e:cli-3] handshake.init.recv session_id=1", false, false),
            None
        );
    }

    #[test]
    fn clean_mode_keeps_important_events_with_compact_text() {
        assert_eq!(
            display_line_for_mode(
                "[e2e] secure session established role=initiator session=abc",
                false,
                false
            )
            .as_deref(),
            Some("[e2e] secure session established")
        );
        assert_eq!(
            display_line_for_mode("[session:cli-4] started id=abc", false, false).as_deref(),
            Some("[session] started")
        );
        assert_eq!(
            display_line_for_mode("[invite:cli-5] DL1:abc.def", false, false).as_deref(),
            Some("[invite] new invite ready (use /my invite copy)")
        );
        assert_eq!(
            display_line_for_mode("[invite] code DL1:abc.def", false, false).as_deref(),
            Some("[invite] code DL1:abc.def")
        );
    }

    #[test]
    fn details_mode_preserves_original_lines() {
        let line = "[e2e:cli-4] handshake.init.recv session_id=1";
        assert_eq!(
            display_line_for_mode(line, false, true).as_deref(),
            Some(line)
        );
    }

    #[test]
    fn toggle_details_flips_state() {
        let mut ui = TerminalUi::new(false);
        assert!(ui.toggle_details());
        assert!(!ui.toggle_details());
    }
}
