use crate::commands::command_palette_items;
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{disable_raw_mode, enable_raw_mode, size, Clear, ClearType},
};
use std::{
    collections::VecDeque,
    io::{self, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_HISTORY_LINES: usize = 600;
const MAX_COMMAND_MENU_ITEMS: usize = 4;
const MIN_TERMINAL_WIDTH: usize = 28;
const MIN_TERMINAL_HEIGHT: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatLineKind {
    Incoming,
    Outgoing,
    System,
    Error,
}

#[derive(Debug, Clone)]
struct ChatLine {
    timestamp: String,
    sender: String,
    text: String,
    kind: ChatLineKind,
}

#[derive(Debug)]
pub struct TerminalUi {
    interactive: bool,
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
            input_buffer: String::new(),
            command_matches: Vec::new(),
            command_selected: 0,
            history: VecDeque::with_capacity(256),
            active_peer: None,
        }
    }

    pub fn print_line(&mut self, line: &str) {
        if self.interactive {
            self.track_context_from_line(line, false);
            self.push_history_line(line, false);
            self.render();
            return;
        }

        println!("{line}");
    }

    pub fn print_error(&mut self, line: &str) {
        if self.interactive {
            self.track_context_from_line(line, true);
            self.push_history_line(line, true);
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

    fn track_context_from_line(&mut self, line: &str, _is_error: bool) {
        if line.starts_with("[session:") && line.contains("ended") {
            self.active_peer = None;
            return;
        }

        if let Some(login) = parse_trust_login(line) {
            self.active_peer = Some(login);
            return;
        }

        if let Some((sender, _)) = parse_sender_line(line) {
            let sender = normalize_sender(&sender);
            if !is_outgoing_sender(&sender) {
                self.active_peer = Some(sender);
            }
        }
    }

    fn push_history_line(&mut self, line: &str, is_error: bool) {
        let timestamp = hhmm_utc();

        let entry = if let Some((sender, text)) = parse_sender_line(line) {
            let sender = normalize_sender(&sender);
            let kind = if is_outgoing_sender(&sender) {
                ChatLineKind::Outgoing
            } else {
                ChatLineKind::Incoming
            };
            ChatLine {
                timestamp,
                sender,
                text: text.to_string(),
                kind,
            }
        } else if let Some((sender, text)) = parse_bracketed_system_line(line) {
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

    fn render(&mut self) {
        if !self.interactive {
            return;
        }

        let (cols, rows) = terminal_size();
        if cols < MIN_TERMINAL_WIDTH || rows < MIN_TERMINAL_HEIGHT {
            self.render_compact(cols, rows);
            return;
        }

        let inner = cols.saturating_sub(2);
        let messages_height = rows.saturating_sub(6);

        let mut stdout = io::stdout();
        let _ = queue!(stdout, Hide, MoveTo(0, 0), Clear(ClearType::All));

        let top_border = format!("╔{}╗", "═".repeat(inner));
        let peers_sep = format!("╠{}╣", "═".repeat(inner));
        let input_sep = peers_sep.clone();
        let bottom_border = format!("╚{}╝", "═".repeat(inner));

        let _ = queue!(stdout, MoveTo(0, 0), Print(top_border));
        self.draw_peers_row(&mut stdout, 1, inner);
        let _ = queue!(stdout, MoveTo(0, 2), Print(peers_sep));

        self.draw_message_area(&mut stdout, 3, messages_height, inner);

        let input_sep_y = rows.saturating_sub(3) as u16;
        let input_y = rows.saturating_sub(2) as u16;
        let bottom_y = rows.saturating_sub(1) as u16;

        let _ = queue!(stdout, MoveTo(0, input_sep_y), Print(input_sep));
        self.draw_input_row(&mut stdout, input_y, inner);
        let _ = queue!(stdout, MoveTo(0, bottom_y), Print(bottom_border));

        let input_prefix = " > ";
        let available_input = inner.saturating_sub(input_prefix.chars().count());
        let input_visible = tail_chars(&self.input_buffer, available_input);
        let cursor_x = (1 + input_prefix.chars().count() + input_visible.chars().count()) as u16;
        let _ = queue!(stdout, MoveTo(cursor_x, input_y), Show);
        let _ = stdout.flush();
    }

    fn render_compact(&mut self, cols: usize, rows: usize) {
        let mut stdout = io::stdout();
        let width = cols.max(1);
        let mut cursor_y = 0_u16;
        let input_row = rows.saturating_sub(1);
        let history_capacity = input_row.saturating_sub(1);

        let _ = queue!(stdout, Hide, MoveTo(0, 0), Clear(ClearType::All));

        let peer = self.active_peer.as_deref().unwrap_or("-");
        let peer_line = truncate_with_marker(&format!("peer: {peer}"), width);
        let _ = queue!(stdout, MoveTo(0, 0), Print(peer_line));

        let menu_rows = if self.command_menu_visible() {
            2.min(history_capacity)
        } else {
            0
        };
        let history_rows = history_capacity.saturating_sub(menu_rows);

        let history_lines: Vec<&ChatLine> = self
            .history
            .iter()
            .rev()
            .take(history_rows)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        for (idx, line) in history_lines.iter().enumerate() {
            let y = (1 + idx) as u16;
            let compact = compact_history_row(line, width);
            let _ = queue!(stdout, MoveTo(0, y), Print(compact));
            cursor_y = y;
        }

        if menu_rows > 0 {
            let (start_idx, end_idx) =
                command_menu_window(self.command_matches.len(), self.command_selected, menu_rows);
            let start_y = 1 + history_rows;
            for (idx, command) in self.command_matches[start_idx..end_idx].iter().enumerate() {
                let absolute = start_idx + idx;
                let prefix = if absolute == self.command_selected {
                    "/ "
                } else {
                    "  "
                };
                let line = truncate_with_marker(&format!("{prefix}{command}"), width);
                let y = (start_y + idx) as u16;
                let _ = queue!(stdout, MoveTo(0, y), Print(line));
                cursor_y = y;
            }
        }

        if cursor_y < input_row as u16 {
            for y in (cursor_y as usize + 1)..input_row {
                let _ = queue!(stdout, MoveTo(0, y as u16), Print(" ".repeat(width)));
            }
        }

        let input_visible = tail_chars(&self.input_buffer, width.saturating_sub(2));
        let input_line = format!("> {input_visible}");
        let _ = queue!(
            stdout,
            MoveTo(0, input_row as u16),
            Print(pad_or_trim(&input_line, width)),
            MoveTo(
                input_line.chars().count().min(width) as u16,
                input_row as u16
            ),
            Show
        );
        let _ = stdout.flush();
    }

    fn draw_peers_row(&self, stdout: &mut io::Stdout, y: u16, inner: usize) {
        let _ = queue!(stdout, MoveTo(0, y), Print("║"));

        let prefix = " peers: ";
        let _ = queue!(stdout, Print(prefix));
        let mut used = prefix.chars().count();

        let peer = self.active_peer.as_deref().unwrap_or("-");
        let peer_visible = truncate_chars(peer, inner.saturating_sub(used));
        let color = sender_color(peer);
        if let Some(color) = color {
            let _ = queue!(stdout, SetForegroundColor(color));
        }
        let _ = queue!(stdout, Print(&peer_visible), ResetColor);
        used += peer_visible.chars().count();

        if used < inner {
            let _ = queue!(stdout, Print(" ".repeat(inner - used)));
        }

        let _ = queue!(stdout, Print("║"));
    }

    fn draw_message_area(
        &self,
        stdout: &mut io::Stdout,
        start_y: usize,
        height: usize,
        inner: usize,
    ) {
        let menu_rows = if self.command_menu_visible() {
            MAX_COMMAND_MENU_ITEMS.min(height.saturating_sub(1))
        } else {
            0
        };
        let history_rows = height.saturating_sub(menu_rows);

        let mut y = start_y;

        let lines: Vec<&ChatLine> = self
            .history
            .iter()
            .rev()
            .take(history_rows)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        for line in &lines {
            self.draw_history_row(stdout, y as u16, inner, line);
            y += 1;
        }

        while y < start_y + history_rows {
            self.draw_blank_row(stdout, y as u16, inner);
            y += 1;
        }

        if menu_rows > 0 {
            let (start_idx, end_idx) =
                command_menu_window(self.command_matches.len(), self.command_selected, menu_rows);

            for (idx, command) in self.command_matches[start_idx..end_idx].iter().enumerate() {
                let absolute_idx = start_idx + idx;
                let selected = absolute_idx == self.command_selected;
                self.draw_command_row(stdout, y as u16, inner, command, selected);
                y += 1;
            }

            while y < start_y + height {
                self.draw_blank_row(stdout, y as u16, inner);
                y += 1;
            }
        }
    }

    fn draw_history_row(&self, stdout: &mut io::Stdout, y: u16, inner: usize, line: &ChatLine) {
        let _ = queue!(stdout, MoveTo(0, y), Print("║"));

        // Row shape: " HH:MM sender: message"
        let fixed_cells_without_sender = 1 + 5 + 1 + 2;
        let min_body_width = 8;
        let max_sender = inner.saturating_sub(fixed_cells_without_sender + min_body_width);
        let sender_width = max_sender.clamp(6, 16);
        let header_width = 1 + 5 + 1 + sender_width + 2;
        let body_width = inner.saturating_sub(header_width);

        let mut used = 0;
        let _ = queue!(stdout, Print(" "));
        used += 1;

        let time = pad_or_trim(&line.timestamp, 5);
        let _ = queue!(
            stdout,
            SetForegroundColor(Color::DarkGrey),
            Print(time),
            ResetColor
        );
        used += 5;

        let _ = queue!(stdout, Print(" "));
        used += 1;

        let sender = pad_or_trim(
            &truncate_with_marker(&line.sender, sender_width),
            sender_width,
        );
        match line.kind {
            ChatLineKind::System => {
                if let Some(color) = sender_color(&line.sender) {
                    let _ = queue!(stdout, SetForegroundColor(color));
                } else {
                    let _ = queue!(stdout, SetForegroundColor(Color::DarkGrey));
                }
            }
            ChatLineKind::Error => {
                let _ = queue!(stdout, SetForegroundColor(Color::Red));
            }
            _ => {
                if let Some(color) = sender_color(&line.sender) {
                    let _ = queue!(stdout, SetForegroundColor(color));
                }
            }
        }
        let _ = queue!(stdout, Print(sender), ResetColor);
        used += sender_width;

        let _ = queue!(stdout, Print(": "));
        used += 2;

        let body = truncate_with_marker(&line.text, body_width);
        match line.kind {
            ChatLineKind::Error => {
                let _ = queue!(
                    stdout,
                    SetForegroundColor(Color::Red),
                    Print(&body),
                    ResetColor
                );
            }
            _ => {
                let _ = queue!(stdout, Print(&body));
            }
        }
        used += body.chars().count();

        if used < inner {
            let _ = queue!(stdout, Print(" ".repeat(inner - used)));
        }

        let _ = queue!(stdout, Print("║"));
    }

    fn draw_command_row(
        &self,
        stdout: &mut io::Stdout,
        y: u16,
        inner: usize,
        command: &str,
        selected: bool,
    ) {
        let _ = queue!(stdout, MoveTo(0, y), Print("║"));

        let prefix = if selected { " / " } else { "   " };
        let _ = queue!(stdout, Print(prefix));
        let mut used = prefix.chars().count();

        let available = inner.saturating_sub(used);
        let text = truncate_chars(command, available);

        if selected {
            let _ = queue!(
                stdout,
                SetForegroundColor(Color::Cyan),
                Print(text),
                ResetColor
            );
        } else {
            let _ = queue!(
                stdout,
                SetForegroundColor(Color::DarkGrey),
                Print(text),
                ResetColor
            );
        }
        used += command.chars().count().min(available);

        if used < inner {
            let _ = queue!(stdout, Print(" ".repeat(inner - used)));
        }

        let _ = queue!(stdout, Print("║"));
    }

    fn draw_input_row(&self, stdout: &mut io::Stdout, y: u16, inner: usize) {
        let _ = queue!(stdout, MoveTo(0, y), Print("║"));

        let prefix = " > ";
        let _ = queue!(stdout, Print(prefix));
        let mut used = prefix.chars().count();

        let available = inner.saturating_sub(used);
        let input_visible = tail_chars(&self.input_buffer, available);
        let _ = queue!(stdout, Print(&input_visible));
        used += input_visible.chars().count();

        if used < inner {
            let _ = queue!(stdout, Print(" ".repeat(inner - used)));
        }

        let _ = queue!(stdout, Print("║"));
    }

    fn draw_blank_row(&self, stdout: &mut io::Stdout, y: u16, inner: usize) {
        let _ = queue!(
            stdout,
            MoveTo(0, y),
            Print("║"),
            Print(" ".repeat(inner)),
            Print("║")
        );
    }
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

fn terminal_size() -> (usize, usize) {
    size()
        .map(|(cols, rows)| (cols as usize, rows as usize))
        .ok()
        .filter(|(cols, rows)| *cols > 0 && *rows > 0)
        .unwrap_or((80, 24))
}

fn parse_sender_line(line: &str) -> Option<(String, &str)> {
    if line.starts_with('[') {
        return None;
    }

    let (sender, body) = line.split_once("> ")?;
    if sender.is_empty() || sender.contains(' ') {
        return None;
    }

    Some((sender.to_string(), body))
}

fn parse_bracketed_system_line(line: &str) -> Option<(String, String)> {
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

fn parse_trust_login(line: &str) -> Option<String> {
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

fn is_outgoing_sender(sender: &str) -> bool {
    sender.eq_ignore_ascii_case("you") || sender.eq_ignore_ascii_case("me")
}

fn normalize_sender(sender: &str) -> String {
    sender.trim().trim_end_matches('>').to_string()
}

fn sender_color(sender: &str) -> Option<Color> {
    let normalized = sender.trim().trim_start_matches('@').to_ascii_lowercase();
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

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let mut out = String::with_capacity(input.len().min(max_chars));
    for ch in input.chars().take(max_chars) {
        out.push(ch);
    }
    out
}

fn truncate_with_marker(input: &str, max_chars: usize) -> String {
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

fn tail_chars(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let count = input.chars().count();
    if count <= max_chars {
        return input.to_string();
    }

    input.chars().skip(count - max_chars).collect()
}

fn pad_or_trim(input: &str, width: usize) -> String {
    let trimmed = truncate_chars(input, width);
    let len = trimmed.chars().count();
    if len >= width {
        return trimmed;
    }

    format!("{trimmed}{}", " ".repeat(width - len))
}

fn hhmm_utc() -> String {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let day_secs = now_secs % 86_400;
    let hours = day_secs / 3_600;
    let mins = (day_secs % 3_600) / 60;
    format!("{hours:02}:{mins:02}")
}

fn command_menu_window(total: usize, selected: usize, max_rows: usize) -> (usize, usize) {
    if total == 0 || max_rows == 0 {
        return (0, 0);
    }
    if total <= max_rows {
        return (0, total);
    }

    let half = max_rows / 2;
    let mut start = selected.saturating_sub(half);
    let mut end = start + max_rows;
    if end > total {
        end = total;
        start = end.saturating_sub(max_rows);
    }

    (start, end)
}

fn compact_history_row(line: &ChatLine, width: usize) -> String {
    let sender = truncate_with_marker(&line.sender, 10);
    let content = truncate_with_marker(&line.text, width.saturating_sub(19));
    truncate_with_marker(
        &format!("{} {}: {}", line.timestamp, sender, content),
        width,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(ui.input_buffer, "/help all");
    }

    #[test]
    fn slash_menu_argument_template_waits_for_argument() {
        let mut ui = TerminalUi::new(false);
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));

        let first_enter = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(first_enter.is_none());
        assert_eq!(ui.input_buffer, "/c ");

        let second_enter = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(second_enter.is_none());

        let _ = ui.handle_key_event(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
        let submitted = ui.handle_key_event(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(submitted.as_deref(), Some("/c X"));
    }

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
    fn command_menu_window_keeps_selected_in_view() {
        let (start, end) = command_menu_window(10, 8, 4);
        assert!(8 >= start && 8 < end);
        assert_eq!(end - start, 4);
    }

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
}
