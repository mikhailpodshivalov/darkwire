use super::{
    style,
    text::{
        self, compact_history_row, pad_or_trim, tail_chars, truncate_chars, truncate_with_marker,
    },
    ChatLine, ChatLineKind, TerminalUi, MAX_COMMAND_MENU_ITEMS, MIN_TERMINAL_HEIGHT,
    MIN_TERMINAL_WIDTH,
};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    queue,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{size, Clear, ClearType},
};
use std::io::{self, Write};

impl TerminalUi {
    pub(super) fn render(&mut self) {
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
        print_colored(stdout, self.theme.sender_color(peer), &peer_visible);
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
        let sender_width = sender_width_for_inner(inner);
        let body_width = body_width_for_inner(inner);
        let expanded = expanded_history_lines(&self.history, body_width);
        let lines: Vec<&ChatLine> = expanded
            .iter()
            .rev()
            .take(history_rows)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        for line in lines {
            self.draw_history_row(stdout, y as u16, inner, sender_width, line);
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

    fn draw_history_row(
        &self,
        stdout: &mut io::Stdout,
        y: u16,
        inner: usize,
        sender_width: usize,
        line: &ChatLine,
    ) {
        let _ = queue!(stdout, MoveTo(0, y), Print("║"));

        // Row shape: " HH:MM sender: message"
        let header_width = 1 + 5 + 1 + sender_width + 2;
        let body_width = inner.saturating_sub(header_width);

        let mut used = 0;
        let _ = queue!(stdout, Print(" "));
        used += 1;

        let time = if line.timestamp.is_empty() {
            " ".repeat(5)
        } else {
            text::pad_or_trim(&line.timestamp, 5)
        };
        let _ = queue!(
            stdout,
            SetForegroundColor(Color::DarkGrey),
            Print(time),
            ResetColor
        );
        used += 5;

        let _ = queue!(stdout, Print(" "));
        used += 1;

        if line.timestamp.is_empty() {
            let _ = queue!(stdout, Print(" ".repeat(sender_width)));
        } else {
            let sender = text::pad_or_trim(
                &truncate_with_marker(&line.sender, sender_width),
                sender_width,
            );
            print_colored(stdout, sender_cell_color(&self.theme, line), &sender);
        }
        used += sender_width;

        let _ = queue!(stdout, Print(": "));
        used += 2;
        let body = truncate_chars(&line.text, body_width);
        print_colored(stdout, body_cell_color(&self.theme, line), &body);
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

fn sender_cell_color(theme: &style::UiTheme, line: &ChatLine) -> Option<Color> {
    match line.kind {
        ChatLineKind::Error => Some(theme.error),
        ChatLineKind::System | ChatLineKind::Incoming | ChatLineKind::Outgoing => {
            theme.sender_color(&line.sender)
        }
    }
}

fn body_cell_color(theme: &style::UiTheme, line: &ChatLine) -> Option<Color> {
    match line.kind {
        ChatLineKind::Error => Some(theme.error),
        ChatLineKind::System | ChatLineKind::Incoming | ChatLineKind::Outgoing => {
            sender_cell_color(theme, line).or(Some(theme.system))
        }
    }
}

fn print_colored(stdout: &mut io::Stdout, color: Option<Color>, text: &str) {
    if let Some(color) = color {
        let _ = queue!(stdout, SetForegroundColor(color), Print(text), ResetColor);
    } else {
        let _ = queue!(stdout, Print(text));
    }
}

fn terminal_size() -> (usize, usize) {
    size()
        .map(|(cols, rows)| (cols as usize, rows as usize))
        .ok()
        .filter(|(cols, rows)| *cols > 0 && *rows > 0)
        .unwrap_or((80, 24))
}

fn sender_width_for_inner(inner: usize) -> usize {
    let fixed_cells_without_sender = 1 + 5 + 1 + 2;
    let min_body_width = 8;
    let max_sender = inner.saturating_sub(fixed_cells_without_sender + min_body_width);
    max_sender.clamp(6, 16)
}

fn body_width_for_inner(inner: usize) -> usize {
    let sender_width = sender_width_for_inner(inner);
    let header_width = 1 + 5 + 1 + sender_width + 2;
    inner.saturating_sub(header_width).max(1)
}

fn expanded_history_lines(
    history: &std::collections::VecDeque<ChatLine>,
    body_width: usize,
) -> Vec<ChatLine> {
    let mut out = Vec::new();
    for line in history {
        let chunks = text::wrap_chars(&line.text, body_width);
        for (idx, chunk) in chunks.into_iter().enumerate() {
            out.push(ChatLine {
                timestamp: if idx == 0 {
                    line.timestamp.clone()
                } else {
                    String::new()
                },
                sender: if idx == 0 {
                    line.sender.clone()
                } else {
                    line.sender.clone()
                },
                text: chunk,
                kind: line.kind,
            });
        }
    }
    out
}

pub(super) fn command_menu_window(
    total: usize,
    selected: usize,
    max_rows: usize,
) -> (usize, usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_history_row(inner: usize, sender_width: usize, line: &ChatLine) -> String {
        let header_width = 1 + 5 + 1 + sender_width + 2;
        let body_width = inner.saturating_sub(header_width);
        let time = if line.timestamp.is_empty() {
            " ".repeat(5)
        } else {
            text::pad_or_trim(&line.timestamp, 5)
        };
        let sender = if line.timestamp.is_empty() {
            " ".repeat(sender_width)
        } else {
            text::pad_or_trim(
                &truncate_with_marker(&line.sender, sender_width),
                sender_width,
            )
        };
        let body = truncate_chars(&line.text, body_width);
        let used = 1 + 5 + 1 + sender_width + 2 + body.chars().count();
        let mut row = format!("║ {} {}: {}", time, sender, body);
        if used < inner {
            row.push_str(&" ".repeat(inner - used));
        }
        row.push('║');
        row
    }

    fn snapshot_lines(ui: &TerminalUi, cols: usize, rows: usize) -> Vec<String> {
        if rows == 0 {
            return Vec::new();
        }

        if cols < MIN_TERMINAL_WIDTH || rows < MIN_TERMINAL_HEIGHT {
            return snapshot_lines_compact(ui, cols, rows);
        }
        snapshot_lines_normal(ui, cols, rows)
    }

    fn snapshot_lines_normal(ui: &TerminalUi, cols: usize, rows: usize) -> Vec<String> {
        let inner = cols.saturating_sub(2);
        let messages_height = rows.saturating_sub(6);
        let mut lines = vec![" ".repeat(cols); rows];

        lines[0] = format!("╔{}╗", "═".repeat(inner));

        let prefix = " peers: ";
        let peer = ui.active_peer.as_deref().unwrap_or("-");
        let peer_visible = truncate_chars(peer, inner.saturating_sub(prefix.chars().count()));
        let mut peers_row = format!("║{}{}", prefix, peer_visible);
        let used = prefix.chars().count() + peer_visible.chars().count();
        if used < inner {
            peers_row.push_str(&" ".repeat(inner - used));
        }
        peers_row.push('║');
        lines[1] = peers_row;

        lines[2] = format!("╠{}╣", "═".repeat(inner));

        let menu_rows = if ui.command_menu_visible() {
            MAX_COMMAND_MENU_ITEMS.min(messages_height.saturating_sub(1))
        } else {
            0
        };
        let history_rows = messages_height.saturating_sub(menu_rows);
        let sender_width = sender_width_for_inner(inner);
        let body_width = body_width_for_inner(inner);
        let expanded = expanded_history_lines(&ui.history, body_width);
        let selected: Vec<&ChatLine> = expanded
            .iter()
            .rev()
            .take(history_rows)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        for idx in 0..history_rows {
            lines[3 + idx] = if idx < selected.len() {
                plain_history_row(inner, sender_width, selected[idx])
            } else {
                format!("║{}║", " ".repeat(inner))
            };
        }

        if menu_rows > 0 {
            let (start_idx, end_idx) =
                command_menu_window(ui.command_matches.len(), ui.command_selected, menu_rows);
            let mut row = 3 + history_rows;
            for (idx, command) in ui.command_matches[start_idx..end_idx].iter().enumerate() {
                let absolute = start_idx + idx;
                let prefix = if absolute == ui.command_selected {
                    " / "
                } else {
                    "   "
                };
                let text = truncate_chars(command, inner.saturating_sub(prefix.chars().count()));
                let mut menu_row = format!("║{}{}", prefix, text);
                let used = prefix.chars().count() + text.chars().count();
                if used < inner {
                    menu_row.push_str(&" ".repeat(inner - used));
                }
                menu_row.push('║');
                lines[row] = menu_row;
                row += 1;
            }
            while row < 3 + messages_height {
                lines[row] = format!("║{}║", " ".repeat(inner));
                row += 1;
            }
        }

        lines[rows - 3] = format!("╠{}╣", "═".repeat(inner));
        let input_prefix = " > ";
        let available_input = inner.saturating_sub(input_prefix.chars().count());
        let input_visible = tail_chars(&ui.input_buffer, available_input);
        let mut input_row = format!("║{}{}", input_prefix, input_visible);
        let used_input = input_prefix.chars().count() + input_visible.chars().count();
        if used_input < inner {
            input_row.push_str(&" ".repeat(inner - used_input));
        }
        input_row.push('║');
        lines[rows - 2] = input_row;
        lines[rows - 1] = format!("╚{}╝", "═".repeat(inner));

        lines
    }

    fn snapshot_lines_compact(ui: &TerminalUi, cols: usize, rows: usize) -> Vec<String> {
        let width = cols.max(1);
        let mut lines = vec![String::new(); rows];
        let input_row = rows.saturating_sub(1);
        let history_capacity = input_row.saturating_sub(1);

        let peer = ui.active_peer.as_deref().unwrap_or("-");
        lines[0] = truncate_with_marker(&format!("peer: {peer}"), width);

        let menu_rows = if ui.command_menu_visible() {
            2.min(history_capacity)
        } else {
            0
        };
        let history_rows = history_capacity.saturating_sub(menu_rows);

        let history_lines: Vec<&ChatLine> = ui
            .history
            .iter()
            .rev()
            .take(history_rows)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        for (idx, line) in history_lines.iter().enumerate() {
            lines[1 + idx] = compact_history_row(line, width);
        }

        if menu_rows > 0 {
            let (start_idx, end_idx) =
                command_menu_window(ui.command_matches.len(), ui.command_selected, menu_rows);
            let start_row = 1 + history_rows;
            for (idx, command) in ui.command_matches[start_idx..end_idx].iter().enumerate() {
                let absolute = start_idx + idx;
                let prefix = if absolute == ui.command_selected {
                    "/ "
                } else {
                    "  "
                };
                lines[start_row + idx] = truncate_with_marker(&format!("{prefix}{command}"), width);
            }
        }

        lines[input_row] = text::pad_or_trim(
            &format!(
                "> {}",
                tail_chars(&ui.input_buffer, width.saturating_sub(2))
            ),
            width,
        );
        lines
    }

    #[test]
    fn command_menu_window_keeps_selected_in_view() {
        let (start, end) = command_menu_window(10, 8, 4);
        assert!(8 >= start && 8 < end);
        assert_eq!(end - start, 4);
    }

    #[test]
    fn expanded_history_lines_wraps_long_payload_into_multiple_rows() {
        let mut history = std::collections::VecDeque::new();
        history.push_back(ChatLine {
            timestamp: "12:00".to_string(),
            sender: "invite".to_string(),
            text: "DL1:ABCDEFGHIJ".to_string(),
            kind: ChatLineKind::System,
        });

        let expanded = expanded_history_lines(&history, 4);
        assert_eq!(expanded.len(), 4);
        assert_eq!(expanded[0].timestamp, "12:00");
        assert_eq!(expanded[0].sender, "invite");
        assert!(expanded[1].timestamp.is_empty());
        assert_eq!(expanded[1].sender, "invite");
    }

    #[test]
    fn render_snapshot_normal_layout_is_stable() {
        let mut ui = TerminalUi::new(false);
        ui.active_peer = Some("@mike".to_string());
        ui.input_buffer = "hello".to_string();
        ui.history.push_back(ChatLine {
            timestamp: "12:01".to_string(),
            sender: "you".to_string(),
            text: "first".to_string(),
            kind: ChatLineKind::Outgoing,
        });
        ui.history.push_back(ChatLine {
            timestamp: "12:02".to_string(),
            sender: "@mike".to_string(),
            text: "second".to_string(),
            kind: ChatLineKind::Incoming,
        });

        let lines = snapshot_lines(&ui, 40, 12);
        assert_eq!(lines.len(), 12);
        assert_eq!(lines[0], "╔══════════════════════════════════════╗");
        assert!(lines[1].contains("peers: @mike"));
        assert!(lines[3].contains("12:01"));
        assert!(lines[4].contains("12:02"));
        assert!(lines[10].contains("> hello"));
        assert_eq!(lines[11], "╚══════════════════════════════════════╝");
    }

    #[test]
    fn render_snapshot_compact_layout_is_stable() {
        let mut ui = TerminalUi::new(false);
        ui.active_peer = Some("@anna".to_string());
        ui.input_buffer = "/he".to_string();
        ui.command_matches = vec!["/help", "/my invite copy"];
        ui.command_selected = 1;
        ui.history.push_back(ChatLine {
            timestamp: "12:03".to_string(),
            sender: "@anna".to_string(),
            text: "ping".to_string(),
            kind: ChatLineKind::Incoming,
        });

        let lines = snapshot_lines(&ui, 20, 7);
        assert_eq!(lines[0], "peer: @anna");
        assert!(lines[1].contains("12:03"));
        assert_eq!(lines[4], "  /help");
        assert_eq!(lines[5], "/ /my invite copy");
        assert!(lines[6].contains("> /he"));
    }
}
