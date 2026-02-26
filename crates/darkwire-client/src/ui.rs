use crate::commands::command_palette_items;
use crossterm::{
    event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, size},
};
use std::io::{self, Write};

#[derive(Debug)]
pub struct TerminalUi {
    interactive: bool,
    input_buffer: String,
    rendered_prompt_rows: usize,
    command_matches: Vec<&'static str>,
    command_selected: usize,
}

impl TerminalUi {
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            input_buffer: String::new(),
            rendered_prompt_rows: 0,
            command_matches: Vec::new(),
            command_selected: 0,
        }
    }

    pub fn print_line(&mut self, line: &str) {
        if self.interactive {
            self.clear_rendered_prompt();
            println!("{line}");
            self.redraw_prompt();
            return;
        }

        println!("{line}");
    }

    pub fn print_error(&mut self, line: &str) {
        if self.interactive {
            self.clear_rendered_prompt();
            eprintln!("{line}");
            self.redraw_prompt();
            return;
        }

        eprintln!("{line}");
    }

    pub fn redraw_prompt(&mut self) {
        if !self.interactive {
            return;
        }

        self.clear_rendered_prompt();

        let mut rendered_rows = 0;
        if self.command_menu_visible() {
            for (index, command) in self.command_matches.iter().enumerate() {
                let line = if index == self.command_selected {
                    format!("  > {command}")
                } else {
                    format!("    {command}")
                };
                print!("\r{line}\r\n");
                rendered_rows += line_rows(&line);
            }
        }

        // Always start prompt from column 0 even if cursor drifted after wrapped output.
        print!("\r> {}", self.input_buffer);
        let _ = io::stdout().flush();
        rendered_rows += prompt_rows(&self.input_buffer);
        self.rendered_prompt_rows = rendered_rows;
    }

    pub fn clear_line(&mut self) {
        if !self.interactive {
            return;
        }

        self.clear_rendered_prompt();
        let _ = io::stdout().flush();
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
                print!("\r\n");
                let _ = io::stdout().flush();
                // Keep the submitted line in scrollback and draw a fresh prompt
                // on the next line without trying to erase wrapped rows above.
                self.rendered_prompt_rows = 0;
                self.redraw_prompt();
                Some(submitted)
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
                self.update_command_matches();
                self.redraw_prompt();
                None
            }
            KeyCode::Up => {
                if self.command_menu_visible() {
                    if self.command_selected == 0 {
                        self.command_selected = self.command_matches.len() - 1;
                    } else {
                        self.command_selected -= 1;
                    }
                    self.redraw_prompt();
                }
                None
            }
            KeyCode::Down => {
                if self.command_menu_visible() {
                    self.command_selected =
                        (self.command_selected + 1) % self.command_matches.len();
                    self.redraw_prompt();
                }
                None
            }
            KeyCode::Esc => {
                if self.command_menu_visible() {
                    self.command_matches.clear();
                    self.command_selected = 0;
                    self.redraw_prompt();
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
                self.redraw_prompt();
                None
            }
            _ => None,
        }
    }

    pub fn handle_paste(&mut self, text: &str) {
        for ch in text.chars() {
            if ch == '\r' || ch == '\n' {
                continue;
            }
            if ch.is_control() {
                continue;
            }
            self.input_buffer.push(ch);
        }

        self.update_command_matches();
        if self.interactive {
            self.redraw_prompt();
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
        self.redraw_prompt();
        true
    }

    fn clear_rendered_prompt(&mut self) {
        if !self.interactive || self.rendered_prompt_rows == 0 {
            return;
        }

        print!("\r\x1b[2K");
        for _ in 1..self.rendered_prompt_rows {
            print!("\x1b[1A\r\x1b[2K");
        }
        print!("\r");
        self.rendered_prompt_rows = 0;
    }
}

pub struct RawModeGuard;

impl RawModeGuard {
    pub fn activate(enabled: bool) -> io::Result<Option<Self>> {
        if !enabled {
            return Ok(None);
        }

        enable_raw_mode()?;
        Ok(Some(Self))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        print!("\r\x1b[2K");
        let _ = io::stdout().flush();
    }
}

fn prompt_rows(input: &str) -> usize {
    let width = terminal_width();

    let prompt_len = 2 + input.chars().count();
    let used_cells = prompt_len.max(1);
    ((used_cells - 1) / width) + 1
}

fn line_rows(line: &str) -> usize {
    let width = terminal_width();
    let used_cells = line.chars().count().max(1);
    ((used_cells - 1) / width) + 1
}

fn terminal_width() -> usize {
    size()
        .map(|(cols, _)| cols as usize)
        .ok()
        .filter(|cols| *cols > 0)
        .unwrap_or(80)
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
    fn prompt_rows_scales_with_length() {
        let short = prompt_rows("hi");
        let long = prompt_rows(&"x".repeat(500));
        assert!(short >= 1);
        assert!(long >= short);
    }
}
