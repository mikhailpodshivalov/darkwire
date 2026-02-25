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
}

impl TerminalUi {
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            input_buffer: String::new(),
            rendered_prompt_rows: 0,
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
        print!("> {}", self.input_buffer);
        let _ = io::stdout().flush();
        self.rendered_prompt_rows = prompt_rows(&self.input_buffer);
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
                let submitted = std::mem::take(&mut self.input_buffer);
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
                self.redraw_prompt();
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

        if self.interactive {
            self.redraw_prompt();
        }
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
    let width = size()
        .map(|(cols, _)| cols as usize)
        .ok()
        .filter(|cols| *cols > 0)
        .unwrap_or(80);

    let prompt_len = 2 + input.chars().count();
    let used_cells = prompt_len.max(1);
    ((used_cells - 1) / width) + 1
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
    fn prompt_rows_scales_with_length() {
        let short = prompt_rows("hi");
        let long = prompt_rows(&"x".repeat(500));
        assert!(short >= 1);
        assert!(long >= short);
    }
}
