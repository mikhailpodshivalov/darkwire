use crossterm::{
    event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::io::{self, Write};

#[derive(Debug)]
pub struct TerminalUi {
    interactive: bool,
    input_buffer: String,
}

impl TerminalUi {
    pub fn new(interactive: bool) -> Self {
        Self {
            interactive,
            input_buffer: String::new(),
        }
    }

    pub fn print_line(&mut self, line: &str) {
        if self.interactive {
            self.clear_line();
            println!("{line}");
            self.redraw_prompt();
            return;
        }

        println!("{line}");
    }

    pub fn print_error(&mut self, line: &str) {
        if self.interactive {
            self.clear_line();
            eprintln!("{line}");
            self.redraw_prompt();
            return;
        }

        eprintln!("{line}");
    }

    pub fn redraw_prompt(&self) {
        if !self.interactive {
            return;
        }

        print!("\r\x1b[2K> {}", self.input_buffer);
        let _ = io::stdout().flush();
    }

    pub fn clear_line(&self) {
        if !self.interactive {
            return;
        }

        print!("\r\x1b[2K");
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
}
