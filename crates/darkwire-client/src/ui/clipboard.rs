use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine as _};
use std::{
    io::{self, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

pub(super) fn copy_text(text: &str) -> io::Result<()> {
    if copy_with_system_command(text).is_ok() {
        return Ok(());
    }

    match copy_with_osc52(text) {
        Ok(()) => Err(io::Error::other(
            "system clipboard command unavailable; terminal OSC52 copy attempted (paste may be blocked)",
        )),
        Err(err) => Err(io::Error::other(format!(
            "clipboard command unavailable and OSC52 failed: {err}",
        ))),
    }
}

fn copy_with_osc52(text: &str) -> io::Result<()> {
    let encoded = BASE64_STD.encode(text.as_bytes());
    let mut stdout = io::stdout();
    write!(stdout, "\x1b]52;c;{encoded}\x07")?;
    stdout.flush()
}

fn copy_with_system_command(text: &str) -> io::Result<()> {
    let mut last_error: Option<io::Error> = None;

    for (program, args) in clipboard_command_candidates() {
        match run_clipboard_command(program, args, text) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err),
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
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }

    for _ in 0..20 {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            return Err(io::Error::other(format!(
                "{program} exited with status {status}",
            )));
        }
        thread::sleep(Duration::from_millis(5));
    }

    // Some clipboard tools keep a helper process alive after accepting input.
    // Reap it in a detached thread so UI remains responsive and no zombie remains.
    thread::spawn(move || {
        let _ = child.wait();
    });

    Ok(())
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
        ("xclip", &["-selection", "clipboard", "-in", "-silent"]),
        ("xsel", &["--clipboard", "--input"]),
    ]
}
