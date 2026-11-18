//! The terminal: questions on stderr (the TS `prompt` in bin.ts), typing hidden for passwords, and
//! the host name for the device name. The only module with `unsafe` (libc's termios and
//! `gethostname`, contract-v1.4).
#![allow(unsafe_code)]

use std::io::{BufRead, IsTerminal, Write};

use ov_error::{OvError, OvErrorCode};

/// Whether stdin is a terminal, so `ov` may ask questions (the TS asks only then).
pub fn can_prompt() -> bool {
    std::io::stdin().is_terminal()
}

fn cancelled() -> OvError {
    OvError::new(OvErrorCode::Aborted, "cancelled")
}

/// Asks `question` on stderr and reads one line from the terminal; `hidden` doesn't echo it (and
/// prints the newline itself, as the TS does). Ctrl-C while hidden fails with "cancelled".
pub fn prompt(question: &str, hidden: bool) -> Result<String, OvError> {
    let mut err = std::io::stderr();
    let _ = err.write_all(question.as_bytes());
    let _ = err.flush();
    if hidden {
        let line = read_hidden()?;
        let _ = err.write_all(b"\n");
        return Ok(line);
    }
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).map_err(|e| OvError::internal(e.to_string()))?;
    if n == 0 {
        return Err(cancelled());
    }
    Ok(line.strip_suffix("\r\n").or_else(|| line.strip_suffix('\n')).unwrap_or(&line).to_string())
}

/// Puts the terminal back as it was, even on an early return.
#[cfg(unix)]
struct Restore(libc::termios);

#[cfg(unix)]
impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: fd 0 is the terminal we changed, and the struct is the one tcgetattr filled.
        unsafe {
            libc::tcsetattr(0, libc::TCSAFLUSH, &self.0);
        }
    }
}

/// Reads a line with echo off and the terminal's signal keys off, one byte at a time: Enter ends it,
/// Backspace and Ctrl-U edit it, Ctrl-C cancels, Ctrl-D on an empty line cancels.
#[cfg(unix)]
fn read_hidden() -> Result<String, OvError> {
    use std::io::Read;
    // SAFETY: termios is plain data; tcgetattr fills it or fails (then we don't use it).
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd 0 is valid for the life of the process; `t` is a valid out-pointer.
    if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
        return Err(OvError::internal("can't read the terminal settings"));
    }
    let restore = Restore(t);
    let mut raw = t;
    raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    // SAFETY: as above; `raw` is a copy of the current settings with flags cleared.
    if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &raw) } != 0 {
        return Err(OvError::internal("can't change the terminal settings"));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::<u8>::new());
    let mut stdin = std::io::stdin().lock();
    let mut b = [0u8; 1];
    loop {
        match stdin.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(OvError::internal(e.to_string())),
        }
        match b[0] {
            b'\r' | b'\n' => break,
            0x03 => return Err(cancelled()),
            0x04 if bytes.is_empty() => return Err(cancelled()),
            0x04 => break,
            0x15 => bytes.clear(),
            0x7f | 0x08 => {
                // Drop one UTF-8 character.
                while let Some(last) = bytes.pop() {
                    if last & 0xc0 != 0x80 {
                        break;
                    }
                }
            }
            c => bytes.push(c),
        }
    }
    drop(restore);
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Windows: hiding typed text needs the console API (not in the dependency allow-list yet), so
/// hidden questions aren't asked; set the value in the environment or pass the flag instead.
#[cfg(not(unix))]
fn read_hidden() -> Result<String, OvError> {
    Err(OvError::new(
        OvErrorCode::InvalidRequest,
        "this terminal can't hide what you type: set OPENVIREO_PASSWORD (and pass --secret-key, OPENVIREO_SHARE_PASSCODE) instead",
    ))
}

/// The computer's name (Node's `os.hostname()`).
pub fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is valid for `len` bytes; gethostname NUL-terminates or truncates.
        if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
        String::new()
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}
