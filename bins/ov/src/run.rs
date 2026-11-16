//! `ov run`: start a command with references resolved in its environment and its output masked.
//! Ported from `packages/cli/src/run.ts`.

use std::io::Write;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::mask::Masker;

/// Variables the child never gets: it should use the secrets, not the credentials that unlock them.
pub const STRIPPED_ENV: [&str; 4] = [
    "OPENVIREO_SERVICE_ACCOUNT_TOKEN",
    "OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE",
    "OPENVIREO_PASSWORD",
    "OPENVIREO_SECRET_KEY",
];

/// A shared output stream (stdout or stderr).
pub type Out = Arc<Mutex<Box<dyn Write + Send>>>;

/// `RunOptions`.
pub struct RunOptions {
    /// The program.
    pub command: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The child's whole environment.
    pub env: Vec<(String, String)>,
    /// Values to mask in the child's stdout and stderr; `None` passes the output through untouched
    /// (the child then writes to the real stdout/stderr directly).
    pub secrets: Option<Vec<String>>,
    /// Where masked stdout goes.
    pub stdout: Out,
    /// Where masked stderr goes.
    pub stderr: Out,
    /// After this long without output, bytes held back as a possible secret prefix are written
    /// (default 100 ms).
    pub hold: Duration,
}

/// The message Node's `spawn` fails with, e.g. `spawn nope ENOENT`.
fn spawn_error(command: &str, e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => format!("spawn {command} ENOENT"),
        std::io::ErrorKind::PermissionDenied => format!("spawn {command} EACCES"),
        _ => format!("spawn {command}: {e}"),
    }
}

fn write_out(to: &Out, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    if let Ok(mut w) = to.lock() {
        let _ = w.write_all(bytes);
        let _ = w.flush();
    }
}

/// Copies `from` to `to` through a [`Masker`], flushing held bytes after `hold` of silence.
async fn pump<R: tokio::io::AsyncRead + Unpin>(mut from: R, to: Out, secrets: Vec<String>, hold: Duration) {
    let mut masker = Masker::new(&secrets);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let read = if masker.pending() {
            match tokio::time::timeout(hold, from.read(&mut buf)).await {
                Ok(r) => r,
                Err(_) => {
                    write_out(&to, &masker.flush());
                    continue;
                }
            }
        } else {
            from.read(&mut buf).await
        };
        match read {
            Ok(0) | Err(_) => break,
            Ok(n) => write_out(&to, &masker.push(&buf[..n])),
        }
    }
    write_out(&to, &masker.flush());
}

/// The TS `signalNumber`: known names map to their number, any other signal to 1.
#[cfg(unix)]
fn ts_signal_number(sig: i32) -> i32 {
    if matches!(sig, 1 | 2 | 3 | 9 | 15) {
        sig
    } else {
        1
    }
}

/// Sends `sig` to `pid`. Uses kill(1) because no libc binding is on the allow-list (see the
/// OWNER-REQUEST in the W1-L report).
#[cfg(unix)]
fn forward_signal(pid: u32, sig: &str) {
    let _ = std::process::Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// `runCommand`: runs the command and returns its exit code (128 + n when killed by signal n,
/// like a shell). Fails only when the command can't be started.
pub async fn run_command(o: RunOptions) -> Result<i32, String> {
    let masked = o.secrets.is_some();
    let mut cmd = Command::new(&o.command);
    cmd.args(&o.args).env_clear().envs(o.env.iter().map(|(k, v)| (k, v))).stdin(Stdio::inherit());
    if masked {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }
    let mut child = cmd.spawn().map_err(|e| spawn_error(&o.command, &e))?;

    let mut pipes = Vec::new();
    if let Some(secrets) = &o.secrets {
        if let Some(out) = child.stdout.take() {
            pipes.push(tokio::spawn(pump(out, o.stdout.clone(), secrets.clone(), o.hold)));
        }
        if let Some(err) = child.stderr.take() {
            pipes.push(tokio::spawn(pump(err, o.stderr.clone(), secrets.clone(), o.hold)));
        }
    }

    #[cfg(unix)]
    let status = {
        use tokio::signal::unix::{signal, SignalKind};
        let pid = child.id();
        let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
        let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
        let mut hup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
        loop {
            tokio::select! {
                s = child.wait() => break s,
                _ = int.recv() => { if let Some(p) = pid { forward_signal(p, "INT") } }
                _ = term.recv() => { if let Some(p) = pid { forward_signal(p, "TERM") } }
                _ = hup.recv() => { if let Some(p) = pid { forward_signal(p, "HUP") } }
            }
        }
    };
    #[cfg(not(unix))]
    let status = child.wait().await;

    let status = status.map_err(|e| e.to_string())?;
    for p in pipes {
        let _ = p.await;
    }
    if let Some(code) = status.code() {
        return Ok(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        Ok(128 + status.signal().map_or(1, ts_signal_number))
    }
    #[cfg(not(unix))]
    Ok(129)
}

#[cfg(all(test, unix))]
mod tests {
    // No test relies on a PATH lookup (the child is /bin/sh by absolute path) or on scheduling: the
    // hold-back flush is driven through an in-memory pipe and waits for the output it expects.
    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn out_of(b: &Buf) -> Out {
        Arc::new(Mutex::new(Box::new(b.clone())))
    }

    fn opts(script: &str, secrets: Option<Vec<String>>, out: &Buf, err: &Buf) -> RunOptions {
        RunOptions {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![("S".into(), "hunter2".into())],
            secrets,
            stdout: out_of(out),
            stderr: out_of(err),
            hold: Duration::from_millis(100),
        }
    }

    /// A path that can't exist: inside a directory that was never created.
    fn missing_command() -> String {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("ov-run-test-{}-{nanos}-absent", std::process::id()));
        assert!(!dir.exists());
        dir.join("no-such-command").to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn masks_output_and_returns_the_exit_code() {
        let (out, err) = (Buf::default(), Buf::default());
        let script = "printf 'pw=%s\\n' \"$S\"; printf 'e %s e' \"$S\" >&2; exit 3";
        let code = run_command(opts(script, Some(vec!["hunter2".into()]), &out, &err)).await.unwrap();
        assert_eq!(code, 3);
        assert_eq!(out.text(), "pw=<concealed by openvireo>\n");
        assert_eq!(err.text(), "e <concealed by openvireo> e");
    }

    #[tokio::test]
    async fn no_masking_still_returns_the_exit_code() {
        let (out, err) = (Buf::default(), Buf::default());
        assert_eq!(run_command(opts("exit 7", None, &out, &err)).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn releases_a_held_prefix_after_the_hold_time() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let got = Buf::default();
        let pump = tokio::spawn(pump(rx, out_of(&got), vec!["hunter2".into()], Duration::from_millis(20)));
        use tokio::io::AsyncWriteExt;
        tx.write_all(b"hun").await.unwrap();
        // Nothing more arrives, so after the hold time "hun" is written as is.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while got.text() != "hun" {
            assert!(std::time::Instant::now() < deadline, "held bytes never released: {:?}", got.text());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // The rest of the split value is no longer a secret prefix (as in the TS).
        tx.write_all(b"ter2 hunter2").await.unwrap();
        drop(tx);
        pump.await.unwrap();
        assert_eq!(got.text(), "hunter2 <concealed by openvireo>");
    }

    #[tokio::test]
    async fn only_the_given_env_and_signal_codes() {
        let (out, err) = (Buf::default(), Buf::default());
        let code = run_command(opts("echo \"${HOME:-none}\"; kill -TERM $$", Some(vec![]), &out, &err)).await.unwrap();
        assert_eq!(code, 143);
        assert_eq!(out.text(), "none\n");
    }

    #[tokio::test]
    async fn a_missing_command_fails_like_node() {
        let (out, err) = (Buf::default(), Buf::default());
        let mut o = opts("", None, &out, &err);
        let missing = missing_command();
        o.command = missing.clone();
        assert_eq!(run_command(o).await.unwrap_err(), format!("spawn {missing} ENOENT"));
    }
}
