//! Streaming secret masking for `ov run`, ported from `packages/cli/src/mask.ts`: replaces every
//! occurrence of a secret value in a byte stream, also when a value is split across chunks. Bytes
//! that could be the start of a secret are held back until the next chunk (or [`Masker::flush`])
//! shows whether they are.

use zeroize::Zeroizing;

use crate::js;

/// What a secret is replaced with.
pub const MASK: &str = "<concealed by openvireo>";

/// `maskPatterns`: each secret, and each line (at least 4 characters after trimming) of a
/// multi-line secret, without duplicates, in first-seen order.
pub fn mask_patterns<S: AsRef<str>>(secrets: &[S]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |s: &str| {
        if !out.iter().any(|o| o == s) {
            out.push(s.to_string());
        }
    };
    for s in secrets {
        let s = s.as_ref();
        if s.is_empty() {
            continue;
        }
        add(s);
        if s.contains(['\r', '\n']) {
            // split(/\r?\n|\r/)
            for line in s.replace("\r\n", "\n").split(['\n', '\r']) {
                if js::len(js::trim(line)) >= 4 {
                    add(line);
                }
            }
        }
    }
    out
}

/// `Masker`.
pub struct Masker {
    secrets: Vec<Zeroizing<String>>,
    mask: Vec<u8>,
    /// Longest first, so a secret that contains another one is replaced whole.
    patterns: Vec<Zeroizing<Vec<u8>>>,
    first: [bool; 256],
    held: Zeroizing<Vec<u8>>,
}

impl Masker {
    /// A masker with the default [`MASK`].
    pub fn new<S: AsRef<str>>(secrets: &[S]) -> Self {
        Self::with_mask(secrets, MASK)
    }

    /// A masker that writes `mask` in place of each secret.
    pub fn with_mask<S: AsRef<str>>(secrets: &[S], mask: &str) -> Self {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> =
            mask_patterns(secrets).into_iter().map(|s| Zeroizing::new(s.into_bytes())).collect();
        patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
        let mut first = [false; 256];
        for p in &patterns {
            first[usize::from(p[0])] = true;
        }
        Masker {
            secrets: secrets.iter().map(|s| Zeroizing::new(s.as_ref().to_string())).collect(),
            mask: mask.as_bytes().to_vec(),
            patterns,
            first,
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// Whether bytes are held back as a possible secret prefix.
    pub fn pending(&self) -> bool {
        !self.held.is_empty()
    }

    /// Masks a chunk; returns what can be written now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut buf = Zeroizing::new(std::mem::take(&mut *self.held));
        buf.extend_from_slice(chunk);
        self.run(&buf, false)
    }

    /// Emits whatever is held back (at the end of the stream, or after a pause).
    pub fn flush(&mut self) -> Vec<u8> {
        let buf = Zeroizing::new(std::mem::take(&mut *self.held));
        self.run(&buf, true)
    }

    /// Masks a whole string at once (a fresh masker, so held bytes of this stream are not mixed in).
    pub fn mask_string(&self, s: &str) -> String {
        let mut m = Masker::with_mask(&self.secrets, &String::from_utf8_lossy(&self.mask));
        let mut out = m.push(s.as_bytes());
        out.extend(m.flush());
        String::from_utf8_lossy(&out).into_owned()
    }

    fn run(&mut self, buf: &[u8], last: bool) -> Vec<u8> {
        self.held = Zeroizing::new(Vec::new());
        if self.patterns.is_empty() {
            return buf.to_vec();
        }
        let mut out = Vec::with_capacity(buf.len());
        let mut start = 0;
        let mut i = 0;
        while i < buf.len() {
            if !self.first[usize::from(buf[i])] {
                i += 1;
                continue;
            }
            // Could a secret still be starting here? Then wait for more input before deciding.
            if !last && self.patterns.iter().any(|p| is_cut_off_at(p, buf, i)) {
                out.extend_from_slice(&buf[start..i]);
                self.held = Zeroizing::new(buf[i..].to_vec());
                return out;
            }
            if let Some(hit) = self.patterns.iter().find(|p| buf[i..].starts_with(p)) {
                out.extend_from_slice(&buf[start..i]);
                out.extend_from_slice(&self.mask);
                i += hit.len();
                start = i;
            } else {
                i += 1;
            }
        }
        out.extend_from_slice(&buf[start..]);
        out
    }
}

/// `buf` ends with a proper prefix of `pattern` starting at `i` (the rest may be in the next chunk).
fn is_cut_off_at(pattern: &[u8], buf: &[u8], i: usize) -> bool {
    let n = buf.len() - i;
    n < pattern.len() && pattern[..n] == buf[i..]
}

/// `maskText`: masks a value printed outside `ov run`.
pub fn mask_text<S: AsRef<str>>(text: &str, secrets: &[S]) -> String {
    Masker::new(secrets).mask_string(text)
}

#[cfg(test)]
mod tests {
    // Ported from units.test.ts, describe("Masker").
    use super::*;

    fn stream_through(m: &mut Masker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(m.push(c));
        }
        out.extend(m.flush());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_every_occurrence() {
        let mut m = Masker::new(&["s3cret"]);
        assert_eq!(
            stream_through(&mut m, &[b"token=s3cret and again s3cret.\n"]),
            format!("token={MASK} and again {MASK}.\n")
        );
        assert_eq!(Masker::new::<&str>(&[]).mask_string("s3cret"), "s3cret");
        assert_eq!(Masker::new(&[""]).mask_string("abc"), "abc");
    }

    #[test]
    fn masks_a_secret_split_across_chunks_at_every_position() {
        let text = "before hunter2-but-longer after".as_bytes();
        for a in 0..=text.len() {
            let mut b = a;
            while b <= text.len() {
                let mut m = Masker::new(&["hunter2-but-longer"]);
                let got = stream_through(&mut m, &[&text[..a], &text[a..b], &text[b..]]);
                assert_eq!(got, format!("before {MASK} after"), "a={a} b={b}");
                b += 3;
            }
        }
    }

    #[test]
    fn holds_back_a_possible_prefix_and_releases_it_when_it_isnt_one() {
        let mut m = Masker::new(&["password"]);
        assert_eq!(m.push(b"type pass"), b"type ");
        assert!(m.pending());
        assert_eq!(m.push(b"port"), b"passport");
        assert!(!m.pending());
        assert_eq!(m.push(b"pa"), b"");
        assert_eq!(m.flush(), b"pa");
    }

    #[test]
    fn replaces_the_longer_of_two_overlapping_secrets_whole() {
        let mut m = Masker::new(&["abc", "abcdef"]);
        assert_eq!(stream_through(&mut m, &[b"x abc", b"def y abc z"]), format!("x {MASK} y {MASK} z"));
    }

    #[test]
    fn masks_multi_line_secrets_and_each_of_their_lines() {
        let key = "-----BEGIN KEY-----\nMIIBOgIBAAJBAK\n-----END KEY-----";
        assert_eq!(mask_patterns(&[key]), vec![key, "-----BEGIN KEY-----", "MIIBOgIBAAJBAK", "-----END KEY-----"]);
        let out =
            Masker::new(&[key]).mask_string(&format!("whole:\n{key}\nwith CRLF:\n{}\n", key.replace('\n', "\r\n")));
        assert!(!out.contains("MIIBOgIBAAJBAK"));
        assert!(out.starts_with(&format!("whole:\n{MASK}\n")));
    }

    #[test]
    fn works_on_bytes_including_multi_byte_utf8_split_mid_character() {
        let secret = "pä$$wörd✓";
        let s = format!("[{secret}]");
        let bytes = s.as_bytes();
        for cut in 1..bytes.len() {
            let mut m = Masker::new(&[secret]);
            assert_eq!(stream_through(&mut m, &[&bytes[..cut], &bytes[cut..]]), format!("[{MASK}]"));
        }
        // binary output passes through untouched
        let bin = [0u8, 255, 1, 254, 0x70];
        let mut m = Masker::new(&["pass"]);
        let mut out = m.push(&bin);
        out.extend(m.flush());
        assert_eq!(out, bin);
    }
}
