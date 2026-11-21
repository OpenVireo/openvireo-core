//! A strict XML tokenizer for the documents KeePass apps write, feeding the tree
//! [`Builder`](super::tree::Builder) straight from the decrypted `&str`: no per-event UTF-8 check
//! and no copies of names or plain text (`quick-xml` re-validates each slice it hands out, which
//! was a fifth of a 5k-entry read).
//!
//! It takes elements, quoted attributes, text, the predefined entities and character references,
//! comments, processing instructions (the XML declaration) and CDATA sections. Anything else, or
//! anything it isn't sure `quick-xml` reads the same way (a DOCTYPE, an odd name or attribute
//! syntax, a mismatched end tag, an unclosed reference, any error), gives `None`, and
//! [`parse`](super::tree::parse) reads the document with `quick-xml` instead.

use std::borrow::Cow;

use quick_xml::events::attributes::Attribute;
use quick_xml::name::QName;
use zeroize::Zeroizing;

use super::tree::{resolve_ref, xml10_char, Builder, Node, Tag, Text};
use crate::crypto::InnerStream;

/// `quick-xml`'s XML whitespace.
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\r' | b'\n' | b'\t')
}

/// Bytes the fast path takes in names: ASCII letters, digits, `_ - . :`, and any non-ASCII byte.
const NAME_BYTES: [bool; 256] = {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        t[i] = b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':') || b >= 0x80;
        i += 1;
    }
    t
};

fn is_name_byte(b: u8) -> bool {
    NAME_BYTES[usize::from(b)]
}

fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    hay.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|i| from + i)
}

/// XML 1.0 line endings, as `quick-xml`'s `xml10_content`: `\r\n` and a lone `\r` become `\n`.
fn eols(s: &str) -> Cow<'_, str> {
    if !s.as_bytes().contains(&b'\r') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            out.push('\n');
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    // The caller wipes owned text it keeps; this copy is moved there whole
    Cow::Owned(out)
}

/// The local part of a qualified name (after the first `:`, as `quick-xml`).
fn local(q: &str) -> &str {
    q.find(':').map_or(q, |i| &q[i + 1..])
}

/// `<qname attrs>` or `<qname attrs/>` (`content` between `<` and `>`, the `/` already cut).
fn tag(content: &str) -> Option<Tag<'_>> {
    let b = content.as_bytes();
    let name_len = b.iter().position(|&c| is_ws(c)).unwrap_or(b.len());
    let qname = &content[..name_len];
    if local(qname).is_empty() || !qname.bytes().all(is_name_byte) || qname.starts_with(':') {
        return None;
    }
    let mut attrs: Vec<(&str, Text<'_>)> = Vec::new();
    let mut keys: Vec<&str> = Vec::new();
    let mut i = name_len;
    loop {
        while i < b.len() && is_ws(b[i]) {
            i += 1;
        }
        if i == b.len() {
            break;
        }
        let k = i;
        while i < b.len() && is_name_byte(b[i]) {
            i += 1;
        }
        let key = &content[k..i];
        if local(key).is_empty() || key.starts_with(':') || keys.contains(&local(key)) {
            return None;
        }
        while i < b.len() && is_ws(b[i]) {
            i += 1;
        }
        if b.get(i) != Some(&b'=') {
            return None;
        }
        i += 1;
        while i < b.len() && is_ws(b[i]) {
            i += 1;
        }
        let q = *b.get(i).filter(|&&c| c == b'"' || c == b'\'')?;
        let v = i + 1;
        let end = v + b[v..].iter().position(|&c| c == q)?;
        let raw = &content[v..end];
        i = end + 1;
        // Attributes are separated by whitespace
        if i < b.len() && !is_ws(b[i]) {
            return None;
        }
        // quick-xml's own normalization, so values come out exactly as it gives them
        let a = Attribute { key: QName(key), value: Cow::Borrowed(raw) };
        let value = match a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok()? {
            Cow::Borrowed(_) => Text::Borrowed(raw),
            Cow::Owned(o) => Text::Owned(Zeroizing::new(o)),
        };
        if !value.chars().all(xml10_char) {
            return None;
        }
        keys.push(local(key));
        attrs.push((local(key), value));
    }
    Some(Tag { qname, name: local(qname), attrs })
}

/// The tree, or `None` when `quick-xml` should read the document (BOM already stripped).
pub(crate) fn parse<'a>(xml: &'a str, stream: Option<&mut InnerStream>) -> Option<Node<'a>> {
    let b = xml.as_bytes();
    let mut t = Builder::new(stream);
    let mut pos = 0;
    while pos < b.len() {
        // Text up to the next markup or reference; a `\r` in it means line endings to normalize
        let mut next = pos;
        let mut cr = false;
        while next < b.len() {
            match b[next] {
                b'<' | b'&' => break,
                b'\r' => cr = true,
                _ => {}
            }
            next += 1;
        }
        if next > pos {
            let text = &xml[pos..next];
            t.text(if cr { eols(text) } else { Cow::Borrowed(text) });
        }
        pos = next;
        if pos == b.len() {
            break;
        }
        if b[pos] == b'&' {
            // quick-xml: a reference ends at the first `;`, before any `&` or `<`
            let end = pos + 1 + b[pos + 1..].iter().position(|&c| matches!(c, b';' | b'&' | b'<'))?;
            if b[end] != b';' {
                return None;
            }
            if t.in_element() {
                t.char(resolve_ref(&xml[pos + 1..end]).ok()?);
            }
            pos = end + 1;
            continue;
        }
        match b.get(pos + 1) {
            Some(b'/') => {
                let gt = pos + 2 + b[pos + 2..].iter().position(|&c| c == b'>')?;
                let name = xml[pos + 2..gt].trim_end_matches([' ', '\r', '\n', '\t']);
                if t.open_qname() != Some(name) {
                    return None;
                }
                t.end().ok()?;
                pos = gt + 1;
            }
            Some(b'?') => {
                // The declaration or a processing instruction: skipped
                if b.get(pos + 2) == Some(&b'>') {
                    return None;
                }
                pos = find(b, pos + 2, b"?>")? + 2;
            }
            Some(b'!') => {
                let rest = &b[pos..];
                if rest.starts_with(b"<!--") {
                    if matches!(rest.get(4), Some(b'>' | b'-')) {
                        return None;
                    }
                    pos = find(b, pos + 4, b"-->")? + 3;
                } else if rest.starts_with(b"<![CDATA[") {
                    let end = find(b, pos + 9, b"]]>")?;
                    t.text(eols(&xml[pos + 9..end]));
                    pos = end + 3;
                } else {
                    // DOCTYPE and the rest: quick-xml's
                    return None;
                }
            }
            _ => {
                // A start tag ends at the first `>` outside quotes, as quick-xml's ElementParser
                let mut quote = None;
                let mut gt = None;
                for (i, &c) in b[pos + 1..].iter().enumerate() {
                    match (quote, c) {
                        (None, b'>') => {
                            gt = Some(pos + 1 + i);
                            break;
                        }
                        (None, b'"' | b'\'') => quote = Some(c),
                        (Some(q), c) if c == q => quote = None,
                        _ => {}
                    }
                }
                let gt = gt?;
                let content = &xml[pos + 1..gt];
                match content.strip_suffix('/') {
                    Some(c) => t.empty(tag(c)?).ok()?,
                    None => t.start(tag(content)?).ok()?,
                }
                pos = gt + 1;
            }
        }
    }
    t.finish().ok()
}

#[cfg(test)]
mod tests {
    //! Every parse under `cfg(test)` reads the document with `quick-xml` too whenever the fast path
    //! takes it, and asserts the trees match (`tree::parse`): these tests feed it documents.

    use super::super::tree::{parse, FAST_READS};
    use crate::crypto::InnerStream;
    use crate::model::{Entry, Group, StringField, Uuid, XmlElement};

    fn fast_reads() -> u32 {
        FAST_READS.with(|c| c.get())
    }

    /// Parses `xml` (both paths, compared) and says whether the fast path took it.
    fn took_fast(xml: &str) -> bool {
        let before = fast_reads();
        let mut s = InnerStream::new(3, &[5; 64]).unwrap().unwrap();
        let _ = parse(xml, Some(&mut s));
        fast_reads() > before
    }

    #[test]
    fn corpus_files_read_the_same_on_both_paths() {
        let files = super::super::corpus::files();
        for f in &files {
            let before = fast_reads();
            crate::read(&f.bytes, &f.key).unwrap_or_else(|e| panic!("{}: {e}", f.name));
            // KeePass apps' XML is what the fast path is for: none may fall back
            assert_eq!(fast_reads(), before + 1, "{} fell back to quick-xml", f.name);
        }
    }

    #[test]
    fn unwritable_names_and_values_are_refused() {
        for x in [
            "<A><>x</></A>",
            "<A>< x=\"1\"/></A>",
            "<A><p:/></A>",
            "<A :=\"1\"/>",
            "<A p:=\"1\"/>",
            "<A><B\"x=\"1\">y</B\"x=\"1\"></A>",
            "<A><p:a/b/></A>",
            "<A x=\"True\u{1}\"/>",
            "<A x=\"&#1;\"/>",
            "<A p:x=\"1\" q:x=\"2\"/>",
            "<A x=\"1\" p:x=\"2\"/>",
        ] {
            assert!(parse(x, None).is_err(), "{x:?}");
        }
    }

    #[test]
    fn edge_cases() {
        let fast = [
            "<A/>",
            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<A>x</A>",
            "<A>a &lt;b&gt; &amp; &quot;&apos; &#13;&#x41;&#10;</A>",
            "<A>\r\n x\ry\r</A>",
            "<A><![CDATA[<raw> & \r\n]]>tail</A>",
            "<A><!-- c --><B/><?pi data?></A>",
            "<p:A xmlns:p=\"u\"><p:B q:x='1' y = \"2\" /></p:A>",
            "<A x=\"a&amp;b&#9;c\td\ne\r\nf\"/>",
            "<A x='\"' y=\"'\"/>",
            "<A x=\">\"/>",
            "<A>  <B/>  mid  <C> sp </C> </A>",
            "<A Protected=\"True\">AAAA</A>",
            "<A Protected=\"True\"></A>",
            "<A Protected=\"True\">!!</A>",
            "\u{feff}<A>bom</A>",
            "<A>é ✓ 𝄞</A>",
            "<A></A >",
            "<A>",
            "<A/><B/>",
            "x<A/>y",
            "<A>&#0;</A>",
            "<A>&nope;</A>",
            "<A x=\"<\"/>",
            "<A x=\"a>b\" y=''/>",
            "<A\tx=\"1\"\ny='2' />",
            "<é ü=\"✓\">x</é>",
            "<A x=\"&#60;&#x3E;\"/>",
        ];
        for x in fast {
            took_fast(x);
        }
        // These go to quick-xml (it decides: some it reads, some it rejects)
        let slow = [
            "<!DOCTYPE A><A/>",
            "<A>a & b</A>",
            "<A>&amp</A>",
            "<A></B>",
            "</A>",
            "< A/>",
            "<A x=1/>",
            "<A x/>",
            "<A x=\"1\"y=\"2\"/>",
            "<A x=\"1\" x=\"2\"/>",
            "<A x=\"&bad;\"/>",
            "<A \"x\"=\"1\"/>",
            "<A/b/>",
            "<?>",
            "<!-->-->",
            "<!--->",
            "<![CDATA[x",
            "<A",
            "<A x=\"1/>",
            "<:A/>",
            "<>x</>",
            "< x=\"1\"/>",
            "<p:/>",
            "<A p:=\"1\"/>",
        ];
        for x in slow {
            assert!(!took_fast(x), "{x:?} should fall back");
        }
    }

    /// A small vault with protected values, attributes, unknown elements and odd text.
    fn sample_xml() -> String {
        let (mut db, _) = crate::vault::create_vault_kdbx("Vault <&> \"x\"", &[3; 32], 1_700_000_000).unwrap();
        let mut g = Group::new(Uuid::from_u128(7), "Work & play", 1_700_000_000);
        for n in 0..3u128 {
            let mut e = Entry::new(Uuid::from_u128(100 + n), 1_700_000_000);
            e.strings = vec![
                StringField::new("Title", format!("Entry {n} <b>"), false),
                StringField::new("Password", format!("pw ✓ {n}\r\nline"), true),
                StringField::new("Notes", "a\tb  ", false),
            ];
            e.unknown.push(XmlElement {
                name: "ZzX".into(),
                attributes: vec![("k".into(), "v\"'<".into())],
                text: "t".into(),
                children: vec![],
            });
            g.entries.push(e);
        }
        db.root.groups.push(g);
        let xml = super::super::write::document(&db, InnerStream::new(3, &[5; 64]).unwrap().unwrap()).unwrap();
        String::from_utf8(xml.to_vec()).unwrap()
    }

    #[test]
    fn mutated_documents_read_the_same_on_both_paths() {
        const BITS: [&str; 34] = [
            "<",
            ">",
            "&",
            ";",
            "\"",
            "'",
            "/",
            "=",
            " ",
            "\r",
            "\r\n",
            "\t",
            ":",
            "é",
            "&amp;",
            "&#13;",
            "&#x41;",
            "&lt",
            "<![CDATA[x]]>",
            "<!--c-->",
            "<?pi x?>",
            "<!DOCTYPE x>",
            "<a>",
            "</a>",
            "<b/>",
            " x=\"1\"",
            " x='&lt;'",
            "]]>",
            "-->",
            "?>",
            "<!--",
            "Protected=\"True\"",
            "</Value>",
            "AAAA",
        ];
        let base = sample_xml();
        assert!(took_fast(&base), "the writer's XML is read on the fast path");
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let (mut fast, mut total) = (0, 0);
        for _ in 0..20_000 {
            let mut m = base.clone();
            for _ in 0..=next(3) {
                let at = (0..=m.len()).filter(|&i| m.is_char_boundary(i)).nth(next(m.len() + 1)).unwrap_or(m.len());
                if next(4) == 0 {
                    let to = (at..=m.len()).filter(|&i| m.is_char_boundary(i)).nth(next(8)).unwrap_or(m.len());
                    m.replace_range(at..to, "");
                } else {
                    m.insert_str(at, BITS[next(BITS.len())]);
                }
            }
            total += 1;
            fast += u32::from(took_fast(&m));
        }
        // Many mutants stay well-formed and take the fast path (15% with this seed); the rest fall back
        assert!(fast > total / 10, "{fast} of {total} on the fast path");
    }
}
