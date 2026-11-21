//! A small element tree, with `Protected="True"` values decrypted through the inner random stream
//! in document order, and an escaping writer on `quick-xml`'s `Writer` that encrypts them again.
//!
//! The tree is read by [`fast`](super::fast) when it can (a strict tokenizer for the XML KeePass
//! apps write), else by `quick-xml`'s pull reader: anything the fast path doesn't take whole,
//! malformed documents included, is read again by `quick-xml`, so errors are its errors. Both feed
//! one [`Builder`], and the fast path's trees are checked against `quick-xml`'s in the tests and
//! under the fuzzers (`cfg(fuzzing)`).

use std::borrow::Cow;

use base64::Engine as _;
use ov_error::OvError;
#[cfg(any(test, fuzzing))]
use quick_xml::events::{BytesEnd, BytesText};
use quick_xml::events::{BytesStart, Event};
use zeroize::Zeroizing;

use crate::bytes::err;
use crate::crypto::InnerStream;
use crate::model::XmlElement;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Deeper documents are refused (groups recurse; this bounds the stack).
const MAX_DEPTH: usize = 512;

/// Text from the document: borrowed from the decrypted XML when it is used as written (most of
/// it), else owned and wiped on drop (entity references, line endings, protected values).
#[derive(Clone)]
pub(crate) enum Text<'a> {
    Borrowed(&'a str),
    Owned(Zeroizing<String>),
}

impl Default for Text<'_> {
    fn default() -> Self {
        Text::Borrowed("")
    }
}

impl std::ops::Deref for Text<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<'a> Text<'a> {
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Text::Borrowed(s) => s,
            Text::Owned(s) => s.as_str(),
        }
    }

    /// The text as an owned string that is wiped on drop.
    pub(crate) fn into_zeroizing(self) -> Zeroizing<String> {
        match self {
            Text::Borrowed(s) => Zeroizing::new(s.to_owned()),
            Text::Owned(s) => s,
        }
    }

    fn owned(&mut self) -> &mut String {
        if let Text::Borrowed(s) = self {
            *self = Text::Owned(Zeroizing::new((*s).to_owned()));
        }
        match self {
            Text::Owned(s) => s,
            Text::Borrowed(_) => unreachable!("made owned above"),
        }
    }

    /// Appends `s`, borrowing it while it is the only text.
    fn push(&mut self, s: &'a str) {
        if s.is_empty() {
            return;
        }
        match self {
            Text::Borrowed("") => *self = Text::Borrowed(s),
            _ => self.owned().push_str(s),
        }
    }

    fn push_cow(&mut self, s: Cow<'a, str>) {
        match s {
            Cow::Borrowed(b) => self.push(b),
            Cow::Owned(o) => {
                let o = Zeroizing::new(o);
                self.owned().push_str(&o);
            }
        }
    }
}

/// One element: name, attributes in order, text and children, borrowing from the XML.
#[derive(Default)]
pub(crate) struct Node<'a> {
    pub(crate) name: &'a str,
    pub(crate) attrs: Vec<(&'a str, Text<'a>)>,
    /// Text content. For an element with children: the non-whitespace text around them, each run
    /// trimmed and concatenated. For a leaf: the text exactly. For a protected element: its clear
    /// text (UTF-8, lossy).
    pub(crate) text: Text<'a>,
    /// For a protected element: its decrypted bytes.
    pub(crate) raw: Option<Zeroizing<Vec<u8>>>,
    pub(crate) children: Vec<Node<'a>>,
}

impl<'a> Node<'a> {
    pub(crate) fn child(&self, name: &str) -> Option<&Node<'a>> {
        self.children.iter().find(|c| c.name == name)
    }

    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| *k == name).map(|(_, v)| v.as_str())
    }

    pub(crate) fn is_protected(&self) -> bool {
        self.attr("Protected").is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    /// The element as a model passthrough element.
    pub(crate) fn into_element(self) -> XmlElement {
        XmlElement {
            name: self.name.to_owned(),
            attributes: self.attrs.into_iter().map(|(k, v)| (k.to_owned(), v.as_str().to_owned())).collect(),
            text: self.text.as_str().to_owned(),
            children: self.children.into_iter().map(Node::into_element).collect(),
        }
    }
}

/// A start tag: qualified name, local name and attributes (local names, normalized values).
pub(crate) struct Tag<'a> {
    pub(crate) qname: &'a str,
    pub(crate) name: &'a str,
    pub(crate) attrs: Vec<(&'a str, Text<'a>)>,
}

/// An element being read: its start tag, its text so far and where its children start in the
/// shared stack of finished elements (taken out in one exact-size allocation at its end tag).
struct Frame<'a> {
    qname: &'a str,
    name: &'a str,
    attrs: Vec<(&'a str, Text<'a>)>,
    /// The non-whitespace text around children, each run trimmed.
    text: Text<'a>,
    /// The current text run.
    seg: Text<'a>,
    first_child: usize,
}

impl<'a> Frame<'a> {
    /// Ends a text run at a child boundary: trimmed into `text`.
    fn flush_trimmed(&mut self) {
        match std::mem::take(&mut self.seg) {
            // Mostly indentation: the ASCII pass empties it without the Unicode check per char
            Text::Borrowed(s) => self.text.push(s.trim_ascii().trim()),
            Text::Owned(s) => {
                let t = s.trim_ascii().trim();
                if !t.is_empty() {
                    self.text.owned().push_str(t);
                }
            }
        }
    }
}

/// Builds the tree from start tags, end tags and text, in document order.
pub(crate) struct Builder<'a, 's> {
    stack: Vec<Frame<'a>>,
    /// Finished elements whose parent is still open, in document order.
    done: Vec<Node<'a>>,
    root: Option<Node<'a>>,
    stream: Option<&'s mut InnerStream>,
}

impl<'a, 's> Builder<'a, 's> {
    pub(crate) fn new(stream: Option<&'s mut InnerStream>) -> Self {
        Builder { stack: Vec::new(), done: Vec::new(), root: None, stream }
    }

    /// The qualified name of the innermost open element.
    pub(crate) fn open_qname(&self) -> Option<&'a str> {
        self.stack.last().map(|f| f.qname)
    }

    /// Whether an element is open (text outside the root is ignored).
    pub(crate) fn in_element(&self) -> bool {
        !self.stack.is_empty()
    }

    fn open_frame(&mut self, tag: Tag<'a>) -> Result<Frame<'a>, OvError> {
        if self.root.is_some() {
            return Err(err("the XML has more than one root element"));
        }
        if let Some(parent) = self.stack.last_mut() {
            parent.flush_trimmed();
        }
        Ok(Frame {
            qname: tag.qname,
            name: tag.name,
            attrs: tag.attrs,
            text: Text::default(),
            seg: Text::default(),
            first_child: self.done.len(),
        })
    }

    pub(crate) fn start(&mut self, tag: Tag<'a>) -> Result<(), OvError> {
        if self.root.is_none() && self.stack.len() >= MAX_DEPTH {
            return Err(err("the XML is nested too deeply"));
        }
        let f = self.open_frame(tag)?;
        self.stack.push(f);
        Ok(())
    }

    pub(crate) fn empty(&mut self, tag: Tag<'a>) -> Result<(), OvError> {
        let f = self.open_frame(tag)?;
        self.close(f)
    }

    pub(crate) fn end(&mut self) -> Result<(), OvError> {
        let f = self.stack.pop().ok_or_else(|| err("the XML has an unmatched end tag"))?;
        self.close(f)
    }

    /// Text (already with XML 1.0 line endings) inside the innermost open element.
    pub(crate) fn text(&mut self, t: Cow<'a, str>) {
        if let Some(f) = self.stack.last_mut() {
            f.seg.push_cow(t);
        }
    }

    /// A resolved entity or character reference.
    pub(crate) fn char(&mut self, c: char) {
        if let Some(f) = self.stack.last_mut() {
            f.seg.owned().push(c);
        }
    }

    fn close(&mut self, mut f: Frame<'a>) -> Result<(), OvError> {
        let text = if f.first_child == self.done.len() {
            std::mem::take(&mut f.seg)
        } else {
            f.flush_trimmed();
            std::mem::take(&mut f.text)
        };
        let children = self.done.split_off(f.first_child);
        let mut node = Node { name: f.name, attrs: f.attrs, text, raw: None, children };
        if node.is_protected() {
            let s = self.stream.as_deref_mut().ok_or_else(|| err("a protected value but no inner stream"))?;
            let cleaned: Zeroizing<String> = Zeroizing::new(node.text.chars().filter(|c| !c.is_whitespace()).collect());
            let mut raw =
                Zeroizing::new(B64.decode(cleaned.as_bytes()).map_err(|_| err("a protected value isn't base64"))?);
            s.apply(&mut raw);
            node.text = Text::Owned(Zeroizing::new(String::from_utf8_lossy(&raw).into_owned()));
            node.raw = Some(raw);
        }
        if self.stack.is_empty() {
            self.root = Some(node);
        } else {
            self.done.push(node);
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Node<'a>, OvError> {
        if !self.stack.is_empty() {
            return Err(err("the XML ends inside an element"));
        }
        self.root.ok_or_else(|| err("the XML has no root element"))
    }
}

/// `part` as a slice of `src`, when it lies inside it: quick-xml's names and attributes borrow
/// from the event, though they point into the document, which is already known to be UTF-8.
fn within<'a>(src: &'a str, part: &str) -> Option<&'a str> {
    let start = (part.as_ptr() as usize).checked_sub(src.as_ptr() as usize)?;
    src.get(start..start.checked_add(part.len())?)
}

/// `part` borrowed from `src` when it lies inside it, else copied.
fn text_in<'a>(src: &'a str, part: &str) -> Text<'a> {
    match within(src, part) {
        Some(s) => Text::Borrowed(s),
        None => Text::Owned(Zeroizing::new(part.to_owned())),
    }
}

/// Whether `name` can be written back as an element or attribute name: not empty, and no markup,
/// whitespace or control characters (the writer writes names as they are).
fn writable_name(name: &str) -> bool {
    !name.is_empty()
        && !name.bytes().any(|b| {
            matches!(b, b'<' | b'>' | b'"' | b'\'' | b'=' | b'&' | b'/' | b'!' | b'?')
                || b.is_ascii_whitespace()
                || b < 0x20
        })
}

/// A `quick-xml` start tag, borrowing from the document.
fn start_tag<'a>(src: &'a str, e: &BytesStart<'_>) -> Result<Tag<'a>, OvError> {
    let outside = || err("an XML name outside the document");
    let qname = within(src, e.name().into_inner()).ok_or_else(outside)?;
    let name = within(src, e.local_name().into_inner()).ok_or_else(outside)?;
    // quick-xml takes `<>`, `< x="1">` and names full of markup; they couldn't be written back
    if !writable_name(name) {
        return Err(err("the XML has an element without a valid name"));
    }
    let mut attrs = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|e| err(format!("bad XML attribute: {e}")))?;
        let key =
            within(src, a.key.local_name().into_inner()).ok_or_else(|| err("an XML name outside the document"))?;
        if !writable_name(key) {
            return Err(err("the XML has an attribute without a valid name"));
        }
        // Kept by local name: `p:x` and `q:x` would be written back as two `x`
        if attrs.iter().any(|(k, _)| *k == key) {
            return Err(err("the XML has two attributes with the same local name"));
        }
        let value = a
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| err(format!("bad XML attribute: {e}")))?;
        if !value.chars().all(xml10_char) {
            return Err(err("an XML attribute holds a character XML 1.0 doesn't allow"));
        }
        let value = match value {
            Cow::Borrowed(v) => text_in(src, v),
            Cow::Owned(v) => Text::Owned(Zeroizing::new(v)),
        };
        attrs.push((key, value));
    }
    Ok(Tag { qname, name, attrs })
}

pub(crate) fn resolve_ref(name: &str) -> Result<char, OvError> {
    Ok(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let num = name.strip_prefix('#').ok_or_else(|| err(format!("unknown XML entity &{name};")))?;
            let code = match num.strip_prefix('x') {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => num.parse::<u32>(),
            }
            .map_err(|_| err(format!("bad XML character reference &{name};")))?;
            char::from_u32(code).ok_or_else(|| err(format!("bad XML character reference &{name};")))?
        }
    })
}

/// Parses `xml`. With a `stream`, protected values are decrypted in document order; without one,
/// a protected value is an error.
pub(crate) fn parse<'a>(xml: &'a str, mut stream: Option<&mut InnerStream>) -> Result<Node<'a>, OvError> {
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    // A document the fast path gives up on is read again from here, protected values included
    let start = stream.as_deref().map(InnerStream::position);
    let fast = super::fast::parse(xml, stream.as_deref_mut());
    #[cfg(test)]
    FAST_READS.with(|c| c.set(c.get() + u32::from(fast.is_some())));
    if let (Some(s), Some(p)) = (stream.as_deref_mut(), start) {
        if fast.is_none() || cfg!(any(test, fuzzing)) {
            s.seek(p);
        }
    }
    match fast {
        #[cfg(any(test, fuzzing))]
        Some(fast) => {
            // Whatever the fast path reads, quick-xml reads the same
            let slow = parse_quick_xml(xml, stream).expect("quick-xml reads what the fast path read");
            assert!(same_tree(&fast, &slow), "the fast path's tree differs from quick-xml's");
            Ok(fast)
        }
        #[cfg(not(any(test, fuzzing)))]
        Some(fast) => Ok(fast),
        None => parse_quick_xml(xml, stream),
    }
}

#[cfg(test)]
thread_local! {
    /// Documents this thread read on the fast path (tests check which ones fall back).
    pub(crate) static FAST_READS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Whether two trees are the same: names, attributes, text, decrypted bytes and children.
#[cfg(any(test, fuzzing))]
pub(crate) fn same_tree(a: &Node<'_>, b: &Node<'_>) -> bool {
    a.name == b.name
        && a.text.as_str() == b.text.as_str()
        && a.raw.as_deref() == b.raw.as_deref()
        && a.attrs.len() == b.attrs.len()
        && a.attrs.iter().zip(&b.attrs).all(|((ka, va), (kb, vb))| ka == kb && va.as_str() == vb.as_str())
        && a.children.len() == b.children.len()
        && a.children.iter().zip(&b.children).all(|(x, y)| same_tree(x, y))
}

/// [`parse`] with `quick-xml`'s pull reader (BOM already stripped).
pub(crate) fn parse_quick_xml<'a>(xml: &'a str, stream: Option<&mut InnerStream>) -> Result<Node<'a>, OvError> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut b = Builder::new(stream);
    let bad = |e: quick_xml::Error| err(format!("the XML is malformed: {e}"));
    loop {
        match reader.read_event().map_err(bad)? {
            Event::Start(e) => b.start(start_tag(xml, &e)?)?,
            Event::Empty(e) => b.empty(start_tag(xml, &e)?)?,
            Event::End(_) => b.end()?,
            Event::Text(t) => b.text(t.xml10_content()),
            Event::CData(t) => b.text(t.xml10_content()),
            Event::GeneralRef(r) => {
                if b.in_element() {
                    b.char(resolve_ref(&r)?);
                }
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
    b.finish()
}

// ---------------------------------------------------------------------------------------------
// Writing

/// Whether `c` may appear in an XML 1.0 document (KeePassXC strips the rest on save). Attribute
/// values holding others are refused on read: the writer would drop them, and `Protected="True\x01"`
/// would come back protected.
pub(crate) fn xml10_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// Escapes text content. `\r` becomes `&#13;` so line endings survive XML's normalisation.
#[cfg(any(test, fuzzing))]
fn escape(s: &str, attribute: bool) -> Cow<'_, str> {
    if !needs_escape(s, attribute) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    escape_slow(s, attribute, |p| out.push_str(p));
    Cow::Owned(out)
}

/// Whether `s` has anything [`escape_slow`] changes: markup characters, `\r`, in attributes also
/// `" \t \n`, and characters XML 1.0 doesn't allow (control characters, U+FFFE, U+FFFF; a `str`
/// has no surrogates). Byte by byte: those are ASCII but U+FFFE/U+FFFF (`EF BF BE`/`EF BF BF`).
fn needs_escape(s: &str, attribute: bool) -> bool {
    let b = s.as_bytes();
    b.iter().enumerate().any(|(i, &c)| match c {
        b'&' | b'<' | b'>' | b'\r' => true,
        b'"' | b'\t' | b'\n' => attribute,
        0..=0x1f => true,
        0xef => b.get(i + 1) == Some(&0xbf) && matches!(b.get(i + 2), Some(0xbe | 0xbf)),
        _ => false,
    })
}

/// The escaped text of `s`, in pieces.
fn escape_slow(s: &str, attribute: bool, mut put: impl FnMut(&str)) {
    let mut buf = [0u8; 4];
    for c in s.chars() {
        match c {
            '&' => put("&amp;"),
            '<' => put("&lt;"),
            '>' => put("&gt;"),
            '\r' => put("&#13;"),
            '"' if attribute => put("&quot;"),
            '\t' if attribute => put("&#9;"),
            '\n' if attribute => put("&#10;"),
            c if !xml10_char(c) => {}
            c => put(c.encode_utf8(&mut buf)),
        }
    }
}

/// An indenting XML writer that protects values through the inner stream in document order.
///
/// It writes what `quick-xml`'s indenting `Writer` wrote before (tab indents; a line break before
/// every tag except right after text), straight into one buffer that is wiped on drop and grown by
/// copying into a fresh wiped one, so no copy of the plaintext is left behind. Under `cfg(test)` it
/// (and `cfg(fuzzing)`) drives that `quick-xml` writer alongside and [`finish`](Self::finish)
/// asserts the same bytes.
pub(crate) struct XmlOut {
    buf: Zeroizing<Vec<u8>>,
    /// Where the XML starts in `buf` (after what the caller put there).
    #[cfg(any(test, fuzzing))]
    start: usize,
    depth: usize,
    /// The next tag starts on a new line (not right after text).
    line_break: bool,
    stream: InnerStream,
    #[cfg(any(test, fuzzing))]
    reference: reference::RefOut,
}

impl XmlOut {
    #[cfg(test)]
    pub(crate) fn new(stream: InnerStream) -> Result<Self, OvError> {
        Self::with_buffer(stream, Zeroizing::new(Vec::new()))
    }

    /// A writer that appends to `buf`.
    pub(crate) fn with_buffer(stream: InnerStream, buf: Zeroizing<Vec<u8>>) -> Result<Self, OvError> {
        let mut o = XmlOut {
            #[cfg(any(test, fuzzing))]
            start: buf.len(),
            buf,
            depth: 0,
            line_break: false,
            stream,
            #[cfg(any(test, fuzzing))]
            reference: reference::RefOut::new()?,
        };
        o.put(b"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>");
        o.line_break = true;
        Ok(o)
    }

    pub(crate) fn finish(mut self) -> Zeroizing<Vec<u8>> {
        self.put(b"\n");
        #[cfg(any(test, fuzzing))]
        assert!(self.buf[self.start..] == self.reference.finish()[..], "the XML differs from quick-xml's writer");
        self.buf
    }

    /// Room for `n` more bytes: a bigger buffer gets a copy and the old one is wiped.
    fn reserve(&mut self, n: usize) {
        if self.buf.capacity() - self.buf.len() < n {
            let cap = (self.buf.capacity() * 2).max(self.buf.len() + n).max(1 << 16);
            let mut grown = Zeroizing::new(Vec::with_capacity(cap));
            grown.extend_from_slice(&self.buf);
            self.buf = grown;
        }
    }

    fn put(&mut self, b: &[u8]) {
        self.reserve(b.len());
        self.buf.extend_from_slice(b);
    }

    fn put_escaped(&mut self, s: &str, attribute: bool) {
        if needs_escape(s, attribute) {
            let mut out = Zeroizing::new(String::with_capacity(s.len() + 8));
            escape_slow(s, attribute, |p| out.push_str(p));
            self.put(out.as_bytes());
        } else {
            self.put(s.as_bytes());
        }
    }

    fn indent(&mut self) {
        self.reserve(1 + self.depth);
        self.buf.push(b'\n');
        let depth = self.depth;
        self.buf.extend(std::iter::repeat_n(b'\t', depth));
    }

    fn tag(&mut self, name: &str, attrs: &[(&str, &str)], empty: bool) {
        if self.line_break {
            self.indent();
        }
        self.put(b"<");
        self.put(name.as_bytes());
        for (k, v) in attrs {
            self.put(b" ");
            self.put(k.as_bytes());
            self.put(b"=\"");
            self.put_escaped(v, true);
            self.put(b"\"");
        }
        self.put(if empty { b"/>" } else { b">" });
        self.line_break = true;
    }

    fn start(&mut self, name: &str, attrs: &[(&str, &str)]) {
        self.tag(name, attrs, false);
        self.depth += 1;
    }

    fn end(&mut self, name: &str) {
        self.depth = self.depth.saturating_sub(1);
        if self.line_break {
            self.indent();
        }
        self.put(b"</");
        self.put(name.as_bytes());
        self.put(b">");
        self.line_break = true;
    }

    pub(crate) fn open(&mut self, name: &str) -> Result<(), OvError> {
        self.open_with(name, &[])
    }

    pub(crate) fn open_with(&mut self, name: &str, attrs: &[(&str, &str)]) -> Result<(), OvError> {
        #[cfg(any(test, fuzzing))]
        self.reference.open_with(name, attrs)?;
        self.start(name, attrs);
        Ok(())
    }

    pub(crate) fn close(&mut self, name: &str) -> Result<(), OvError> {
        #[cfg(any(test, fuzzing))]
        self.reference.close(name)?;
        self.end(name);
        Ok(())
    }

    /// `<name attrs>text</name>`, or `<name attrs/>` when `text` is empty and not protected.
    /// With a `Protected="True"` attribute, `text` is encrypted and base64-encoded.
    pub(crate) fn leaf_with(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) -> Result<(), OvError> {
        let protected = attrs.iter().any(|(k, v)| *k == "Protected" && v.eq_ignore_ascii_case("true"));
        if protected {
            let mut raw = Zeroizing::new(text.as_bytes().to_vec());
            self.stream.apply(&mut raw);
            let b64 = B64.encode(&raw);
            #[cfg(any(test, fuzzing))]
            self.reference.text_element(name, attrs, &b64)?;
            self.text_element(name, attrs, &b64);
            return Ok(());
        }
        #[cfg(any(test, fuzzing))]
        self.reference.leaf_with(name, attrs, text)?;
        if text.is_empty() {
            self.tag(name, attrs, true);
        } else {
            self.text_element(name, attrs, text);
        }
        Ok(())
    }

    fn text_element(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) {
        self.start(name, attrs);
        self.put_escaped(text, false);
        self.line_break = false;
        self.end(name);
    }

    pub(crate) fn leaf(&mut self, name: &str, text: &str) -> Result<(), OvError> {
        self.leaf_with(name, &[], text)
    }

    /// Writes a passthrough element back: attributes, text, then children.
    pub(crate) fn element(&mut self, e: &XmlElement) -> Result<(), OvError> {
        let attrs: Vec<(&str, &str)> = e.attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        if e.children.is_empty() {
            return self.leaf_with(&e.name, &attrs, &e.text);
        }
        self.open_with(&e.name, &attrs)?;
        if !e.text.is_empty() {
            #[cfg(any(test, fuzzing))]
            self.reference.mixed_text(&e.text)?;
            // Text before the children, then a line break: they still start on their own line
            self.put_escaped(&e.text, false);
            self.line_break = false;
            self.indent();
        }
        for c in &e.children {
            self.element(c)?;
        }
        self.close(&e.name)
    }
}

/// The `quick-xml` writer the XML used to come from, for the byte-for-byte check.
#[cfg(any(test, fuzzing))]
mod reference {
    use super::*;

    /// A byte buffer that is wiped on drop.
    struct ZBuf(Zeroizing<Vec<u8>>);

    impl std::io::Write for ZBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn io(e: std::io::Error) -> OvError {
        err(format!("writing the XML failed: {e}"))
    }

    pub(super) struct RefOut {
        w: quick_xml::Writer<ZBuf>,
    }

    impl RefOut {
        pub(super) fn new() -> Result<Self, OvError> {
            let mut w = quick_xml::Writer::new_with_indent(ZBuf(Zeroizing::new(Vec::new())), b'\t', 1);
            w.write_event(Event::Decl(quick_xml::events::BytesDecl::new("1.0", Some("utf-8"), Some("yes"))))
                .map_err(io)?;
            Ok(RefOut { w })
        }

        pub(super) fn finish(self) -> Zeroizing<Vec<u8>> {
            let mut out = self.w.into_inner().0;
            out.push(b'\n');
            out
        }

        fn start_tag<'a>(name: &'a str, attrs: &[(&str, &str)]) -> BytesStart<'a> {
            let mut s = String::from(name);
            for (k, v) in attrs {
                s.push(' ');
                s.push_str(k);
                s.push_str("=\"");
                s.push_str(&escape(v, true));
                s.push('"');
            }
            BytesStart::from_content(s, name.len())
        }

        pub(super) fn open_with(&mut self, name: &str, attrs: &[(&str, &str)]) -> Result<(), OvError> {
            self.w.write_event(Event::Start(Self::start_tag(name, attrs))).map_err(io)
        }

        pub(super) fn close(&mut self, name: &str) -> Result<(), OvError> {
            self.w.write_event(Event::End(BytesEnd::new(name))).map_err(io)
        }

        pub(super) fn leaf_with(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) -> Result<(), OvError> {
            if text.is_empty() {
                return self.w.write_event(Event::Empty(Self::start_tag(name, attrs))).map_err(io);
            }
            self.text_element(name, attrs, text)
        }

        pub(super) fn text_element(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) -> Result<(), OvError> {
            self.w.write_event(Event::Start(Self::start_tag(name, attrs))).map_err(io)?;
            self.w.write_event(Event::Text(BytesText::from_escaped(escape(text, false)))).map_err(io)?;
            self.w.write_event(Event::End(BytesEnd::new(name))).map_err(io)
        }

        pub(super) fn mixed_text(&mut self, text: &str) -> Result<(), OvError> {
            self.w.write_event(Event::Text(BytesText::from_escaped(escape(text, false)))).map_err(io)?;
            self.w.write_indent().map_err(io)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_refs_and_mixed_content() {
        let n = parse(
            "<?xml version=\"1.0\"?>\n<A x=\"1&amp;2\">\n\t<B>a &lt;b&gt; &#13;&#x41;</B>\n\t<C/>mid<D> sp </D>\n</A>",
            None,
        )
        .unwrap();
        assert_eq!(n.name, "A");
        assert_eq!(n.attr("x"), Some("1&2"));
        assert_eq!(n.child("B").unwrap().text.as_str(), "a <b> \rA");
        assert_eq!(n.child("C").unwrap().text.as_str(), "");
        assert_eq!(n.child("D").unwrap().text.as_str(), " sp ");
        assert_eq!(n.text.as_str(), "mid");
    }

    #[test]
    fn writer_output_parses_back() {
        let stream = InnerStream::new(3, &[5; 64]).unwrap().unwrap();
        let mut w = XmlOut::new(stream).unwrap();
        let e = XmlElement {
            name: "Zz".into(),
            attributes: vec![("q".into(), "a\"b\tc".into())],
            text: "line1\r\nline2 <&>".into(),
            children: vec![XmlElement { name: "In".into(), text: " x ".into(), ..XmlElement::default() }],
        };
        w.open("Root").unwrap();
        w.element(&e).unwrap();
        w.leaf_with("P", &[("Protected", "True")], "sécret").unwrap();
        w.close("Root").unwrap();
        let bytes = w.finish();
        let mut s = InnerStream::new(3, &[5; 64]).unwrap().unwrap();
        let n = parse(std::str::from_utf8(&bytes).unwrap(), Some(&mut s)).unwrap();
        let back = n.children.into_iter().map(Node::into_element).collect::<Vec<_>>();
        assert_eq!(back[0], e);
        assert_eq!(back[1].text, "sécret");
    }
}
