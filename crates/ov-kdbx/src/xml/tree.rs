//! A small element tree over `quick-xml`'s pull reader, with `Protected="True"` values decrypted
//! through the inner random stream in document order, and an escaping writer on `quick-xml`'s
//! `Writer` that encrypts them again.

use std::borrow::Cow;

use base64::Engine as _;
use ov_error::OvError;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use zeroize::Zeroizing;

use crate::bytes::err;
use crate::crypto::InnerStream;
use crate::model::XmlElement;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Deeper documents are refused (groups recurse; this bounds the stack).
const MAX_DEPTH: usize = 512;

/// One element: name, attributes in order, text and children.
#[derive(Default)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) attrs: Vec<(String, String)>,
    /// Text content. For an element with children: the non-whitespace text around them, each run
    /// trimmed and concatenated. For a leaf: the text exactly. For a protected element: its clear
    /// text (UTF-8, lossy).
    pub(crate) text: Zeroizing<String>,
    /// For a protected element: its decrypted bytes.
    pub(crate) raw: Option<Zeroizing<Vec<u8>>>,
    pub(crate) children: Vec<Node>,
}

impl Node {
    pub(crate) fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub(crate) fn is_protected(&self) -> bool {
        self.attr("Protected").is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    /// The element as a model passthrough element.
    pub(crate) fn into_element(self) -> XmlElement {
        XmlElement {
            name: self.name,
            attributes: self.attrs,
            text: self.text.to_string(),
            children: self.children.into_iter().map(Node::into_element).collect(),
        }
    }
}

struct Frame {
    node: Node,
    seg: Zeroizing<String>,
}

impl Frame {
    /// Ends a text run at a child boundary: trimmed into `text`.
    fn flush_trimmed(&mut self) {
        let t = self.seg.trim();
        if !t.is_empty() {
            self.node.text.push_str(t);
        }
        self.seg.clear();
    }
}

fn start_node(e: &BytesStart<'_>) -> Result<Node, OvError> {
    let name = e.local_name().into_inner().to_owned();
    let mut attrs = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|e| err(format!("bad XML attribute: {e}")))?;
        let key = a.key.local_name().into_inner().to_owned();
        let value =
            a.normalized_value(quick_xml::XmlVersion::Implicit1_0).map_err(|e| err(format!("bad XML attribute: {e}")))?;
        attrs.push((key, value.into_owned()));
    }
    Ok(Node { name, attrs, ..Node::default() })
}

fn resolve_ref(name: &str) -> Result<char, OvError> {
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
pub(crate) fn parse(xml: &str, mut stream: Option<&mut InnerStream>) -> Result<Node, OvError> {
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Node> = None;
    let bad = |e: quick_xml::Error| err(format!("the XML is malformed: {e}"));

    let mut finish = |stack: &mut Vec<Frame>, root: &mut Option<Node>, mut f: Frame| -> Result<(), OvError> {
        if f.node.children.is_empty() {
            f.node.text = std::mem::take(&mut f.seg);
        } else {
            f.flush_trimmed();
        }
        if f.node.is_protected() {
            let s = stream.as_deref_mut().ok_or_else(|| err("a protected value but no inner stream"))?;
            let cleaned: Zeroizing<String> = Zeroizing::new(f.node.text.chars().filter(|c| !c.is_whitespace()).collect());
            let mut raw = Zeroizing::new(B64.decode(cleaned.as_bytes()).map_err(|_| err("a protected value isn't base64"))?);
            s.apply(&mut raw);
            f.node.text = Zeroizing::new(String::from_utf8_lossy(&raw).into_owned());
            f.node.raw = Some(raw);
        }
        match stack.last_mut() {
            Some(parent) => parent.node.children.push(f.node),
            None => *root = Some(f.node),
        }
        Ok(())
    };

    loop {
        match reader.read_event().map_err(bad)? {
            Event::Start(e) => {
                if root.is_some() {
                    return Err(err("the XML has more than one root element"));
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(err("the XML is nested too deeply"));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.flush_trimmed();
                }
                stack.push(Frame { node: start_node(&e)?, seg: Zeroizing::new(String::new()) });
            }
            Event::Empty(e) => {
                if root.is_some() {
                    return Err(err("the XML has more than one root element"));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.flush_trimmed();
                }
                let f = Frame { node: start_node(&e)?, seg: Zeroizing::new(String::new()) };
                finish(&mut stack, &mut root, f)?;
            }
            Event::End(_) => {
                let f = stack.pop().ok_or_else(|| err("the XML has an unmatched end tag"))?;
                finish(&mut stack, &mut root, f)?;
            }
            Event::Text(t) => {
                if let Some(f) = stack.last_mut() {
                    f.seg.push_str(&t.xml10_content());
                }
            }
            Event::CData(t) => {
                if let Some(f) = stack.last_mut() {
                    f.seg.push_str(&t.xml10_content());
                }
            }
            Event::GeneralRef(r) => {
                if let Some(f) = stack.last_mut() {
                    f.seg.push(resolve_ref(&r)?);
                }
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
    if !stack.is_empty() {
        return Err(err("the XML ends inside an element"));
    }
    root.ok_or_else(|| err("the XML has no root element"))
}

// ---------------------------------------------------------------------------------------------
// Writing

/// Whether `c` may appear in an XML 1.0 document (KeePassXC strips the rest on save).
fn xml10_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// Escapes text content. `\r` becomes `&#13;` so line endings survive XML's normalisation.
fn escape(s: &str, attribute: bool) -> Cow<'_, str> {
    let needs = s.chars().any(|c| {
        matches!(c, '&' | '<' | '>' | '\r') || !xml10_char(c) || (attribute && matches!(c, '"' | '\t' | '\n'))
    });
    if !needs {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            '"' if attribute => out.push_str("&quot;"),
            '\t' if attribute => out.push_str("&#9;"),
            '\n' if attribute => out.push_str("&#10;"),
            c if !xml10_char(c) => {}
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

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

/// An indenting XML writer that protects values through the inner stream in document order.
pub(crate) struct XmlOut {
    w: quick_xml::Writer<ZBuf>,
    stream: InnerStream,
}

fn io(e: std::io::Error) -> OvError {
    err(format!("writing the XML failed: {e}"))
}

impl XmlOut {
    pub(crate) fn new(stream: InnerStream) -> Result<Self, OvError> {
        let mut w = quick_xml::Writer::new_with_indent(ZBuf(Zeroizing::new(Vec::new())), b'\t', 1);
        w.write_event(Event::Decl(quick_xml::events::BytesDecl::new("1.0", Some("utf-8"), Some("yes")))).map_err(io)?;
        Ok(XmlOut { w, stream })
    }

    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
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

    pub(crate) fn open(&mut self, name: &str) -> Result<(), OvError> {
        self.open_with(name, &[])
    }

    pub(crate) fn open_with(&mut self, name: &str, attrs: &[(&str, &str)]) -> Result<(), OvError> {
        self.w.write_event(Event::Start(Self::start_tag(name, attrs))).map_err(io)
    }

    pub(crate) fn close(&mut self, name: &str) -> Result<(), OvError> {
        self.w.write_event(Event::End(BytesEnd::new(name))).map_err(io)
    }

    /// `<name attrs>text</name>`, or `<name attrs/>` when `text` is empty and not protected.
    /// With a `Protected="True"` attribute, `text` is encrypted and base64-encoded.
    pub(crate) fn leaf_with(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) -> Result<(), OvError> {
        let protected = attrs.iter().any(|(k, v)| *k == "Protected" && v.eq_ignore_ascii_case("true"));
        if protected {
            let mut raw = Zeroizing::new(text.as_bytes().to_vec());
            self.stream.apply(&mut raw);
            let b64 = B64.encode(&raw);
            return self.text_element(name, attrs, &b64);
        }
        if text.is_empty() {
            return self.w.write_event(Event::Empty(Self::start_tag(name, attrs))).map_err(io);
        }
        self.text_element(name, attrs, text)
    }

    fn text_element(&mut self, name: &str, attrs: &[(&str, &str)], text: &str) -> Result<(), OvError> {
        self.w.write_event(Event::Start(Self::start_tag(name, attrs))).map_err(io)?;
        self.w.write_event(Event::Text(BytesText::from_escaped(escape(text, false)))).map_err(io)?;
        self.w.write_event(Event::End(BytesEnd::new(name))).map_err(io)
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
            self.w.write_event(Event::Text(BytesText::from_escaped(escape(&e.text, false)))).map_err(io)?;
            self.w.write_indent().map_err(io)?;
        }
        for c in &e.children {
            self.element(c)?;
        }
        self.close(&e.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_refs_and_mixed_content() {
        let n = parse("<?xml version=\"1.0\"?>\n<A x=\"1&amp;2\">\n\t<B>a &lt;b&gt; &#13;&#x41;</B>\n\t<C/>mid<D> sp </D>\n</A>", None)
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
