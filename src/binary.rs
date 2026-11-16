//! WhatsApp binary nodes, ported from Baileys WABinary (MIT).
use crate::{jid, tokens};
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub tag: String,
    /// Ordered to preserve JavaScript's serialized attribute order.
    pub attrs: Vec<(String, String)>,
    pub content: Option<Content>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Text(String),
    Bytes(Vec<u8>),
    Nodes(Vec<Node>),
}
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_depth: 128,
            max_nodes: 65535,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

struct Writer {
    out: Vec<u8>,
    limits: Limits,
    nodes: usize,
}
impl Writer {
    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.limits.max_bytes.saturating_sub(self.out.len()) {
            return Err(Error("byte limit"));
        }
        self.out.extend_from_slice(bytes);
        Ok(())
    }
    fn length(&mut self, len: usize) -> Result<()> {
        if len > u32::MAX as usize {
            return Err(Error("string too large"));
        }
        if len < 256 {
            self.bytes(&[252, len as u8])
        } else if len < 1 << 20 {
            self.bytes(&[253, ((len >> 16) & 15) as u8, (len >> 8) as u8, len as u8])
        } else {
            self.bytes(&[254])?;
            self.bytes(&(len as u32).to_be_bytes())
        }
    }
    fn raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.length(bytes.len())?;
        self.bytes(bytes)
    }
    fn list(&mut self, n: usize) -> Result<()> {
        if n == 0 {
            self.bytes(&[0])
        } else if n < 256 {
            self.bytes(&[248, n as u8])
        } else if n <= u16::MAX as usize {
            self.bytes(&[249])?;
            self.bytes(&(n as u16).to_be_bytes())
        } else {
            Err(Error("list too large"))
        }
    }
    fn string(&mut self, s: &str, depth: usize) -> Result<()> {
        if depth > self.limits.max_depth {
            return Err(Error("depth limit"));
        }
        if s.is_empty() {
            return self.raw(&[]);
        }
        if let Some((dict, index)) = tokens::token(s) {
            if let Some(d) = dict {
                self.bytes(&[236 + d])?;
            }
            return self.bytes(&[index]);
        }
        let nibble = s.len() <= 127
            && s.bytes()
                .all(|b| b.is_ascii_digit() || b == b'-' || b == b'.');
        let hex = s.len() <= 127
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b));
        if nibble || hex {
            let n = s.len().div_ceil(2) as u8 | if s.len() % 2 == 1 { 128 } else { 0 };
            self.bytes(&[if nibble { 255 } else { 251 }, n])?;
            let pack = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'-' => 10,
                b'.' => 11,
                b'A'..=b'F' => b - b'A' + 10,
                _ => 15,
            };
            for pair in s.as_bytes().chunks(2) {
                self.bytes(&[(pack(pair[0]) << 4) | pair.get(1).map(|b| pack(*b)).unwrap_or(15)])?;
            }
            return Ok(());
        }
        if let Ok(j) = jid::jid_decode(s) {
            if let Some(d) = j.device {
                self.bytes(&[247, j.domain_type as u8, d as u8])?;
                self.string(j.user, depth + 1)?;
            } else {
                self.bytes(&[250])?;
                if j.user.is_empty() {
                    self.bytes(&[0])?;
                } else {
                    self.string(j.user, depth + 1)?;
                }
                self.string(j.server, depth + 1)?;
            }
            return Ok(());
        }
        self.raw(s.as_bytes())
    }
    fn node(&mut self, n: &Node, depth: usize) -> Result<()> {
        if n.tag.is_empty() {
            return Err(Error("empty node tag"));
        }
        if depth > self.limits.max_depth || self.nodes >= self.limits.max_nodes {
            return Err(Error("node/depth limit"));
        }
        self.nodes += 1;
        self.list(
            n.attrs
                .len()
                .checked_mul(2)
                .and_then(|size| size.checked_add(1 + usize::from(n.content.is_some())))
                .unwrap_or(usize::MAX),
        )?;
        self.string(&n.tag, 0)?;
        for (k, v) in &n.attrs {
            self.string(k, 0)?;
            self.string(v, 0)?;
        }
        match &n.content {
            None => Ok(()),
            Some(Content::Text(s)) => self.string(s, 0),
            Some(Content::Bytes(b)) => self.raw(b),
            Some(Content::Nodes(children)) => {
                self.list(children.len())?;
                for child in children {
                    self.node(child, depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

pub fn encode(node: &Node) -> Result<Vec<u8>> {
    encode_with_limits(node, Limits::default())
}
pub fn encode_with_limits(node: &Node, limits: Limits) -> Result<Vec<u8>> {
    let mut w = Writer {
        out: Vec::new(),
        limits,
        nodes: 0,
    };
    w.bytes(&[0])?;
    w.node(node, 0)?;
    Ok(w.out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    limits: Limits,
    nodes: usize,
}
impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(len).ok_or(Error("length overflow"))?;
        let b = self
            .bytes
            .get(self.pos..end)
            .ok_or(Error("end of stream"))?;
        self.pos = end;
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn integer(&mut self, n: usize) -> Result<usize> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0, |v, b| (v << 8) | usize::from(*b)))
    }
    fn list(&mut self, tag: u8) -> Result<usize> {
        match tag {
            0 => Ok(0),
            248 => self.integer(1),
            249 => self.integer(2),
            _ => Err(Error("invalid list tag")),
        }
    }
    fn length(&mut self, tag: u8) -> Result<usize> {
        match tag {
            252 => self.integer(1),
            253 => Ok(self.integer(3)? & 0xfffff),
            254 => self.integer(4),
            _ => Err(Error("invalid length tag")),
        }
    }
    fn string(&mut self, tag: u8, depth: usize) -> Result<String> {
        if depth > self.limits.max_depth {
            return Err(Error("depth limit"));
        }
        if tag >= 1 && usize::from(tag) < tokens::SINGLE.len() {
            return Ok(tokens::SINGLE[usize::from(tag)].to_owned());
        }
        match tag {
            0 => Ok(String::new()),
            236..=239 => {
                let i = usize::from(self.byte()?);
                tokens::DOUBLE
                    .get(usize::from(tag - 236))
                    .and_then(|d| d.get(i))
                    .map(|s| s.to_string())
                    .ok_or(Error("invalid dictionary token"))
            }
            252..=254 => {
                let n = self.length(tag)?;
                Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
            }
            250 => {
                let t = self.byte()?;
                let user = self.string(t, depth + 1)?;
                let t = self.byte()?;
                let server = self.string(t, depth + 1)?;
                if server.is_empty() {
                    return Err(Error("invalid jid pair"));
                }
                Ok(format!("{user}@{server}"))
            }
            247 => {
                let domain = self.byte()?;
                let device = self.byte()?;
                let t = self.byte()?;
                let user = self.string(t, depth + 1)?;
                let server =
                    jid::get_server_from_domain_type("s.whatsapp.net", Some(u32::from(domain)));
                Ok(jid::jid_encode(
                    &user,
                    server,
                    Some(u32::from(device)),
                    None,
                ))
            }
            246 => {
                let t = self.byte()?;
                let user = self.string(t, depth + 1)?;
                let device = self.integer(2)?;
                let t = self.byte()?;
                let server = self.string(t, depth + 1)?;
                Ok(format!("{user}:{device}@{server}"))
            }
            245 => {
                let t = self.byte()?;
                let user = self.string(t, depth + 1)?;
                let device = self.integer(2)?;
                let integrator = self.integer(2)?;
                let before = self.pos;
                let server = (|| {
                    let t = self.byte()?;
                    self.string(t, depth + 1)
                })();
                let server = server.unwrap_or_else(|_| {
                    self.pos = before;
                    "interop".into()
                });
                Ok(format!("{integrator}-{user}:{device}@{server}"))
            }
            251 | 255 => {
                let start = self.byte()?;
                let n = usize::from(start & 127);
                let mut out = Vec::with_capacity(n * 2);
                for b in self.take(n)? {
                    for nib in [b >> 4, b & 15] {
                        out.push(if tag == 251 {
                            b"0123456789ABCDEF"[usize::from(nib)]
                        } else {
                            match nib {
                                0..=9 => b'0' + nib,
                                10 => b'-',
                                11 => b'.',
                                15 => 0,
                                _ => return Err(Error("invalid nibble")),
                            }
                        });
                    }
                }
                if start & 128 != 0 {
                    out.pop();
                }
                Ok(String::from_utf8(out).map_err(|_| Error("invalid packed string"))?)
            }
            _ => Err(Error("invalid string tag")),
        }
    }
    fn node(&mut self, depth: usize) -> Result<Node> {
        if depth > self.limits.max_depth || self.nodes >= self.limits.max_nodes {
            return Err(Error("node/depth limit"));
        }
        self.nodes += 1;
        let t = self.byte()?;
        let size = self.list(t)?;
        let t = self.byte()?;
        let tag = self.string(t, 0)?;
        if size == 0 || tag.is_empty() {
            return Err(Error("invalid node"));
        }
        let mut attrs = Vec::new();
        for _ in 0..((size - 1) / 2) {
            let t = self.byte()?;
            let k = self.string(t, 0)?;
            let t = self.byte()?;
            let v = self.string(t, 0)?;
            if let Some((_, value)) = attrs.iter_mut().find(|(key, _)| key == &k) {
                *value = v;
            } else {
                attrs.push((k, v));
            }
        }
        let content = if size % 2 == 0 {
            let t = self.byte()?;
            Some(match t {
                0 | 248 | 249 => {
                    let n = self.list(t)?;
                    if n > self.limits.max_nodes.saturating_sub(self.nodes) {
                        return Err(Error("node limit"));
                    }
                    let mut children = Vec::new();
                    for _ in 0..n {
                        children.push(self.node(depth + 1)?);
                    }
                    Content::Nodes(children)
                }
                252..=254 => {
                    let n = self.length(t)?;
                    Content::Bytes(self.take(n)?.to_vec())
                }
                _ => Content::Text(self.string(t, 0)?),
            })
        } else {
            None
        };
        Ok(Node {
            tag,
            attrs,
            content,
        })
    }
}

/// Decode one uncompressed node; the cursor can be used for concatenated nodes.
pub fn decode_decompressed(bytes: &[u8], cursor: &mut usize, limits: Limits) -> Result<Node> {
    if bytes.len() > limits.max_bytes {
        return Err(Error("byte limit"));
    }
    let mut r = Reader {
        bytes,
        pos: *cursor,
        limits,
        nodes: 0,
    };
    let result = r.node(0);
    *cursor = r.pos;
    result
}
pub fn decode(frame: &[u8]) -> Result<Node> {
    decode_with_limits(frame, Limits::default())
}
pub fn decode_with_limits(frame: &[u8], limits: Limits) -> Result<Node> {
    if frame.len() > limits.max_bytes {
        return Err(Error("byte limit"));
    }
    let (&flags, payload) = frame.split_first().ok_or(Error("empty frame"))?;
    if flags & 2 != 0 {
        let decoder = flate2::read::ZlibDecoder::new(payload);
        let mut bytes = Vec::new();
        decoder
            .take((limits.max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| Error("invalid compressed frame"))?;
        if bytes.len() > limits.max_bytes {
            return Err(Error("decompressed byte limit"));
        }
        decode_decompressed(&bytes, &mut 0, limits)
    } else {
        decode_decompressed(payload, &mut 0, limits)
    }
}
