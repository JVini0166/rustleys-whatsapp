//! USync queries/protocols ported from pinned Baileys WAUSync (MIT).
//! Dates in dynamic protocol results are Unix milliseconds, not JS Date objects.
use crate::{
    binary::{Content, Node},
    prekeys::Query as Endpoint,
    socket,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NoProtocols,
    InvalidSid,
    Limit,
    InvalidBotProfile,
    Randomness,
    IdExhausted,
    Timeout,
    Server(Option<i64>),
    Network(socket::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "USync: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Option<String>,
    pub lid: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub username_key: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub persona_id: Option<String>,
}
impl User {
    pub fn with_id(mut self, v: impl Into<String>) -> Self {
        self.id = Some(v.into());
        self
    }
    pub fn with_lid(mut self, v: impl Into<String>) -> Self {
        self.lid = Some(v.into());
        self
    }
    pub fn with_phone(mut self, v: impl Into<String>) -> Self {
        self.phone = Some(v.into());
        self
    }
    pub fn with_username(mut self, v: impl Into<String>) -> Self {
        self.username = Some(v.into());
        self
    }
    pub fn with_username_key(mut self, v: impl Into<String>) -> Self {
        self.username_key = Some(v.into());
        self
    }
    pub fn with_type(mut self, v: impl Into<String>) -> Self {
        self.kind = Some(v.into());
        self
    }
    pub fn with_persona_id(mut self, v: impl Into<String>) -> Self {
        self.persona_id = Some(v.into());
        self
    }
}
pub trait Protocol: Send + Sync {
    fn name(&self) -> &str;
    fn query_element(&self) -> Node;
    fn user_element(&self, user: &User) -> Option<Node>;
    /// None and JSON null omit the field, as upstream's null parser result does.
    fn parse(&self, node: &Node) -> Result<Option<Value>>;
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Builtin {
    Contact,
    Devices,
    Status,
    DisappearingMode,
    Bot,
    Lid,
    Username,
}
fn node(tag: &str, attrs: Vec<(&str, String)>, content: Option<Content>) -> Node {
    Node {
        tag: tag.into(),
        attrs: attrs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        content,
    }
}
fn attr<'a>(n: &'a Node, name: &str) -> Option<&'a str> {
    n.attrs
        .iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}
fn nodes(n: &Node) -> &[Node] {
    match &n.content {
        Some(Content::Nodes(c)) => c,
        _ => &[],
    }
}
fn child<'a>(n: &'a Node, tag: &str) -> Option<&'a Node> {
    nodes(n).iter().find(|n| n.tag == tag)
}
fn text(n: &Node) -> Option<String> {
    match &n.content {
        Some(Content::Text(s)) => Some(s.clone()),
        Some(Content::Bytes(b)) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    }
}
fn truthy(v: Option<&str>) -> Option<&str> {
    v.filter(|s| !s.is_empty())
}
fn error_free(n: &Node) -> Result<()> {
    if let Some(e) = child(n, "error") {
        Err(Error::Server(number(attr(e, "code")).as_i64()))
    } else {
        Ok(())
    }
}
// JS unary-plus on protocol string attributes, including missing=>NaN. Invalid
// and nonfinite values normalize to JSON null, matching JSON.stringify's result.
// Correctly round power-of-two integer strings once, rather than accumulating
// rounded f64 multiply/add steps (which diverges from JS Number for long keys).
fn radix_number(digits: &str, radix: u32) -> f64 {
    if digits.is_empty() {
        return f64::NAN;
    }
    let width = radix.trailing_zeros();
    let (mut bits, mut leading, mut guard, mut sticky) = (0usize, 0u64, false, false);
    for c in digits.chars() {
        let Some(digit) = c.to_digit(radix) else {
            return f64::NAN;
        };
        for shift in (0..width).rev() {
            let bit = digit >> shift & 1;
            if bits == 0 && bit == 0 {
                continue;
            }
            bits += 1;
            if bits <= 53 {
                leading = leading << 1 | u64::from(bit);
            } else if bits == 54 {
                guard = bit != 0;
            } else {
                sticky |= bit != 0;
            }
        }
    }
    if bits <= 53 {
        return leading as f64;
    }
    if bits > 1024 {
        return f64::INFINITY;
    }
    if guard && (sticky || leading & 1 != 0) {
        leading += 1;
    }
    leading as f64 * 2.0_f64.powi(bits as i32 - 53)
}
fn number(v: Option<&str>) -> Value {
    let Some(s) = v else { return Value::Null };
    let s = s.trim_matches(|c: char| matches!(c, '\u{9}'..='\u{d}' | '\u{20}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'));
    let value = if s.is_empty() {
        0.0
    } else if let Some((digits, radix)) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map(|s| (s, 16))
        .or_else(|| {
            s.strip_prefix("0b")
                .or_else(|| s.strip_prefix("0B"))
                .map(|s| (s, 2))
        })
        .or_else(|| {
            s.strip_prefix("0o")
                .or_else(|| s.strip_prefix("0O"))
                .map(|s| (s, 8))
        })
    {
        radix_number(digits, radix)
    } else {
        s.parse::<f64>().unwrap_or(f64::NAN)
    };
    if !value.is_finite() {
        Value::Null
    } else if value == 0.0 {
        json!(0)
    } else if value >= i64::MIN as f64 && value < i64::MAX as f64 && value.fract() == 0.0 {
        json!(value as i64)
    } else {
        json!(value)
    }
}
fn date(v: Option<&str>) -> Value {
    let n = number(Some(truthy(v).unwrap_or("0")))
        .as_f64()
        .map(|n| (n * 1000.0).trunc());
    n.filter(|n| n.abs() <= 8_640_000_000_000_000.0)
        .map_or(Value::Null, |n| json!(n as i64))
}
fn insert_text(map: &mut Map<String, Value>, key: &str, parent: Option<&Node>, tag: &str) {
    if let Some(v) = parent.and_then(|p| child(p, tag)).and_then(text) {
        map.insert(key.into(), json!(v));
    }
}
impl Protocol for Builtin {
    fn name(&self) -> &str {
        match self {
            Self::Contact => "contact",
            Self::Devices => "devices",
            Self::Status => "status",
            Self::DisappearingMode => "disappearing_mode",
            Self::Bot => "bot",
            Self::Lid => "lid",
            Self::Username => "username",
        }
    }
    fn query_element(&self) -> Node {
        match self {
            Self::Devices => node(self.name(), vec![("version", "2".into())], None),
            Self::Bot => node(
                "bot",
                vec![],
                Some(Content::Nodes(vec![node(
                    "profile",
                    vec![("v", "1".into())],
                    None,
                )])),
            ),
            _ => node(self.name(), vec![], None),
        }
    }
    fn user_element(&self, u: &User) -> Option<Node> {
        match self {
            Self::Contact => Some(if let Some(phone) = truthy(u.phone.as_deref()) {
                node("contact", vec![], Some(Content::Text(phone.into())))
            } else if let Some(username) = truthy(u.username.as_deref()) {
                let mut attrs = vec![("username", username.into())];
                if let Some(pin) = truthy(u.username_key.as_deref()) {
                    attrs.push(("pin", pin.into()));
                }
                if let Some(lid) = truthy(u.lid.as_deref()) {
                    attrs.push(("lid", lid.into()));
                }
                node("contact", attrs, None)
            } else {
                node(
                    "contact",
                    truthy(u.kind.as_deref())
                        .map(|v| vec![("type", v.into())])
                        .unwrap_or_default(),
                    None,
                )
            }),
            Self::Lid => {
                truthy(u.lid.as_deref()).map(|lid| node("lid", vec![("jid", lid.into())], None))
            }
            Self::Bot => Some(node(
                "bot",
                vec![],
                Some(Content::Nodes(vec![node(
                    "profile",
                    u.persona_id
                        .as_ref()
                        .map(|p| vec![("persona_id", p.clone())])
                        .unwrap_or_default(),
                    None,
                )])),
            )),
            _ => None,
        }
    }
    fn parse(&self, n: &Node) -> Result<Option<Value>> {
        bound(n, Limits::default())?;
        if !matches!(self, Self::Bot) && n.tag != self.name() {
            return Ok(match self {
                Self::Contact => Some(json!(false)),
                Self::Devices => Some(json!({"deviceList":[]})),
                _ => None,
            });
        }
        if !matches!(self, Self::Bot | Self::Lid) {
            error_free(n)?;
        }
        Ok(match self {
            Self::Contact => Some(json!(attr(n, "type") == Some("in"))),
            Self::Lid => attr(n, "val").map(|s| json!(s)),
            Self::Username => {
                if let Some(Content::Text(s)) = &n.content {
                    Some(json!(s))
                } else {
                    None
                }
            }
            Self::Status => {
                let status = text(n).filter(|s| !s.is_empty()).map_or_else(
                    || {
                        if number(attr(n, "code")) == json!(401) {
                            json!("")
                        } else {
                            Value::Null
                        }
                    },
                    |s| json!(s),
                );
                Some(json!({"status":status,"setAt":date(attr(n,"t"))}))
            }
            Self::DisappearingMode => {
                Some(json!({"duration":number(attr(n,"duration")),"setAt":date(attr(n,"t"))}))
            }
            Self::Devices => {
                let devices=child(n,"device-list").map(nodes).unwrap_or_default().iter().filter(|c|c.tag=="device").map(|c|json!({"id":number(attr(c,"id")),"keyIndex":number(attr(c,"key-index")),"isHosted":attr(c,"is_hosted")==Some("true")})).collect::<Vec<_>>();
                let mut out = json!({"deviceList":devices});
                if let Some(key) = child(n, "key-index-list") {
                    let mut value = json!({"timestamp":number(attr(key,"ts"))});
                    if let Some(Content::Bytes(bytes)) = &key.content {
                        value["signedKeyIndex"] = json!(bytes);
                    } else if let Some(Content::Text(s)) = &key.content {
                        value["signedKeyIndex"] = json!(s);
                    }
                    if let Some(t) = truthy(attr(key, "expected_ts")) {
                        value["expectedTimestamp"] = number(Some(t));
                    }
                    out["keyIndex"] = value;
                }
                Some(out)
            }
            Self::Bot => {
                // The pinned parser looks for bot/profile inside its input, even
                // when USyncQuery has already selected a child tagged bot.
                let profile = child(n, "bot")
                    .and_then(|b| child(b, "profile"))
                    .ok_or(Error::InvalidBotProfile)?;
                let commands = child(profile, "commands");
                let prompts = child(profile, "prompts");
                let mut out = Map::new();
                out.insert(
                    "isDefault".into(),
                    json!(child(profile, "default").is_some()),
                );
                if let Some(jid) = attr(n, "jid") {
                    out.insert("jid".into(), json!(jid));
                }
                for key in ["name", "attributes", "description", "category"] {
                    insert_text(&mut out, key, Some(profile), key);
                }
                if let Some(persona) = attr(profile, "persona_id") {
                    out.insert("personaId".into(), json!(persona));
                }
                insert_text(&mut out, "commandsDescription", commands, "description");
                out.insert(
                    "commands".into(),
                    Value::Array(
                        commands
                            .map(nodes)
                            .unwrap_or_default()
                            .iter()
                            .filter(|c| c.tag == "command")
                            .map(|c| {
                                let mut m = Map::new();
                                insert_text(&mut m, "name", Some(c), "name");
                                insert_text(&mut m, "description", Some(c), "description");
                                Value::Object(m)
                            })
                            .collect(),
                    ),
                );
                out.insert(
                    "prompts".into(),
                    Value::Array(
                        prompts
                            .map(nodes)
                            .unwrap_or_default()
                            .iter()
                            .filter(|c| c.tag == "prompt")
                            .map(|c| {
                                json!(format!(
                                    "{} {}",
                                    child(c, "emoji")
                                        .and_then(text)
                                        .unwrap_or("undefined".into()),
                                    child(c, "text")
                                        .and_then(text)
                                        .unwrap_or("undefined".into())
                                ))
                            })
                            .collect(),
                    ),
                );
                Some(Value::Object(out))
            }
        })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_users: usize,
    pub max_protocols: usize,
    pub max_nodes: usize,
    pub max_attributes: usize,
    pub max_bytes: usize,
    pub max_depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_users: 8192,
            max_protocols: 32,
            max_nodes: 65535,
            max_attributes: 65535,
            max_bytes: 16 * 1024 * 1024,
            max_depth: 128,
        }
    }
}
fn bound(root: &Node, l: Limits) -> Result<(usize, usize, usize)> {
    let mut stack = vec![(root, 0usize)];
    let (mut count, mut bytes, mut attributes) = (0usize, 0usize, 0usize);
    while let Some((n, depth)) = stack.pop() {
        count = count.checked_add(1).ok_or(Error::Limit)?;
        if count > l.max_nodes || depth > l.max_depth {
            return Err(Error::Limit);
        }
        bytes = bytes.checked_add(n.tag.len()).ok_or(Error::Limit)?;
        attributes = attributes.checked_add(n.attrs.len()).ok_or(Error::Limit)?;
        if attributes > l.max_attributes {
            return Err(Error::Limit);
        }
        for (k, v) in &n.attrs {
            bytes = bytes
                .checked_add(k.len())
                .and_then(|b| b.checked_add(v.len()))
                .ok_or(Error::Limit)?;
        }
        match &n.content {
            Some(Content::Nodes(children)) => {
                if children.len() > l.max_nodes.saturating_sub(count)
                    || stack.len() > l.max_nodes.saturating_sub(count + children.len())
                {
                    return Err(Error::Limit);
                }
                stack.extend(children.iter().map(|c| (c, depth + 1)));
            }
            Some(Content::Text(s)) => bytes = bytes.checked_add(s.len()).ok_or(Error::Limit)?,
            Some(Content::Bytes(b)) => bytes = bytes.checked_add(b.len()).ok_or(Error::Limit)?,
            None => {}
        }
        if bytes > l.max_bytes {
            return Err(Error::Limit);
        }
    }
    Ok((count, bytes, attributes))
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Row {
    #[serde(flatten)]
    pub data: Map<String, Value>,
    pub id: String,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult {
    pub list: Vec<Row>,
    pub side_list: Vec<Row>,
}
pub struct Query {
    pub users: Vec<User>,
    pub context: String,
    pub mode: String,
    pub limits: Limits,
    protocols: Vec<Arc<dyn Protocol>>,
}
impl Default for Query {
    fn default() -> Self {
        Self {
            users: vec![],
            context: "interactive".into(),
            mode: "query".into(),
            limits: Limits::default(),
            protocols: vec![],
        }
    }
}
impl Query {
    pub fn with_mode(mut self, v: impl Into<String>) -> Self {
        self.mode = v.into();
        self
    }
    pub fn with_context(mut self, v: impl Into<String>) -> Self {
        self.context = v.into();
        self
    }
    pub fn with_user(mut self, u: User) -> Self {
        self.users.push(u);
        self
    }
    pub fn with_protocol(mut self, p: impl Protocol + 'static) -> Self {
        self.protocols.push(Arc::new(p));
        self
    }
    pub fn build(&self, sid: &str) -> Result<Node> {
        if self.protocols.is_empty() {
            return Err(Error::NoProtocols);
        }
        if sid.is_empty() || sid.len() > 1024 {
            return Err(Error::InvalidSid);
        }
        if self.users.len() > self.limits.max_users
            || self.protocols.len() > self.limits.max_protocols
        {
            return Err(Error::Limit);
        }
        if self
            .context
            .len()
            .saturating_add(self.mode.len())
            .saturating_add(sid.len())
            > self.limits.max_bytes
        {
            return Err(Error::Limit);
        }
        for u in &self.users {
            for field in [
                &u.id,
                &u.lid,
                &u.phone,
                &u.username,
                &u.username_key,
                &u.kind,
                &u.persona_id,
            ]
            .into_iter()
            .flatten()
            {
                if field.len() > self.limits.max_bytes {
                    return Err(Error::Limit);
                }
            }
        }
        // Charge each newly built fragment before retaining it. Repeated
        // protocols/large phone fields cannot multiply the entire request in
        // memory before the final bound detects an oversized aggregate.
        let mut totals = (0usize, 0usize, 0usize);
        let mut charge = |n: &Node| -> Result<()> {
            let cost = bound(n, self.limits)?;
            totals.0 = totals.0.checked_add(cost.0).ok_or(Error::Limit)?;
            totals.1 = totals.1.checked_add(cost.1).ok_or(Error::Limit)?;
            totals.2 = totals.2.checked_add(cost.2).ok_or(Error::Limit)?;
            if totals.0 > self.limits.max_nodes
                || totals.1 > self.limits.max_bytes
                || totals.2 > self.limits.max_attributes
            {
                return Err(Error::Limit);
            }
            Ok(())
        };
        let mut root = node(
            "iq",
            vec![
                ("to", crate::jid::S_WHATSAPP_NET.into()),
                ("type", "get".into()),
                ("xmlns", "usync".into()),
            ],
            None,
        );
        let mut sync = node(
            "usync",
            vec![
                ("context", self.context.clone()),
                ("mode", self.mode.clone()),
                ("sid", sid.into()),
                ("last", "true".into()),
                ("index", "0".into()),
            ],
            None,
        );
        let mut query_node = node("query", vec![], None);
        let mut list_node = node("list", vec![], None);
        for n in [&root, &sync, &query_node, &list_node] {
            charge(n)?;
        }
        let mut user_nodes = Vec::with_capacity(self.users.len());
        for u in &self.users {
            let attrs = if truthy(u.phone.as_deref()).is_none() {
                u.id.as_ref()
                    .map(|id| vec![("jid", id.clone())])
                    .unwrap_or_default()
            } else {
                vec![]
            };
            let mut user = node("user", attrs, None);
            charge(&user)?;
            let mut parts = Vec::new();
            for p in &self.protocols {
                if let Some(part) = p.user_element(u) {
                    charge(&part)?;
                    parts.push(part);
                }
            }
            user.content = Some(Content::Nodes(parts));
            user_nodes.push(user);
        }
        let mut protocol_nodes = Vec::new();
        for p in &self.protocols {
            let part = p.query_element();
            charge(&part)?;
            protocol_nodes.push(part);
        }
        query_node.content = Some(Content::Nodes(protocol_nodes));
        list_node.content = Some(Content::Nodes(user_nodes));
        sync.content = Some(Content::Nodes(vec![query_node, list_node]));
        root.content = Some(Content::Nodes(vec![sync]));
        let n = root;
        bound(&n, self.limits)?;
        Ok(n)
    }
    pub fn parse(&self, result: Option<&Node>) -> Result<Option<QueryResult>> {
        if self.protocols.len() > self.limits.max_protocols {
            return Err(Error::Limit);
        }
        let Some(result) = result else {
            return Ok(None);
        };
        bound(result, self.limits)?;
        if attr(result, "type") != Some("result") {
            return Ok(None);
        }
        let protocol_map: std::collections::HashMap<_, _> =
            self.protocols.iter().map(|p| (p.name(), p)).collect();
        let mut out = QueryResult::default();
        if let Some(list) = child(result, "usync").and_then(|n| child(n, "list")) {
            if nodes(list).len() > self.limits.max_users {
                return Err(Error::Limit);
            }
            for n in nodes(list) {
                let Some(id) = truthy(attr(n, "jid")) else {
                    continue;
                };
                let mut data = Map::new();
                for c in nodes(n) {
                    if let Some(p) = protocol_map.get(c.tag.as_str())
                        && let Some(value) = p.parse(c)?
                        && !value.is_null()
                    {
                        data.insert(c.tag.clone(), value);
                    }
                }
                // Original final {...data,id} wins even for a custom 'id' protocol.
                data.remove("id");
                out.list.push(Row {
                    id: id.into(),
                    data,
                });
            }
        }
        Ok(Some(out))
    }
}
struct Context<Q> {
    endpoint: Q,
    prefix: String,
    next: AtomicU64,
}
pub struct Client<Q> {
    inner: Arc<Context<Q>>,
}
impl<Q> Clone for Client<Q> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contact {
    pub jid: String,
    pub exists: bool,
}
impl<Q: Endpoint> Client<Q> {
    pub fn new(endpoint: Q) -> Result<Self> {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| Error::Randomness)?;
        let prefix = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Ok(Self {
            inner: Arc::new(Context {
                endpoint,
                prefix,
                next: AtomicU64::new(0),
            }),
        })
    }
    pub async fn execute(&self, query: &Query) -> Result<Option<QueryResult>> {
        let id = self
            .inner
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Error::IdExhausted)?;
        let request = query.build(&format!("{}.{}", self.inner.prefix, id))?;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            self.inner.endpoint.query(request),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Network)?;
        query.parse(Some(&response))
    }
    pub async fn on_whatsapp(&self, phones: &[String]) -> Result<Option<Vec<Contact>>> {
        let mut q = Query::default().with_protocol(Builtin::Contact);
        for p in phones {
            if !crate::jid::is_lid_user(Some(p)) {
                let phone = p.replacen('+', "", 1);
                let phone = phone
                    .split('@')
                    .next()
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("");
                q.users
                    .push(User::default().with_phone(format!("+{phone}")));
            }
        }
        if q.users.is_empty() {
            return Ok(Some(vec![]));
        }
        Ok(self.execute(&q).await?.map(|r| {
            r.list
                .into_iter()
                .filter(|r| r.data.get("contact") == Some(&json!(true)))
                .map(|r| Contact {
                    jid: r.id,
                    exists: true,
                })
                .collect()
        }))
    }
    pub async fn pn_from_lid(&self, jids: &[String]) -> Result<Vec<crate::lid_mapping::Mapping>> {
        let mut q = Query::default()
            .with_protocol(Builtin::Lid)
            .with_context("background");
        for jid in jids {
            if !crate::jid::is_lid_user(Some(jid)) {
                q.users.push(User::default().with_id(jid));
            }
        }
        if q.users.is_empty() {
            return Ok(vec![]);
        }
        Ok(self
            .execute(&q)
            .await?
            .unwrap_or_default()
            .list
            .into_iter()
            .filter_map(|r| {
                r.data
                    .get("lid")
                    .and_then(Value::as_str)
                    .filter(|lid| !lid.is_empty())
                    .map(|lid| crate::lid_mapping::Mapping {
                        pn: r.id.clone(),
                        lid: lid.into(),
                    })
            })
            .collect())
    }
}

pub(crate) fn check_node(node: &Node) -> Result<()> {
    bound(node, Limits::default()).map(|_| ())
}
