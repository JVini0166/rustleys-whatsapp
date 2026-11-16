//! Single-owner asynchronous WebSocket/Noise transport, not a logged-in client.
//! Callers must prepare the correct ClientPayload and continuously drain events.
use crate::{
    auth::Credentials,
    binary::{self, Content, Node},
    crypto,
    noise::{self, Frame, NoiseSession},
    proto,
};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    time::{Instant, timeout_at},
};
use tokio_tungstenite::{
    WebSocketStream, connect_async_with_config,
    tungstenite::{self, Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_URL: &str = "wss://web.whatsapp.com/ws/chat";
pub const DEFAULT_ORIGIN: &str = "https://web.whatsapp.com";
#[derive(Clone, Debug)]
pub struct Config {
    pub connect_timeout: Duration,
    pub write_timeout: Duration,
    pub query_timeout: Duration,
    pub close_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub keep_alive_grace: Duration,
    pub command_capacity: usize,
    pub event_capacity: usize,
    pub max_pending_queries: usize,
    pub max_custom_query_ids: usize,
    pub outbound_budget: usize,
    pub event_budget: usize,
    pub max_message_bytes: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(20),
            write_timeout: Duration::from_secs(20),
            query_timeout: Duration::from_secs(60),
            close_timeout: Duration::from_secs(5),
            keep_alive_interval: Duration::from_secs(30),
            keep_alive_grace: Duration::from_secs(5),
            command_capacity: 128,
            event_capacity: 256,
            max_pending_queries: 1024,
            max_custom_query_ids: 8192,
            outbound_budget: 64 * 1024 * 1024,
            event_budget: 64 * 1024 * 1024,
            max_message_bytes: noise::MAX_FRAME_SIZE - 16,
        }
    }
}
impl Config {
    fn validate(&self) -> Result<()> {
        for d in [
            self.connect_timeout,
            self.write_timeout,
            self.query_timeout,
            self.close_timeout,
            self.keep_alive_interval,
            self.keep_alive_grace,
        ] {
            if d.is_zero() || d > Duration::from_secs(86_400) {
                return Err(Error::InvalidConfig);
            }
        }
        if [
            self.command_capacity,
            self.event_capacity,
            self.max_pending_queries,
            self.max_custom_query_ids,
        ]
        .iter()
        .any(|n| *n == 0 || *n > 65_536)
            || self.max_message_bytes == 0
            || self.max_message_bytes > noise::MAX_FRAME_SIZE - 16
            || [self.outbound_budget, self.event_budget]
                .iter()
                .any(|n| *n == 0 || *n > u32::MAX as usize || *n > Semaphore::MAX_PERMITS)
            || self.outbound_budget < self.max_message_bytes
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
    fn websocket(&self) -> WebSocketConfig {
        WebSocketConfig::default()
            .read_buffer_size(16 * 1024)
            .write_buffer_size(0)
            .max_write_buffer_size(2 * (noise::MAX_FRAME_SIZE + 3))
            .max_message_size(Some(2 * (noise::MAX_FRAME_SIZE + 3)))
            .max_frame_size(Some(2 * (noise::MAX_FRAME_SIZE + 3)))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutPhase {
    Connect,
    Handshake,
    Queue,
    Write,
    Response,
    Close,
    Idle,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    InvalidUrl,
    InvalidCredentials,
    Pairing(crate::pairing::Error),
    Randomness,
    Closed,
    ConsumerGone,
    Http(u16),
    Network(std::io::ErrorKind),
    Tls,
    WebSocketProtocol,
    WebSocket,
    UnexpectedMessage,
    MessageTooLarge,
    Noise(noise::Error),
    Binary(binary::Error),
    InvalidHandshake,
    InvalidNode,
    DuplicateId,
    ReservedId,
    IdHistoryLimit,
    IdExhausted,
    PendingLimit,
    Backpressure,
    Timeout(TimeoutPhase),
    OutcomeUnknown,
    PeerClosed(Option<u16>),
    Server(Option<u16>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Socket: {self:?}")
    }
}
impl Error {
    /// True means retrying can repeat a request that reached the peer.
    pub fn delivery_uncertain(&self) -> bool {
        matches!(
            self,
            Self::OutcomeUnknown | Self::Timeout(TimeoutPhase::Write | TimeoutPhase::Response)
        )
    }
}
impl std::error::Error for Error {}
impl From<noise::Error> for Error {
    fn from(error: noise::Error) -> Self {
        Self::Noise(error)
    }
}
impl From<binary::Error> for Error {
    fn from(error: binary::Error) -> Self {
        Self::Binary(error)
    }
}
type Result<T> = std::result::Result<T, Error>;
fn ws_error(error: tungstenite::Error) -> Error {
    match error {
        tungstenite::Error::Http(response) => Error::Http(response.status().as_u16()),
        tungstenite::Error::Io(error) => Error::Network(error.kind()),
        tungstenite::Error::Tls(_) => Error::Tls,
        tungstenite::Error::Protocol(_) => Error::WebSocketProtocol,
        tungstenite::Error::Capacity(_) => Error::MessageTooLarge,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => Error::Closed,
        _ => Error::WebSocket,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    NoiseEstablished,
    Closing,
    Closed(Error),
}
struct Ids {
    prefix: String,
    next: AtomicU64,
}
impl Ids {
    fn new() -> Result<Self> {
        let mut bytes = [0; 8];
        getrandom::getrandom(&mut bytes).map_err(|_| Error::Randomness)?;
        Ok(Self {
            prefix: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            next: AtomicU64::new(0),
        })
    }
    fn next(&self) -> Result<String> {
        let n = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::IdExhausted)?;
        Ok(format!("{}.{n}", self.prefix))
    }
}
struct Packet {
    bytes: Box<[u8]>,
    _budget: OwnedSemaphorePermit,
}
impl Drop for Packet {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
enum Command {
    Send {
        packet: Packet,
        deadline: Instant,
        reply: oneshot::Sender<Result<()>>,
    },
    Query {
        packet: Packet,
        id: String,
        custom: bool,
        deadline: Instant,
        reply: oneshot::Sender<Result<Arc<Node>>>,
    },
    Close {
        reply: oneshot::Sender<Result<()>>,
    },
}
#[derive(Clone)]
pub struct Connection {
    commands: mpsc::Sender<Command>,
    status: watch::Receiver<Status>,
    ids: Arc<Ids>,
    outbound: Arc<Semaphore>,
    config: Config,
}
impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}
/// Memory charged while an event is queued or held. into_node transfers memory
/// ownership to the caller and releases the transport's event budget.
pub struct Event {
    node: Arc<Node>,
    _budget: OwnedSemaphorePermit,
}
impl Event {
    pub fn node(&self) -> &Node {
        &self.node
    }
    pub fn into_node(self) -> Arc<Node> {
        self.node
    }
}
impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Event([redacted])")
    }
}
pub struct Events {
    receiver: mpsc::Receiver<Event>,
    status: watch::Receiver<Status>,
}
impl Events {
    pub async fn recv(&mut self) -> Option<Event> {
        self.receiver.recv().await
    }
    pub fn status(&self) -> Status {
        self.status.borrow().clone()
    }
}
impl Connection {
    /// TLS and WhatsApp's pinned Noise certificate chain are mandatory here.
    /// NoiseEstablished means transport-ready, not authenticated/logged in.
    pub async fn connect(
        url: &str,
        creds: &Credentials,
        payload: &proto::ClientPayload,
        routing: Option<&[u8]>,
        config: Config,
    ) -> Result<(Self, Events)> {
        config.validate()?;
        creds.validate().map_err(|_| Error::InvalidCredentials)?;
        let request = websocket_request(url, false)?;
        if payload.encoded_len() > config.max_message_bytes {
            return Err(Error::MessageTooLarge);
        }
        let plaintext = Zeroizing::new(payload.encode_to_vec());
        let mut noise = NoiseSession::new(
            crypto::PrivateKey::generate().map_err(|_| Error::Randomness)?,
            routing,
        )?;
        noise.set_node_limits(binary::Limits {
            max_bytes: config.max_message_bytes,
            ..Default::default()
        });
        let static_key = crypto::PrivateKey::from_bytes(
            creds
                .noise_key
                .private
                .expose()
                .try_into()
                .map_err(|_| Error::InvalidCredentials)?,
        );
        let deadline = Instant::now() + config.connect_timeout;
        let (mut websocket, _) = timeout_at(
            deadline,
            connect_async_with_config(request, Some(config.websocket()), false),
        )
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::Connect))?
        .map_err(ws_error)?;
        handshake(&mut websocket, &mut noise, &static_key, &plaintext, &config).await?;
        spawn(websocket, noise, config)
    }
    /// Select registration/login from persisted account state and build the
    /// pinned-compatible payload. Pairing/login event orchestration is separate.
    pub async fn connect_account(
        url: &str,
        creds: &Credentials,
        client: &crate::pairing::ClientConfig,
        transport: Config,
    ) -> Result<(Self, Events)> {
        let payload = crate::pairing::client_payload(creds, client).map_err(Error::Pairing)?;
        Self::connect(
            url,
            creds,
            &payload,
            creds.routing_info.as_ref().map(|bytes| bytes.expose()),
            transport,
        )
        .await
    }
    pub fn status(&self) -> Status {
        self.status.borrow().clone()
    }
    pub async fn closed(&self) -> Error {
        let mut status = self.status.clone();
        loop {
            if let Status::Closed(error) = status.borrow().clone() {
                return error;
            }
            if status.changed().await.is_err() {
                return Error::Closed;
            }
        }
    }
    fn check_open(&self) -> Result<()> {
        if matches!(*self.status.borrow(), Status::NoiseEstablished) {
            Ok(())
        } else {
            Err(Error::Closed)
        }
    }
    async fn packet(&self, node: &Node, deadline: Instant) -> Result<Packet> {
        self.check_open()?;
        // Reserve before encoding: tasks waiting for budget must not each
        // retain an additional uncharged encoded copy of a large node.
        let mut reservation = timeout_at(
            deadline,
            self.outbound
                .clone()
                .acquire_many_owned(
                    encoded_reservation(node, self.config.max_message_bytes, 0) as u32
                ),
        )
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::Queue))?
        .map_err(|_| Error::Closed)?;
        self.check_open()?;
        let bytes = binary::encode_with_limits(
            node,
            binary::Limits {
                max_bytes: self.config.max_message_bytes,
                ..Default::default()
            },
        )?
        .into_boxed_slice();
        if deadline <= Instant::now() {
            return Err(Error::Timeout(TimeoutPhase::Queue));
        }
        let budget = reservation
            .split(bytes.len().max(1))
            .ok_or(Error::InvalidConfig)?;
        drop(reservation);
        Ok(Packet {
            bytes,
            _budget: budget,
        })
    }
    /// Ok only confirms a flushed WebSocket write. It is not a delivery receipt.
    pub async fn send_node(&self, node: Node) -> Result<()> {
        let deadline = Instant::now() + self.config.write_timeout;
        let packet = self.packet(&node, deadline).await?;
        let (reply, result) = oneshot::channel();
        timeout_at(
            deadline,
            self.commands.send(Command::Send {
                packet,
                deadline,
                reply,
            }),
        )
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::Queue))?
        .map_err(|_| Error::Closed)?;
        timeout_at(deadline, result)
            .await
            .map_err(|_| Error::OutcomeUnknown)?
            .map_err(|_| Error::OutcomeUnknown)?
    }
    pub async fn query(&self, node: Node) -> Result<Arc<Node>> {
        self.query_with_timeout(node, self.config.query_timeout)
            .await
    }
    pub async fn query_with_timeout(&self, mut node: Node, wait: Duration) -> Result<Arc<Node>> {
        if wait.is_zero() || wait > Duration::from_secs(86_400) {
            return Err(Error::InvalidConfig);
        }
        let deadline = Instant::now() + wait;
        let (id, custom) = match node_id(&node)? {
            Some(id) if !id.is_empty() => {
                if id.starts_with(&format!("{}.", self.ids.prefix)) {
                    return Err(Error::ReservedId);
                }
                (id.to_owned(), true)
            }
            _ => {
                node.attrs.retain(|(key, _)| key != "id");
                let id = self.ids.next()?;
                node.attrs.push(("id".into(), id.clone()));
                (id, false)
            }
        };
        let packet = self.packet(&node, deadline).await?;
        let (reply, result) = oneshot::channel();
        timeout_at(
            deadline,
            self.commands.send(Command::Query {
                packet,
                id,
                custom,
                deadline,
                reply,
            }),
        )
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::Queue))?
        .map_err(|_| Error::Closed)?;
        timeout_at(deadline, result)
            .await
            .map_err(|_| Error::OutcomeUnknown)?
            .map_err(|_| Error::OutcomeUnknown)?
    }
    pub async fn close(&self) -> Result<()> {
        if matches!(self.status(), Status::Closed(_)) {
            return Ok(());
        }
        let deadline = Instant::now() + self.config.close_timeout;
        if matches!(self.status(), Status::Closing) {
            return timeout_at(deadline, self.closed())
                .await
                .map(|_| ())
                .map_err(|_| Error::Timeout(TimeoutPhase::Close));
        }
        let (reply, result) = oneshot::channel();
        match timeout_at(deadline, self.commands.send(Command::Close { reply })).await {
            Err(_) => return Err(Error::Timeout(TimeoutPhase::Queue)),
            Ok(Err(_)) if matches!(self.status(), Status::Closed(_)) => return Ok(()),
            Ok(Err(_)) => return Err(Error::Closed),
            Ok(Ok(())) => {}
        }
        match timeout_at(deadline, result).await {
            Err(_) => Err(Error::Timeout(TimeoutPhase::Close)),
            Ok(Ok(result)) => result,
            // Another caller may have closed the actor before this queued
            // close command was read. Wait for its authoritative final status.
            Ok(Err(_)) => timeout_at(deadline, self.closed())
                .await
                .map(|_| ())
                .map_err(|_| Error::Timeout(TimeoutPhase::Close)),
        }
    }
}
fn websocket_request(url: &str, allow_plain: bool) -> Result<tungstenite::http::Request<()>> {
    let mut request = url.into_client_request().map_err(|_| Error::InvalidUrl)?;
    let uri = request.uri();
    if (uri.scheme_str() != Some("wss") && !(allow_plain && uri.scheme_str() == Some("ws")))
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err(Error::InvalidUrl);
    }
    request.headers_mut().insert(
        "origin",
        tungstenite::http::HeaderValue::from_static(DEFAULT_ORIGIN),
    );
    Ok(request)
}
async fn write<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
    bytes: Vec<u8>,
    deadline: Instant,
) -> Result<()> {
    timeout_at(deadline, socket.send(Message::Binary(bytes.into())))
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::Write))?
        .map_err(ws_error)
}
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
    noise: &mut NoiseSession,
    static_key: &crypto::PrivateKey,
    payload: &[u8],
    config: &Config,
) -> Result<()> {
    let deadline = Instant::now() + config.connect_timeout;
    write(socket, noise.client_hello()?, deadline).await?;
    let hello = loop {
        if let Some(frame) = noise.next_frame()? {
            let Frame::Handshake(bytes) = frame else {
                return Err(Error::InvalidHandshake);
            };
            if bytes.len() > 1024 * 1024 {
                return Err(Error::MessageTooLarge);
            }
            let message =
                proto::HandshakeMessage::decode(bytes).map_err(|_| Error::InvalidHandshake)?;
            if message.client_hello.is_some() || message.client_finish.is_some() {
                return Err(Error::InvalidHandshake);
            }
            break message.server_hello.ok_or(Error::InvalidHandshake)?;
        }
        match timeout_at(deadline, socket.next())
            .await
            .map_err(|_| Error::Timeout(TimeoutPhase::Handshake))?
        {
            Some(Ok(Message::Binary(bytes))) => noise.push_bytes(&bytes)?,
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                timeout_at(deadline, socket.flush())
                    .await
                    .map_err(|_| Error::Timeout(TimeoutPhase::Handshake))?
                    .map_err(ws_error)?;
            }
            Some(Ok(Message::Close(frame))) => {
                return Err(Error::PeerClosed(frame.map(|f| f.code.into())));
            }
            Some(Ok(_)) => return Err(Error::UnexpectedMessage),
            Some(Err(error)) => return Err(ws_error(error)),
            None => return Err(Error::Closed),
        }
    };
    let encrypted_static = noise.process_handshake(&hello, static_key)?;
    let payload = noise.encrypt_client_payload(payload)?;
    let finish = proto::HandshakeMessage {
        client_finish: Some(proto::handshake_message::ClientFinish {
            r#static: Some(encrypted_static),
            payload: Some(payload),
            ..Default::default()
        }),
        ..Default::default()
    };
    write(
        socket,
        noise.encode_frame(&finish.encode_to_vec())?,
        deadline,
    )
    .await?;
    noise.finish_init()?;
    Ok(())
}
fn node_id(node: &Node) -> Result<Option<&str>> {
    let mut values = node.attrs.iter().filter(|(key, _)| key == "id");
    let first = values.next().map(|(_, value)| value.as_str());
    if values.next().is_some() || first.is_some_and(|id| id.len() > 256) {
        return Err(Error::InvalidNode);
    }
    Ok(first)
}
fn server_error(node: &Node) -> Option<Error> {
    if let Some(Content::Nodes(children)) = &node.content
        && let Some(error) = children.iter().find(|child| child.tag == "error")
    {
        return Some(Error::Server(
            error
                .attrs
                .iter()
                .find(|(k, _)| k == "code")
                .and_then(|(_, v)| v.parse().ok()),
        ));
    }
    None
}
// Conservative preallocation bound without building an encoded copy. Tokens
// and packed strings only reduce size. Recursive JID encoding consumes an @ or
// device suffix at each step, so 16 bytes per input byte plus 32 per string also
// bounds nested JID_PAIR headers. Cap early at the configured encoding limit.
fn encoded_reservation(node: &Node, limit: usize, depth: usize) -> usize {
    if depth > 128 {
        return limit;
    }
    let string = |s: &str| s.len().saturating_mul(16).saturating_add(32);
    let mut total = 10usize.saturating_add(string(&node.tag));
    for (key, value) in &node.attrs {
        total = total
            .saturating_add(string(key))
            .saturating_add(string(value));
        if total >= limit {
            return limit;
        }
    }
    match &node.content {
        Some(Content::Text(text)) => total = total.saturating_add(string(text)),
        Some(Content::Bytes(bytes)) => total = total.saturating_add(bytes.len()).saturating_add(5),
        Some(Content::Nodes(nodes)) => {
            for child in nodes {
                if total >= limit {
                    return limit;
                }
                total = total.saturating_add(encoded_reservation(child, limit - total, depth + 1));
            }
        }
        None => {}
    }
    total.min(limit).max(1)
}
fn node_cost(node: &Node) -> usize {
    let mut size = std::mem::size_of::<Node>()
        .saturating_add(node.tag.capacity())
        .saturating_add(node.attrs.capacity() * std::mem::size_of::<(String, String)>());
    for (k, v) in &node.attrs {
        size = size
            .saturating_add(k.capacity())
            .saturating_add(v.capacity());
    }
    match &node.content {
        Some(Content::Text(s)) => size = size.saturating_add(s.capacity()),
        Some(Content::Bytes(b)) => size = size.saturating_add(b.capacity()),
        Some(Content::Nodes(children)) => {
            size = size.saturating_add(children.capacity() * std::mem::size_of::<Node>());
            for child in children {
                size = size
                    .saturating_add(node_cost(child).saturating_sub(std::mem::size_of::<Node>()));
            }
        }
        None => {}
    }
    size
}
struct Pending {
    deadline: Instant,
    reply: oneshot::Sender<Result<Arc<Node>>>,
}
fn prune_pending(pending: &mut HashMap<String, Pending>) {
    pending.retain(|_, entry| !entry.reply.is_closed());
    let now = Instant::now();
    let expired: Vec<_> = pending
        .iter()
        .filter(|(_, entry)| entry.deadline <= now)
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        if let Some(entry) = pending.remove(&id) {
            let _ = entry
                .reply
                .send(Err(Error::Timeout(TimeoutPhase::Response)));
        }
    }
}
fn spawn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: WebSocketStream<S>,
    noise: NoiseSession,
    config: Config,
) -> Result<(Connection, Events)> {
    config.validate()?;
    let ids = Arc::new(Ids::new()?);
    let (commands, receiver) = mpsc::channel(config.command_capacity);
    let (events, incoming) = mpsc::channel(config.event_capacity);
    let (status, watcher) = watch::channel(Status::NoiseEstablished);
    let connection = Connection {
        commands,
        status: watcher.clone(),
        ids: ids.clone(),
        outbound: Arc::new(Semaphore::new(config.outbound_budget)),
        config: config.clone(),
    };
    tokio::spawn(async move {
        run(socket, noise, config, ids, receiver, events, status).await;
    });
    Ok((
        connection,
        Events {
            receiver: incoming,
            status: watcher,
        },
    ))
}
async fn graceful_close<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
    wait: Duration,
) -> Result<()> {
    let deadline = Instant::now() + wait;
    timeout_at(deadline, socket.close(None))
        .await
        .map_err(|_| Error::Timeout(TimeoutPhase::Close))?
        .map_err(ws_error)?;
    loop {
        match timeout_at(deadline, socket.next())
            .await
            .map_err(|_| Error::Timeout(TimeoutPhase::Close))?
        {
            Some(Ok(Message::Close(_))) | None => return Ok(()),
            Some(Err(tungstenite::Error::ConnectionClosed)) => return Ok(()),
            Some(Err(error)) => return Err(ws_error(error)),
            Some(Ok(_)) => {}
        }
    }
}
async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: WebSocketStream<S>,
    mut noise: NoiseSession,
    config: Config,
    ids: Arc<Ids>,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    status: watch::Sender<Status>,
) {
    let budget = Arc::new(Semaphore::new(config.event_budget));
    let mut pending: HashMap<String, Pending> = HashMap::new();
    let mut used_custom_ids: HashSet<[u8; 32]> = HashSet::new();
    let mut last_received = Instant::now();
    let mut next_ping = last_received + config.keep_alive_interval;
    let result:Result<()>=async {
        loop {
            prune_pending(&mut pending);
            if events.is_closed(){return Err(Error::ConsumerGone);}
            while let Some(frame)=noise.next_frame()? {
                let Frame::Node(node)=frame else{return Err(Error::InvalidHandshake);};
                last_received=Instant::now();let id=node_id(&node)?.map(str::to_owned);let node=Arc::new(node);
                if let Some(p)=id.and_then(|id|pending.remove(&id)){let result=server_error(&node).map_or_else(||Ok(node.clone()),Err);let _=p.reply.send(result);}
                let cost=u32::try_from(node_cost(&node).max(1)).map_err(|_|Error::Backpressure)?;
                let permit=budget.clone().try_acquire_many_owned(cost).map_err(|_|Error::Backpressure)?;
                events.try_send(Event{node,_budget:permit}).map_err(|error|match error {mpsc::error::TrySendError::Closed(_)=>Error::ConsumerGone,mpsc::error::TrySendError::Full(_)=>Error::Backpressure})?;
            }
            let idle=last_received+config.keep_alive_interval+config.keep_alive_grace;
            let wake=pending.values().map(|p|p.deadline).min().unwrap_or(next_ping).min(next_ping).min(idle);
            tokio::select! {
                _=events.closed()=>return Err(Error::ConsumerGone),
                _=tokio::time::sleep_until(wake)=>{
                    let now=Instant::now();if now>=idle{return Err(Error::Timeout(TimeoutPhase::Idle));}
                    if now>=next_ping {
                        let node=Node{tag:"iq".into(),attrs:vec![("id".into(),ids.next()?),("to".into(),"s.whatsapp.net".into()),("type".into(),"get".into()),("xmlns".into(),"w:p".into())],content:Some(Content::Nodes(vec![Node{tag:"ping".into(),attrs:vec![],content:None}]))};
                        let bytes=binary::encode(&node)?;write(&mut socket,noise.encode_frame(&bytes)?,now+config.write_timeout).await?;
                        next_ping=Instant::now()+config.keep_alive_interval;
                    }
                },
                command=commands.recv()=>match command {
                    None=>return Err(Error::Closed),
                    Some(Command::Close{reply})=>{status.send_replace(Status::Closing);let result=graceful_close(&mut socket,config.close_timeout).await;let _=reply.send(result.clone());return result;},
                    Some(Command::Send{packet,deadline,reply})=>{
                        if reply.is_closed(){continue;}
                        if deadline<=Instant::now(){let _=reply.send(Err(Error::Timeout(TimeoutPhase::Queue)));continue;}
                        let result=write(&mut socket,noise.encode_frame(&packet.bytes)?,deadline.min(Instant::now()+config.write_timeout)).await;
                        // Once a write starts, a failure cannot prove non-delivery.
                        let _=reply.send(result.as_ref().map(|_|()).map_err(|_|Error::OutcomeUnknown));result?;
                    },
                    Some(Command::Query{packet,id,custom,deadline,reply})=>{
                        if reply.is_closed(){continue;}
                        if deadline<=Instant::now(){let _=reply.send(Err(Error::Timeout(TimeoutPhase::Queue)));continue;}
                        prune_pending(&mut pending);
                        let fingerprint=crypto::sha256(id.as_bytes());
                        if pending.contains_key(&id)||(custom&&used_custom_ids.contains(&fingerprint)){let _=reply.send(Err(Error::DuplicateId));continue;}
                        if pending.len()>=config.max_pending_queries{let _=reply.send(Err(Error::PendingLimit));continue;}
                        if custom {
                            if used_custom_ids.len()>=config.max_custom_query_ids {let _=reply.send(Err(Error::IdHistoryLimit));continue;}
                            used_custom_ids.insert(fingerprint);
                        }
                        pending.insert(id.clone(),Pending{deadline,reply});
                        if let Err(error)=write(&mut socket,noise.encode_frame(&packet.bytes)?,deadline.min(Instant::now()+config.write_timeout)).await {
                            if let Some(p)=pending.remove(&id){let _=p.reply.send(Err(Error::OutcomeUnknown));}return Err(error);
                        }
                    },
                },
                message=socket.next()=>match message {
                    Some(Ok(Message::Binary(bytes)))=>noise.push_bytes(&bytes)?,
                    Some(Ok(Message::Ping(_)))|Some(Ok(Message::Pong(_)))=>{timeout_at(Instant::now()+config.write_timeout,socket.flush()).await.map_err(|_|Error::Timeout(TimeoutPhase::Write))?.map_err(ws_error)?;},
                    Some(Ok(Message::Close(frame)))=>{let code=frame.map(|f|f.code.into());let _=timeout_at(Instant::now()+config.close_timeout,socket.flush()).await;return Err(Error::PeerClosed(code));},
                    Some(Ok(_))=>return Err(Error::UnexpectedMessage),Some(Err(error))=>return Err(ws_error(error)),None=>return Err(Error::Closed),
                }
            }
        }
    }.await;
    let error = result.err().unwrap_or(Error::Closed);
    for (_, p) in pending {
        let _ = p.reply.send(Err(Error::OutcomeUnknown));
    }
    status.send_replace(Status::Closed(error));
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
