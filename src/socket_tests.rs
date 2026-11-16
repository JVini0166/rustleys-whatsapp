use super::*;
use serde_json::Value;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_tungstenite::{
    accept_async, accept_hdr_async,
    tungstenite::{
        handshake::server::{Request, Response},
        protocol::Role,
    },
};
// tungstenite's Callback contract fixes this error to an HTTP Response.
#[allow(clippy::result_large_err)]
fn check_origin(
    request: &Request,
    response: Response,
) -> std::result::Result<Response, tungstenite::handshake::server::ErrorResponse> {
    assert_eq!(request.headers()["origin"], DEFAULT_ORIGIN);
    Ok(response)
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/noise-upstream.json")).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::from_value(v.clone()).unwrap()
}
fn private(v: &Value) -> crypto::PrivateKey {
    crypto::PrivateKey::from_bytes(bytes(v).try_into().unwrap())
}
fn row() -> Value {
    fixture()["cases"][0].clone()
}
fn node(id: &str) -> Node {
    Node {
        tag: "iq".into(),
        attrs: vec![("id".into(), id.into()), ("type".into(), "get".into())],
        content: None,
    }
}
fn result(id: &str) -> Node {
    Node {
        tag: "iq".into(),
        attrs: vec![("id".into(), id.into()), ("type".into(), "result".into())],
        content: None,
    }
}
fn test_config() -> Config {
    Config {
        connect_timeout: Duration::from_secs(3),
        write_timeout: Duration::from_secs(3),
        query_timeout: Duration::from_secs(3),
        close_timeout: Duration::from_secs(1),
        ..Default::default()
    }
}
fn session(row: &Value) -> NoiseSession {
    let routing = (!row["routing"].is_null()).then(|| bytes(&row["routing"]));
    NoiseSession::with_test_root(
        private(&row["clientPrivate"]),
        routing.as_deref(),
        bytes(&row["rootPublic"]).try_into().unwrap(),
    )
    .unwrap()
}
fn prepared(row: &Value) -> NoiseSession {
    let mut noise = session(row);
    noise.client_hello().unwrap();
    let hello = proto::HandshakeMessage::decode(bytes(&row["serverHello"]).as_slice())
        .unwrap()
        .server_hello
        .unwrap();
    let static_encrypted = noise
        .process_handshake(&hello, &private(&row["clientStaticPrivate"]))
        .unwrap();
    let payload = noise
        .encrypt_client_payload(&bytes(&row["clientPayload"]))
        .unwrap();
    let finish = proto::HandshakeMessage {
        client_finish: Some(proto::handshake_message::ClientFinish {
            r#static: Some(static_encrypted),
            payload: Some(payload),
            ..Default::default()
        }),
        ..Default::default()
    };
    noise.encode_frame(&finish.encode_to_vec()).unwrap();
    noise.finish_init().unwrap();
    noise
}
struct Server {
    socket: WebSocketStream<TcpStream>,
    cipher: noise::TransportCipher,
    decoder: noise::FrameDecoder,
    encoder: noise::FrameEncoder,
}
impl Server {
    async fn recv(&mut self) -> Option<Node> {
        tokio::time::timeout(Duration::from_secs(3), self.recv_inner())
            .await
            .expect("test peer deadline")
    }
    async fn recv_inner(&mut self) -> Option<Node> {
        loop {
            if let Some(frame) = self.decoder.next_frame().unwrap() {
                return Some(binary::decode(&self.cipher.decrypt(&frame).unwrap()).unwrap());
            }
            match self.socket.next().await {
                Some(Ok(Message::Binary(bytes))) => self.decoder.push(&bytes).unwrap(),
                Some(Ok(Message::Close(_))) | None => {
                    let _ = self.socket.flush().await;
                    return None;
                }
                Some(Ok(Message::Ping(_))) => self.socket.flush().await.unwrap(),
                other => panic!("unexpected server frame: {other:?}"),
            }
        }
    }
    fn wire(&mut self, node: &Node) -> Vec<u8> {
        self.encoder
            .encode(&self.cipher.encrypt(&binary::encode(node).unwrap()).unwrap())
            .unwrap()
    }
    async fn send(&mut self, node: &Node) {
        let wire = self.wire(node);
        self.socket
            .send(Message::Binary(wire.into()))
            .await
            .unwrap();
    }
    async fn finish(mut self, connection: Connection) {
        let (closed, received) = tokio::join!(connection.close(), self.recv());
        assert!(received.is_none());
        closed.unwrap();
    }
}
async fn pair(config: Config, coalesced: bool) -> (Connection, Events, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let row = row();
    let original = row.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_hdr_async(stream, check_origin).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_data(),
            bytes(&original["clientHelloFrame"])
        );
        let mut server = Server {
            socket,
            cipher: noise::TransportCipher::new(
                bytes(&original["clientReadKey"]).try_into().unwrap(),
                bytes(&original["clientWriteKey"]).try_into().unwrap(),
            ),
            decoder: noise::FrameDecoder::default(),
            encoder: noise::FrameEncoder::new(&[], None).unwrap(),
        };
        let mut hello = bytes(&original["serverHelloFrame"]);
        if coalesced {
            hello.extend(server.wire(&result("early")));
        }
        // Noise lengths/transcript may span multiple WebSocket messages.
        for chunk in hello.chunks(7) {
            server
                .socket
                .send(Message::Binary(chunk.to_vec().into()))
                .await
                .unwrap();
        }
        assert_eq!(
            server.socket.next().await.unwrap().unwrap().into_data(),
            bytes(&original["clientFinishFrame"])
        );
        server
    });
    let (mut socket, _) = connect_async_with_config(
        websocket_request(&format!("ws://{address}"), true).unwrap(),
        Some(config.websocket()),
        false,
    )
    .await
    .unwrap();
    let mut noise = session(&row);
    noise.set_node_limits(binary::Limits {
        max_bytes: config.max_message_bytes,
        ..Default::default()
    });
    handshake(
        &mut socket,
        &mut noise,
        &private(&row["clientStaticPrivate"]),
        &bytes(&row["clientPayload"]),
        &config,
    )
    .await
    .unwrap();
    let (connection, events) = spawn(socket, noise, config).unwrap();
    (connection, events, server.await.unwrap())
}
#[tokio::test]
async fn authenticated_handshake_fragments_and_coalesced_transport_preserve_order() {
    let (connection, mut events, mut server) = pair(test_config(), true).await;
    assert_eq!(
        node_id(events.recv().await.unwrap().node()).unwrap(),
        Some("early")
    );
    connection.send_node(node("first")).await.unwrap();
    assert_eq!(server.recv().await.unwrap(), node("first"));
    let mut combined = server.wire(&result("a"));
    combined.extend(server.wire(&result("b")));
    combined.extend([0, 0]);
    server
        .socket
        .send(Message::Binary(combined.into()))
        .await
        .unwrap();
    for id in ["a", "b"] {
        assert_eq!(
            node_id(events.recv().await.unwrap().node()).unwrap(),
            Some(id)
        );
    }
    server.finish(connection.clone()).await;
    assert_eq!(connection.closed().await, Error::Closed);
    assert!(events.recv().await.is_none());
}
#[tokio::test]
async fn concurrent_queries_match_reverse_order_and_broadcast_every_node() {
    let (connection, mut events, mut server) = pair(test_config(), false).await;
    let mut tasks = Vec::new();
    for n in 0..12 {
        let connection = connection.clone();
        tasks.push(tokio::spawn(async move {
            connection.query(node(&format!("query-{n}"))).await.unwrap()
        }));
    }
    let mut requests = Vec::new();
    for _ in 0..12 {
        requests.push(server.recv().await.unwrap());
    }
    for request in requests.iter().rev() {
        server
            .send(&result(node_id(request).unwrap().unwrap()))
            .await;
    }
    for (n, task) in tasks.into_iter().enumerate() {
        assert_eq!(
            node_id(&task.await.unwrap()).unwrap(),
            Some(format!("query-{n}").as_str())
        );
    }
    for request in requests.iter().rev() {
        assert_eq!(
            events.recv().await.unwrap().node(),
            &result(node_id(request).unwrap().unwrap())
        );
    }
    server.finish(connection).await;
}
#[tokio::test]
async fn generated_ids_are_unique_and_immediate_responses_are_not_lost() {
    let (connection, mut events, mut server) = pair(test_config(), false).await;
    let worker = tokio::spawn(async move {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..32 {
            let request = server.recv().await.unwrap();
            let id = node_id(&request).unwrap().unwrap();
            assert!(ids.insert(id.to_owned()));
            server.send(&result(id)).await;
        }
        server
    });
    for _ in 0..32 {
        let mut request = node("");
        request.attrs.clear();
        let response = connection.query(request).await.unwrap();
        assert!(node_id(&response).unwrap().is_some());
        events.recv().await.unwrap();
    }
    worker.await.unwrap().finish(connection).await;
}
#[tokio::test]
async fn duplicate_pending_ids_and_pending_limit_are_rejected_without_sending() {
    let config = Config {
        max_pending_queries: 1,
        ..test_config()
    };
    let (connection, mut events, mut server) = pair(config, false).await;
    let first = {
        let c = connection.clone();
        tokio::spawn(async move { c.query(node("same")).await })
    };
    assert_eq!(
        node_id(&server.recv().await.unwrap()).unwrap(),
        Some("same")
    );
    assert_eq!(
        connection.query(node("same")).await.unwrap_err(),
        Error::DuplicateId
    );
    assert_eq!(
        connection.query(node("other")).await.unwrap_err(),
        Error::PendingLimit
    );
    server.send(&result("same")).await;
    first.await.unwrap().unwrap();
    events.recv().await.unwrap();
    server.finish(connection).await;
}
#[tokio::test]
async fn cancelled_and_expired_queries_release_slots_without_replaying_writes() {
    let config = Config {
        max_pending_queries: 1,
        ..test_config()
    };
    let (connection, mut events, mut server) = pair(config, false).await;
    let cancelled = {
        let c = connection.clone();
        tokio::spawn(async move { c.query(node("cancelled")).await })
    };
    server.recv().await.unwrap();
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    let expired = {
        let c = connection.clone();
        tokio::spawn(async move {
            c.query_with_timeout(node("expired"), Duration::from_millis(60))
                .await
        })
    };
    assert_eq!(
        node_id(&server.recv().await.unwrap()).unwrap(),
        Some("expired")
    );
    assert!(matches!(
        expired.await.unwrap(),
        Err(Error::OutcomeUnknown | Error::Timeout(TimeoutPhase::Response))
    ));
    // Late replies remain observable; they cannot satisfy an unrelated query.
    server.send(&result("cancelled")).await;
    server.send(&result("expired")).await;
    for id in ["cancelled", "expired"] {
        assert_eq!(
            node_id(events.recv().await.unwrap().node()).unwrap(),
            Some(id)
        );
    }
    let query = {
        let c = connection.clone();
        tokio::spawn(async move { c.query(node("next")).await })
    };
    assert_eq!(
        node_id(&server.recv().await.unwrap()).unwrap(),
        Some("next")
    );
    server.send(&result("next")).await;
    query.await.unwrap().unwrap();
    events.recv().await.unwrap();
    server.finish(connection).await;
}
#[tokio::test]
async fn server_error_queries_keep_redacted_error_and_original_event() {
    let (connection, mut events, mut server) = pair(test_config(), false).await;
    let query = {
        let c = connection.clone();
        tokio::spawn(async move { c.query(node("bad")).await })
    };
    server.recv().await.unwrap();
    let mut response = result("bad");
    response.content = Some(Content::Nodes(vec![Node {
        tag: "error".into(),
        attrs: vec![
            ("code".into(), "403".into()),
            ("text".into(), "private server detail".into()),
        ],
        content: None,
    }]));
    server.send(&response).await;
    let error = query.await.unwrap().unwrap_err();
    assert_eq!(error, Error::Server(Some(403)));
    assert!(!format!("{error}").contains("private"));
    assert_eq!(events.recv().await.unwrap().node(), &response);
    server.finish(connection).await;
}
#[tokio::test]
async fn slow_event_consumers_fail_closed_on_count_or_byte_budget() {
    for config in [
        Config {
            event_capacity: 1,
            ..test_config()
        },
        Config {
            event_budget: 1,
            ..test_config()
        },
    ] {
        let (connection, mut events, mut server) = pair(config, false).await;
        server.send(&result("one")).await;
        // The consumer deliberately drains nothing until the connection
        // reports backpressure, regardless of network packet boundaries.
        if connection.config.event_budget > 1 {
            server.send(&result("two")).await;
        }
        assert_eq!(connection.closed().await, Error::Backpressure);
        if connection.config.event_budget > 1 {
            assert_eq!(
                node_id(events.recv().await.unwrap().node()).unwrap(),
                Some("one")
            );
        }
        assert!(events.recv().await.is_none());
    }
}
#[tokio::test]
async fn event_memory_budget_is_released_when_the_host_drops_events() {
    let cost = node_cost(&result("x"));
    let config = Config {
        event_budget: cost * 2,
        ..test_config()
    };
    let (connection, mut events, mut server) = pair(config, false).await;
    for _ in 0..20 {
        server.send(&result("x")).await;
        drop(events.recv().await.unwrap());
    }
    assert_eq!(connection.status(), Status::NoiseEstablished);
    server.finish(connection).await;
}
#[tokio::test]
async fn dropping_consumers_or_all_handles_stops_the_socket_task() {
    let (connection, events, _server) = pair(test_config(), false).await;
    drop(events);
    assert_eq!(connection.closed().await, Error::ConsumerGone);
    let (connection, mut events, _server) = pair(test_config(), false).await;
    drop(connection);
    assert!(events.recv().await.is_none());
    assert_eq!(events.status(), Status::Closed(Error::Closed));
}
#[tokio::test]
async fn authentication_failure_replay_and_text_are_terminal() {
    for mode in 0..3 {
        let (connection, mut events, mut server) = pair(test_config(), false).await;
        if mode == 2 {
            server
                .socket
                .send(Message::Text("private text".into()))
                .await
                .unwrap();
            assert_eq!(connection.closed().await, Error::UnexpectedMessage);
        } else {
            let mut wire = server.wire(&result("protected"));
            if mode == 0 {
                *wire.last_mut().unwrap() ^= 1;
            } else {
                server
                    .socket
                    .send(Message::Binary(wire.clone().into()))
                    .await
                    .unwrap();
                events.recv().await.unwrap();
            }
            server
                .socket
                .send(Message::Binary(wire.into()))
                .await
                .unwrap();
            assert!(matches!(
                connection.closed().await,
                Error::Noise(noise::Error::Crypto(crypto::Error::Authentication))
            ));
        }
        assert!(events.recv().await.is_none());
        assert_eq!(
            connection.send_node(node("after failure")).await,
            Err(Error::Closed)
        );
    }
}
#[tokio::test]
async fn peer_close_rejects_pending_queries_as_uncertain_and_records_only_code() {
    let (connection, mut events, mut server) = pair(test_config(), false).await;
    let query = {
        let c = connection.clone();
        tokio::spawn(async move { c.query(node("written")).await })
    };
    server.recv().await.unwrap();
    server
        .socket
        .send(Message::Close(Some(tungstenite::protocol::CloseFrame {
            code: tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "private reason".into(),
        })))
        .await
        .unwrap();
    assert_eq!(connection.closed().await, Error::PeerClosed(Some(1000)));
    assert_eq!(query.await.unwrap().unwrap_err(), Error::OutcomeUnknown);
    assert!(events.recv().await.is_none());
}
#[tokio::test]
async fn websocket_ping_is_answered_but_does_not_fake_noise_liveness() {
    let (connection, _events, mut server) = pair(test_config(), false).await;
    server
        .socket
        .send(Message::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(
        server.socket.next().await.unwrap().unwrap(),
        Message::Pong(vec![1, 2, 3].into())
    );
    server.finish(connection).await;
}
#[tokio::test]
async fn keepalive_sends_protocol_ping_and_idle_peer_is_closed() {
    let config = Config {
        keep_alive_interval: Duration::from_millis(150),
        keep_alive_grace: Duration::from_millis(150),
        ..test_config()
    };
    let (connection, _events, mut server) = pair(config, false).await;
    let ping = server.recv().await.unwrap();
    assert_eq!(ping.tag, "iq");
    assert!(
        ping.attrs
            .contains(&("to".into(), crate::jid::S_WHATSAPP_NET.into()))
    );
    assert!(ping.attrs.contains(&("xmlns".into(), "w:p".into())));
    assert!(matches!(ping.content,Some(Content::Nodes(nodes))if nodes[0].tag=="ping"));
    assert_eq!(
        connection.closed().await,
        Error::Timeout(TimeoutPhase::Idle)
    );
}
#[tokio::test]
async fn blocked_partial_write_is_uncertain_and_never_retried() {
    let (stream, _unread_peer) = tokio::io::duplex(64);
    let websocket = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
    let config = Config {
        write_timeout: Duration::from_millis(80),
        ..test_config()
    };
    let (connection, _events) = spawn(websocket, prepared(&row()), config).unwrap();
    let mut message = node("blocked");
    message.content = Some(Content::Bytes(vec![17; 16 * 1024]));
    assert_eq!(
        connection.send_node(message).await,
        Err(Error::OutcomeUnknown)
    );
    assert_eq!(
        connection.closed().await,
        Error::Timeout(TimeoutPhase::Write)
    );
}
#[tokio::test]
async fn graceful_close_has_a_deadline_and_pending_queries_are_not_replayed() {
    let config = Config {
        close_timeout: Duration::from_millis(60),
        ..test_config()
    };
    let (connection, _events, _unread_server) = pair(config, false).await;
    assert!(matches!(
        connection.close().await,
        Err(Error::Timeout(TimeoutPhase::Close))
    ));
    assert_eq!(
        connection.closed().await,
        Error::Timeout(TimeoutPhase::Close)
    );
}
#[tokio::test]
async fn handshake_timeout_and_untrusted_certificates_never_publish_a_connection() {
    for untrusted in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = row();
        let server_row = fixture.clone();
        let server: JoinHandle<_> = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            socket.next().await.unwrap().unwrap();
            if untrusted {
                socket
                    .send(Message::Binary(
                        bytes(&server_row["serverHelloFrame"]).into(),
                    ))
                    .await
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let mut noise = if untrusted {
            NoiseSession::new(private(&fixture["clientPrivate"]), None).unwrap()
        } else {
            session(&fixture)
        };
        let config = Config {
            connect_timeout: Duration::from_millis(60),
            ..test_config()
        };
        let result = handshake(
            &mut socket,
            &mut noise,
            &private(&fixture["clientStaticPrivate"]),
            &bytes(&fixture["clientPayload"]),
            &config,
        )
        .await;
        assert_eq!(
            result,
            Err(if untrusted {
                Error::Noise(noise::Error::InvalidCertificate)
            } else {
                Error::Timeout(TimeoutPhase::Handshake)
            })
        );
        server.abort();
        let _ = server.await;
    }
}
#[test]
fn invalid_configuration_urls_ids_and_debug_are_explicit_and_redacted() {
    for url in [
        "ws://localhost",
        "https://example.com",
        "wss://secret:password@example.com/",
    ] {
        assert!(websocket_request(url, false).is_err());
    }
    assert!(websocket_request(DEFAULT_URL, false).is_ok());
    assert!(
        Config {
            command_capacity: 0,
            ..Config::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Config {
            max_message_bytes: usize::MAX,
            ..Config::default()
        }
        .validate()
        .is_err()
    );
    let mut duplicate = node("one");
    duplicate.attrs.push(("id".into(), "two".into()));
    assert_eq!(node_id(&duplicate), Err(Error::InvalidNode));
    assert_eq!(node_id(&node(&"x".repeat(257))), Err(Error::InvalidNode));
    let ids = Ids {
        prefix: "synthetic".into(),
        next: AtomicU64::new(u64::MAX),
    };
    assert_eq!(ids.next(), Err(Error::IdExhausted));
}

#[tokio::test]
async fn outbound_memory_budget_expires_before_enqueue_without_writing() {
    let config = Config {
        max_message_bytes: 4096,
        outbound_budget: 4096,
        write_timeout: Duration::from_millis(50),
        ..test_config()
    };
    let (connection, _events, server) = pair(config, false).await;
    let held = connection
        .outbound
        .clone()
        .acquire_many_owned(4096)
        .await
        .unwrap();
    assert_eq!(
        connection.send_node(node("not-enqueued")).await,
        Err(Error::Timeout(TimeoutPhase::Queue))
    );
    drop(held);
    server.finish(connection).await;
}
#[tokio::test]
async fn reused_custom_ids_cannot_bind_a_late_reply_to_a_new_query() {
    let config = Config {
        max_custom_query_ids: 1,
        ..test_config()
    };
    let (connection, mut events, mut server) = pair(config, false).await;
    let first = {
        let c = connection.clone();
        tokio::spawn(async move {
            c.query_with_timeout(node("external-id"), Duration::from_millis(60))
                .await
        })
    };
    server.recv().await.unwrap();
    assert!(first.await.unwrap().is_err());
    assert_eq!(
        connection.query(node("external-id")).await.unwrap_err(),
        Error::DuplicateId
    );
    assert_eq!(
        connection
            .query(node("another-custom-id"))
            .await
            .unwrap_err(),
        Error::IdHistoryLimit
    );
    assert_eq!(
        connection
            .query(node(&format!("{}.123", connection.ids.prefix)))
            .await
            .unwrap_err(),
        Error::ReservedId
    );
    server.send(&result("external-id")).await;
    assert_eq!(
        node_id(events.recv().await.unwrap().node()).unwrap(),
        Some("external-id")
    );
    let fresh = {
        let c = connection.clone();
        tokio::spawn(async move {
            c.query(Node {
                tag: "iq".into(),
                attrs: vec![],
                content: None,
            })
            .await
        })
    };
    let request = server.recv().await.unwrap();
    let id = node_id(&request).unwrap().unwrap();
    server.send(&result(id)).await;
    fresh.await.unwrap().unwrap();
    events.recv().await.unwrap();
    server.finish(connection).await;
}
#[tokio::test]
async fn websocket_fragmentation_can_interleave_control_frames() {
    use tungstenite::protocol::frame::{
        Frame,
        coding::{Data, OpCode},
    };
    let (connection, mut events, mut server) = pair(test_config(), false).await;
    let wire = server.wire(&result("fragmented"));
    let split = wire.len() / 2;
    server
        .socket
        .send(Message::Frame(Frame::message(
            wire[..split].to_vec(),
            OpCode::Data(Data::Binary),
            false,
        )))
        .await
        .unwrap();
    server
        .socket
        .send(Message::Ping(vec![7].into()))
        .await
        .unwrap();
    server
        .socket
        .send(Message::Frame(Frame::message(
            wire[split..].to_vec(),
            OpCode::Data(Data::Continue),
            true,
        )))
        .await
        .unwrap();
    assert_eq!(
        server.socket.next().await.unwrap().unwrap(),
        Message::Pong(vec![7].into())
    );
    assert_eq!(
        node_id(events.recv().await.unwrap().node()).unwrap(),
        Some("fragmented")
    );
    server.finish(connection).await;
}
#[tokio::test]
async fn incoming_plaintext_and_decompressed_nodes_respect_configured_limit() {
    use std::io::Write;
    for compressed in [false, true] {
        let config = Config {
            max_message_bytes: 256,
            ..test_config()
        };
        let (connection, mut events, mut server) = pair(config, false).await;
        let mut oversized = result("large");
        oversized.content = Some(Content::Bytes(vec![7; 4096]));
        let plain = binary::encode(&oversized).unwrap();
        let raw = if compressed {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(&plain[1..]).unwrap();
            let mut frame = vec![2];
            frame.extend(z.finish().unwrap());
            frame
        } else {
            plain
        };
        let wire = server
            .encoder
            .encode(&server.cipher.encrypt(&raw).unwrap())
            .unwrap();
        server
            .socket
            .send(Message::Binary(wire.into()))
            .await
            .unwrap();
        assert!(matches!(
            connection.closed().await,
            Error::Noise(noise::Error::Binary(_))
        ));
        assert!(events.recv().await.is_none());
    }
}

#[test]
fn outbound_preallocation_bound_covers_tokens_unicode_jids_and_nested_nodes() {
    for text in [
        "",
        "iq",
        "12345",
        "ABCDEF",
        "s.whatsapp.net",
        "áé漢字",
        "1:99@hosted.lid",
        "a@b@c@d",
        "@",
        "a@",
    ] {
        for bytes in [0, 1, 4096] {
            let input = Node {
                tag: "iq".into(),
                attrs: vec![("id".into(), text.into())],
                content: Some(Content::Nodes(vec![
                    Node {
                        tag: "item".into(),
                        attrs: vec![(text.into(), text.into())],
                        content: Some(Content::Text(text.into())),
                    },
                    Node {
                        tag: "bytes".into(),
                        attrs: vec![],
                        content: Some(Content::Bytes(vec![9; bytes])),
                    },
                ])),
            };
            let encoded = binary::encode(&input).unwrap();
            assert!(encoded_reservation(&input, 1024 * 1024, 0) >= encoded.len());
        }
    }
}

#[tokio::test]
async fn concurrent_close_calls_are_idempotent_and_new_connections_have_fresh_state() {
    let (connection, mut events, mut server) = pair(test_config(), false).await;
    let first = {
        let c = connection.clone();
        tokio::spawn(async move { c.close().await })
    };
    let second = {
        let c = connection.clone();
        tokio::spawn(async move { c.close().await })
    };
    assert!(server.recv().await.is_none());
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    assert!(events.recv().await.is_none());
    connection.close().await.unwrap();
    let (next, mut events, mut server) = pair(test_config(), false).await;
    assert!(!Arc::ptr_eq(&connection.ids, &next.ids));
    assert_ne!(connection.ids.prefix, next.ids.prefix);
    assert_eq!(next.status(), Status::NoiseEstablished);
    server.send(&result("after-reconnect")).await;
    assert_eq!(
        node_id(events.recv().await.unwrap().node()).unwrap(),
        Some("after-reconnect")
    );
    server.finish(next).await;
    assert!(Error::OutcomeUnknown.delivery_uncertain());
    assert!(Error::Timeout(TimeoutPhase::Response).delivery_uncertain());
    assert!(!Error::Timeout(TimeoutPhase::Queue).delivery_uncertain());
}

#[tokio::test]
async fn prekey_bootstrap_runs_over_authenticated_transport_with_durable_private_keys() {
    use crate::{
        auth::Credentials,
        prekeys::{Manager, UploadPolicy, Uploader},
        signal::SqliteStore,
    };
    let (connection, mut events, mut server) = pair(test_config(), false).await;
    let creds = Credentials::generate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(SqliteStore::open(directory.path().join("prekeys.sqlite")).unwrap());
    let manager = Arc::new(Manager::new(&creds, store).unwrap());
    let uploader =
        Uploader::new(manager.clone(), connection.clone(), UploadPolicy::default()).unwrap();
    server
        .send(&Node {
            tag: "success".into(),
            attrs: vec![("lid".into(), "synthetic-owner:1@lid".into())],
            content: None,
        })
        .await;
    let success = events.recv().await.unwrap().into_node();
    let initialization = tokio::spawn(async move { uploader.initialize(&success).await });
    for stage in 0..4 {
        let request = server.recv().await.unwrap();
        assert!(
            request
                .attrs
                .contains(&("to".into(), crate::jid::S_WHATSAPP_NET.into()))
        );
        let id = node_id(&request).unwrap().unwrap().to_owned();
        let mut reply = result(&id);
        let Some(Content::Nodes(parts)) = request.content else {
            panic!()
        };
        match stage {
            0 => {
                assert_eq!(parts[0].tag, "count");
                reply.content = Some(Content::Nodes(vec![Node {
                    tag: "count".into(),
                    attrs: vec![("value".into(), "0".into())],
                    content: None,
                }]));
            }
            1 => {
                assert_eq!(parts[0].tag, "registration");
                let Some(Content::Nodes(keys)) = &parts[3].content else {
                    panic!()
                };
                assert_eq!(keys.len(), 812);
                assert!(
                    manager
                        .get_pre_keys(1, 813)
                        .unwrap()
                        .values()
                        .all(Option::is_some)
                );
                assert_eq!(manager.counters().unwrap().next_pre_key_id, 813);
            }
            2 => assert_eq!(parts[0].tag, "active"),
            _ => {
                assert_eq!(parts[0].tag, "digest");
                reply.content = Some(Content::Nodes(vec![Node {
                    tag: "digest".into(),
                    attrs: vec![],
                    content: None,
                }]));
            }
        }
        server.send(&reply).await;
    }
    let report = initialization.await.unwrap().unwrap();
    assert_eq!(report.prekeys.unwrap().unwrap().count, 812);
    assert!(report.active.is_ok());
    assert!(report.digest.unwrap().is_ok());
    for _ in 0..4 {
        events.recv().await.unwrap();
    }
    server.finish(connection).await;
}
