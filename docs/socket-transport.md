# WebSocket and Noise transport — 2026-11-16

Baileys baseline: `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`, particularly `src/Socket/Client/websocket.ts`, `src/Socket/Client/types.ts` and the raw-send, handshake, query and keepalive parts of `src/Socket/socket.ts`. Their inventory status remains **partial**. No FarenX app/service or customer account participates in these tests.

## Implemented path

`socket::Connection::connect` validates configuration/credentials and the supplied `proto::ClientPayload`, establishes a TLS WebSocket with origin `https://web.whatsapp.com`, sends the WA intro/client hello, verifies the pinned WhatsApp Noise certificate chain, sends the encrypted client finish, and starts a single-owner transport task. It uses Tokio, tokio-tungstenite/rustls and the already verified Rust Noise and binary-node codecs. Production accepts only `wss:` and provides no custom Noise trust-root or plaintext bypass.

The raw socket URL defaults are exported as constants; the host passes the actual URL, optional routing bytes and prepared client payload explicitly. `NoiseEstablished` only means the encrypted transport is ready. It does **not** mean the account is logged in, paired or able to exchange WhatsApp messages. [Payload builders and authenticated pairing primitives](pairing.md) are now available, with `connect_account` selecting/building the payload. Automatic QR/pairing orchestration, success/failure stream handlers, prekey upload, sync, messaging and the rest of the socket facade are still required.

After handshake, one task owns the WebSocket, Noise keys, counters and frame parser. Cloned handles enqueue operations; they never clone cryptographic state. Fragments across WebSocket messages, RFC WebSocket fragmentation/control frames and several Noise frames in a single message are supported. Coalesced server-hello/transport input is decoded in the correct phase. A failed write, authentication failure or protocol error terminates that connection; reconnection creates a new transport and fresh ephemeral keys. There is no automatic retry or request replay.

## Queries and results

`send_node` only confirms a flushed WebSocket write, never remote delivery. `query`/`query_with_timeout` register correlation **before** sending, match authenticated node IDs and return structured server-error codes for an `error` child. Every received node is also sent to the event channel, including replies and late responses. Server error text and close reasons are not copied into diagnostic errors; the original authenticated node remains explicitly available through events.

Generated IDs combine a random per-connection prefix and an atomic, checked sequence. Caller-provided IDs must be unique for that connection, including after timeout/cancellation/completion. A bounded SHA-256 fingerprint set detects reuse without keeping arbitrary identifier text. The generated prefix is reserved so custom IDs cannot imitate an automatically generated request. When the custom-ID history fills, new custom IDs fail explicitly; automatic IDs remain available without an ever-growing history set. These stricter rules prevent a late response from satisfying a later request with a recycled ID.

Cancellation frees pending slots before the next query is admitted. Already-written requests are not undone. A timeout before enqueue is `Timeout(Queue)`; a timeout awaiting a response, uncertain partial write or connection loss can mean the peer received it. `Error::delivery_uncertain()` identifies those outcomes. Never infer safe retry from a missing response. Pending queries fail on connection termination, and shutdown does not replay them.

## Bounds and lifecycle

Defaults are 20-second connection/handshake/write timeouts, 60-second queries, a 5-second close deadline, and a protocol keepalive every 30 seconds with a 5-second idle grace. Keepalive uses an encrypted `iq`/`w:p` ping. WebSocket Ping is answered but does not fabricate Noise-level activity. Idle expiry is enforced at its deadline rather than waiting for another interval tick, which can close an idle peer sooner than legacy polling. All deadlines are based on a monotonic clock; there are no overlapping detached keepalive jobs.

The defaults allow 128 queued commands, 256 queued events, 1,024 pending queries and 8,192 custom query-ID fingerprints. Both queued encoded outbound payloads and queued/held events have separate 64 MiB budgets. Before encoding, an outbound call reserves a conservative allocation bound and releases the unused portion after encoding; waiters do not accumulate an additional uncharged encoded copy. Encoded queued plaintext is zeroized on drop. An event holds its byte permit until dropped or `into_node()` transfers ownership to the host.

These are queue/payload budgets, **not** a promise that total resident memory is 128 MiB: caller-owned input/output nodes, parser/WebSocket/TLS buffers, decoder working memory, allocator metadata and task state are additional. Noise frame lengths, WebSocket message/frame sizes, decompression, node depth/count and the total attribute count have independent bounds. Binary decoding now caps total attribute pairs at 65,535 by default and uses a hash index on large attribute tables to preserve first-key order/last-value semantics without quadratic duplicate lookup.

Event consumers must continuously drain `Events`. If count/byte capacity is exhausted, the connection closes with `Backpressure`; it does not silently overwrite buffered events or block the socket reader forever. Already queued events can still be drained, with final status available separately. Dropping the event receiver or all connection handles stops the task. Explicit close is bounded, waits for the peer, and is idempotent across simultaneous callers.

## Evidence and limits

Local tests establish real loopback TCP/WebSocket connections. Synthetic certificate chains, handshake bytes and transport keys come from the pinned original Baileys Noise implementation; the arbitrary test root is injected only in code compiled with `cfg(test)`. The production pin rejects that same synthetic certificate. There is no production custom-root API.

Tests cover handshake intro/origin, fragmented and coalesced input, both WebSocket and Noise boundaries, concurrent/out-of-order queries, immediate/late/error replies, duplicate/recycled IDs, cancellation/expiry, queue/byte pressure, partial write uncertainty, event memory release, malformed/corrupt/replayed packets, decompression limits, Ping/Pong, idle detection, close deadlines, simultaneous close and fresh connection state. Existing original-generated wire fixtures continue to exercise the codec/Noise cryptography independently. The local full suite passed 117 tests, including 23 socket tests and two additional attribute-limit/large-table regressions. Clippy passed with warnings denied.

No WhatsApp server or live account has been contacted. Public-CA TLS success/failure, network proxy agents, configurable headers, redirects, a JavaScript-compatible EventEmitter/callback facade, all original URL/routing options and a full operational pairing/reconnect workflow have not been established. Rust has a bounded typed async API rather than a drop-in JavaScript object. No full Baileys API or protocol parity is claimed.

References for the transport dependency contracts: [tokio-tungstenite](https://docs.rs/tokio-tungstenite/0.30.0/tokio_tungstenite/) and [WebSocketConfig](https://docs.rs/tungstenite/0.30.0/tungstenite/protocol/struct.WebSocketConfig.html). Dependency versions/checksums are locked in `Cargo.lock`.

```sh
nice -n 15 env CARGO_BUILD_JOBS=1 cargo test --locked --lib socket::tests
nice -n 15 env CARGO_BUILD_JOBS=1 cargo test --locked
nice -n 15 env CARGO_BUILD_JOBS=1 cargo clippy --locked --all-targets -- -D warnings
npm run fixtures:noise -- /tmp/baileys-reference
```
