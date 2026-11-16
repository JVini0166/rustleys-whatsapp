# Compatibility progress — 2026-11-16

Baseline: WhiskeySockets/Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`.

## Implemented and exercised locally

- Borrowed JID parsing; normalization; encoding; transfer of device; suffix/category helpers; canonical LID/PN/hosted domain values.
- Generated single/double-byte token dictionaries and encoder lookup from the exact baseline.
- Ordered binary-node attributes and distinct text, bytes, children and absent content.
- Binary encoder/decoder, nibble and uppercase hex packing, JID_PAIR/AD_JID, FB/interop decoding, list8/list16, binary8/binary20/binary32, zlib frame decompression, cursor-based decoding.
- Explicit configurable bounds on frame/decompressed bytes, recursion and nodes. Oversized/deep frames deliberately fail with typed errors rather than allowing unbounded allocation.

## Verification scope

Local native Rust tests contain 2,000 JID reference cases and 1,280 binary wire/decode reference cases computed by running the pinned original TypeScript modules. The original modules are loaded with `git show <commit>:<path>` so changes in an upstream working directory do not silently change the oracle. Other tests exercise truncation, incomplete zlib streams, compression limits, malformed buffers, 20/32-bit payload lengths, list16, cursor consumption, depth and node limits. Clippy checks all targets with warnings denied.

These are differential tests of the exercised protocol utilities, not a test of live WhatsApp interoperability or a proof of entire-library parity.

## Known incomplete compatibility

- JID numeric values are Rust unsigned protocol integers. JavaScript's arbitrary values, parseInt prefixes, floating-point/NaN/Infinity coercion and numeric `user` overload are not reproduced yet. JID helpers remain partial.
- Custom token/tag coding options and caller-provided encoding buffers are not exposed yet. Binary codec remains partial.
- JavaScript runtime non-string/null/undefined attributes, unusual array members and object integer-key enumeration require a compatibility adapter/specification; Rust's current API is strongly typed with explicit attribute order.
- Binary generic utilities, WAM, USync, XEdDSA/signatures, Signal sessions, Noise handshake/certificate verification, credentials, WebSocket, pairing, message processing, history/app-state, media, groups and the rest of the socket API remain pending. Protobuf and crypto progress is detailed below.
- No pairing, sending, receiving, reconnection or production WhatsApp session has been exercised. No operational client exists yet.

## Reproduction

```sh
# Clone/reference only public upstream sources.
git clone https://github.com/WhiskeySockets/Baileys.git /tmp/baileys-reference
git -C /tmp/baileys-reference checkout bb0a87e0326ca8f882fe716c7ee42da362f73fc0
npm ci --ignore-scripts
npm run fixtures:jid -- /tmp/baileys-reference
npm run fixtures:binary -- /tmp/baileys-reference
cargo fmt
CARGO_BUILD_JOBS=1 cargo test --locked
CARGO_BUILD_JOBS=1 cargo clippy --locked --all-targets -- -D warnings
```

Node/TypeScript is used only to generate reference test fixtures; the Rust library does not call into Node or TypeScript. Builds/tests for this project are explicitly authorized locally by the user. No production FarenX service, app or integration was modified; its current `baileys` dependency remains unchanged.


## Protobuf and crypto checkpoint

`proto/WAProto.proto` is the verbatim pinned upstream schema. The build normalizes 23 non-zero-first enums into a separate OUT_DIR file for protoc, without changing any upstream field number or enum value. A synthetic namespaced zero value is added only where protoc requires it, or an existing zero variant is moved first. Generated Rust types/descriptors are checked against all 498 upstream message types, 174 enums and 2,424 fields (including map key/value types).

2,424 per-field inputs are encoded by the original generated protobuf.js bindings and decoded as typed protobuf values in Rust. The reverse check encodes each case with Rust, then independently decodes it with those same original JS bindings; values agree with 2 valid default-field/canonical wire encoding differences. Four additional cases document conflicting oneof JSON accepted by legacy protobuf.js; standard protobuf JSON rejects these while the wire uses last-one-wins. These incompatibilities remain explicit rather than silently deleting the cases.

The original generated fixed64 JSON helper represents an unsigned maximum as `-1` for SignedPreKeyRecordStructure.timestamp. Fixtures retain that legacy JSON alongside the schema-level input and original bytes. Rust uses the schema's unsigned fixed64 values. Other legacy JSON/default/accessor semantics, unknown-field behavior across generated JS/Rust structs, and full protobuf.js helper API parity are still pending; generated schema/wire coverage does not establish those behaviors.

Crypto runtime code uses RustCrypto and x25519-dalek, with no JS/WASM calls. Local differential vectors cover 13 datasets across AES-CBC/CTR/GCM, SHA256, MD5, HMAC256/512; 18 HKDF cases; 16 X25519 agreements; and PBKDF2-SHA256 pairing key derivation with 131,072 iterations. Tests also reject altered GCM tags/AAD, invalid keys/IVs/padding, HKDF oversize outputs and non-contributory X25519 points. Generated private-key state has redacted Debug and derives zeroization on drop.

The GCM adapter currently accepts the 12-byte IV used by Noise. Arbitrary-length IVs accepted by Node crypto, Curve XEdDSA signatures/verification, signed prekeys and key/session persistence remain pending. No authentication/certificate checks have been bypassed to obtain a connection.

Additional reproduction commands (local, one build job):

```sh
npm ci --ignore-scripts
npm run fixtures:crypto -- /tmp/baileys-reference
npm run fixtures:proto -- /tmp/baileys-reference
cargo fmt
CARGO_BUILD_JOBS=1 cargo test --locked
npm run verify:proto -- /tmp/baileys-reference
CARGO_BUILD_JOBS=1 cargo clippy --locked --all-targets -- -D warnings
```
