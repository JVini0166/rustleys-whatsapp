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
- Binary generic utilities, WAM, USync, WebSocket, pairing, message processing, history/app-state, media, groups and the rest of the socket API remain pending. Protobuf and crypto progress is detailed below.
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

The GCM adapter currently accepts the 12-byte IV used by Noise. Arbitrary-length IVs accepted by Node crypto, key/session persistence remain pending. XEdDSA and Noise progress is documented below. No authentication/certificate checks have been bypassed to obtain a connection.

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

## Signal signatures and Noise checkpoint

XEdDSA and signed prekeys use the native Rust `wacore-libsignal` dependency pinned to `3f21778971e36f796b41b1180ef04da075968750`; minimum Rust version is now 1.95. Sixteen signatures generated by original libsignal-node verify in Rust. Independently, sixteen Rust-generated signatures and signed prekeys verify with libsignal-node. Malformed lengths, changed messages and forged signatures are rejected.

There is an intentional security difference from the pinned Baileys wrapper: `Curve.verify` ignores a false return from libsignal-node and returns true unless an exception is thrown. The committed oracle records this behavior for 16 corrupted signatures. Rust checks the actual verification result. The port also requires the leaf certificate's key to match the Noise static key and its issuer to match the intermediate serial. Unsafe acceptance is not reproduced.

Noise XX transcript hashing, DH/HKDF, authenticated client/server handshake, payload encryption, independent transport counters, routing intro and 24-bit framing match original wire output in three offline cases (absent, empty and nonempty routing). Eight malformed/untrusted certificate cases fail closed. Other tests cover fragmented/coalesced packets across the handshake-to-transport transition, tampering, replay, nonce exhaustion and input bounds. Transport failures are terminal; keys are zeroized on failure/drop. A session cannot enter transport before certificate verification and client payload encryption. Synthetic trust roots exist only in private unit tests; the public session constructor pins WhatsApp's root.

The existing upstream test that calls `finishInit` before any handshake is deliberately not reproduced by the public session API. Rust requires exclusive mutable access to counters/parser state instead of concurrent callback mutation. Custom Noise headers, arbitrary low-level transcript manipulation, logger callbacks and the full JS handler API are not exposed. Time-based certificate policy and live server interoperability remain unverified; this module remains partial.

No live WhatsApp connection or real account has been used. The fixtures contain synthetic keys and messages only. These tests validate wire interoperability in the exercised layer, not pairing, Signal session persistence or a working WhatsApp client.

```sh
npm run fixtures:noise -- /tmp/baileys-reference
npm run verify:signatures
```

Validation for this checkpoint: 26 Rust tests passed, Clippy passed with warnings denied, 2,424 reverse protobuf cross-runtime vectors passed, and 16 Rust signatures plus 16 signed prekeys passed independent libsignal-node verification. All validation ran locally with one Cargo build job.

## Authentication state checkpoint

Credential initialization, BufferJSON key import/export, authenticated-ID checks and multi-file persistence now have local differential tests and a JS → Rust → JS storage interoperability check. See [auth-state.md](auth-state.md) for exact guarantees, intentionally stricter failures, pending cache/transaction/category APIs and reproduction. No live account was used.

The development-only protobuf.js oracle is now pinned to 7.6.6, within upstream's declared ^7.5.6 dependency range, after npm audit reported recursion/parser advisories in 7.5.6. The original generated Baileys sources stay pinned; retained wire fixtures and independent reverse checks detect changed behavior. This package is not part of the Rust runtime.

## Signal pairwise checkpoint

A native transactional repository now exercises X3DH, prekey/ordinary messages and Double Ratchet against libsignal-node. SQLite commits session, identity and one-time prekey state before returning output. See [signal-sessions.md](signal-sessions.md) for the 84-message cross-runtime exchange, address/corpus coverage, failed-commit evidence and explicit remaining group/LID/legacy-storage work. No live WhatsApp client is claimed.

## Group sender-key checkpoint

Transactional group distribution/encryption/decryption now has original-wire fixtures, typed sender-name hashing, bounded authenticated refresh and both-direction original-module comparisons. The verifier separately reproduces the pinned legacy JSON skipped-key failure, then uses an explicitly typed BufferJSON adapter for the unchanged JS cryptographic modules. See [group-sessions.md](group-sessions.md) for evidence, intentional policy differences and remaining network/legacy-API work.

## PN/LID checkpoint

Native mapping/cache/coalescing, reciprocal cleanup and transactional session migration now have differential vectors and source-regression characterization. Crypto operations resolve committed aliases in their transaction. See [lid-mapping.md](lid-mapping.md) for corrected upstream behaviors, conflict preservation, async/legacy/archive limitations and reproduction. Live socket/USync integration is still pending.
