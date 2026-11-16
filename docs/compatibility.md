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
- Binary generic utilities, protobuf schemas/bindings, WAM, USync, cryptography, Signal, Noise, credentials, WebSocket, pairing, message processing, history/app-state, media, groups and the rest of the socket API remain pending.
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
