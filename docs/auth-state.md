# Authentication state checkpoint — 2026-11-16

Upstream baseline: `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`.

## Implemented

`auth::Credentials` generates noise, pairing ephemeral, signed identity and signed prekeys with the same default fields as `initAuthCreds`. Import/export uses the Baileys camelCase layout and BufferJSON base64 objects. Unknown credential/settings extensions are retained. Contact, account, history and additional-data objects are preserved as JSON until their respective protocol layers interpret them. `assert_me_id` fails before authentication.

Imported keys are checked for public/private consistency and signed prekeys must verify. The advertising secret must decode to 32 bytes and registration IDs must fit the protocol's 14 bits. Public extension maps cannot shadow known fields and create duplicate JSON members. Byte values/private key diagnostics are redacted; owned byte buffers, the advertising secret, pairing code and serialized read/write buffers are zeroized on drop. Arbitrary preserved JSON metadata and serializer-internal temporary allocations do not have a complete zeroization guarantee. Serialization deliberately exports plaintext credentials, as in the original adapter.

The pinned upstream registration helper uses `Uint16Array.from(randomBytes(2))[0]`, which keeps only the first random byte. The exact 0–255 behavior is retained and covered for all 256 byte values; the importer accepts the full valid 14-bit range. This is recorded rather than silently claiming that the original samples 14 random bits.

`auth_store::MultiFileStore` reads/writes the upstream `creds.json` and all ten `SignalDataTypeMap` filename categories. It normalizes `/` to `__` and `:` to `-`, returns null for missing keys, supports the original adapter’s falsy-value deletion behavior and retains stored BufferJSON/protobuf objects. Writes use a same-directory temporary file, file fsync, atomic replacement and (on Unix) directory fsync. New directories/files use 0700/0600 on Unix. Per-directory advisory file locks serialize operations across Rust store instances. Files are size-bounded and symlink redirects are rejected (with O_NOFOLLOW on Unix).

## Verified interoperability

Fixtures execute the original pinned `initAuthCreds`, `assertMeId`, BufferJSON and registration helper. Eight offline credential states include authenticated/unauthenticated metadata and future fields. No real WhatsApp account or customer data is used.

The reverse check executes the actual pinned `useMultiFileAuthState` helper: JS writes credentials and all ten categories, Rust imports and exports them, and JS reads them back with equal values. AppStateSyncKeyData is constructed by the original JS adapter. Fresh Rust-generated credentials are also opened in JS, their four keypairs checked by original libsignal-node, and their signed prekey independently verified.

Rust tests cover restart/reopen, malformed JSON, corrupted signatures/keys, oversized files, ambiguous byte formats, missing/deleted records, private permissions, symlink rejection, invalid paths, batch prevalidation and concurrent store instances, and readers that do not participate in the Rust lock. Concurrent writes/readbacks use independent store handles and produce complete parseable files without leftover temporary files.

## Explicit differences and remaining work

- Corrupt/unreadable credentials fail explicitly. The original helper catches all read errors and may silently generate a new identity; Rust only initializes on an absent file.
- This is blocking filesystem I/O. A future async socket/storage bridge must execute it off the network executor. Do not simultaneously write the same folder with the JS adapter: its file mutexes do not participate in the Rust advisory lock.
- Each file is replaced atomically. A multi-key batch is not crash-atomic across files and can be partially persisted if a later I/O operation fails. Transactions need a transactional store or explicit journal; the upstream adapter has the same multi-file limitation.
- Original filename normalization can collide (`a/b` and `a__b`, or `a:b` and `a-b`). This legacy layout is preserved for import compatibility. Do not claim collision-free arbitrary identifiers. Backslashes and control characters are rejected to prevent unsafe path interpretation.
- Imported BufferJSON accepts valid base64, byte arrays and contiguous numeric-key objects. JavaScript's permissive invalid base64, arbitrary numeric coercion, prefix-parsed/noncontiguous numeric objects and other invalid runtime values are deliberately rejected or pending.
- The key API currently preserves JSON values rather than exposing all protobuf and Signal categories as typed protocol records. JS prototype/helper behavior is not reproduced by retaining JSON alone.
- The cache wrapper, transaction capability/retries, prekey deletion manager, database adapters and typed session-state bridge remain pending. `auth-utils.ts`, `generics.ts`, `Types/Auth.ts` and `use-multi-file-auth-state.ts` remain partial.
- No QR pairing, WebSocket session, Signal message ratchet or live WhatsApp interoperability has been exercised. Credentials/storage tests do not establish a functioning WhatsApp client.

## Reproduce locally

```sh
npm ci --ignore-scripts
npm run fixtures:auth -- /tmp/baileys-reference
CARGO_BUILD_JOBS=1 cargo test --locked --test auth_compatibility
npm run verify:auth -- /tmp/baileys-reference
```

Use the pinned upstream revision and a synthetic test folder only. This project is independent of both FarenX fronts and its services; no UI, production API, customer database or deployed session is changed.

Checkpoint validation: 13 auth/storage tests passed, the existing 26-test suite passed, Clippy passed with warnings denied, and both storage and 2,424-vector protobuf reverse checks passed. npm audit reported zero advisories after updating the development-only protobuf.js oracle. All validation ran locally with one Cargo build job and low process priority.
