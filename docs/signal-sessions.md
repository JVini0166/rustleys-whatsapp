# Signal pairwise sessions — 2026-11-16

Baseline: Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`, development oracle libsignal-node 6.0.0. Native cryptographic transitions use the already pinned `wacore-libsignal` revision `3f21778971e36f796b41b1180ef04da075968750` (MIT AND BSD-3-Clause). No Node/JS/WASM is invoked by the Rust runtime.

## Implemented behavior

`signal::Repository` initializes outgoing X3DH sessions, authenticates signed prekeys, handles incoming prekey (`pkmsg`) and ordinary (`msg`) messages, advances the Double Ratchet, retains skipped message keys for out-of-order delivery and rejects duplicate/authentication failures. One-time prekeys are consumed atomically with the first successfully authenticated incoming session. A repeated prekey wrapper can use an existing session after that prekey has been consumed, including after local signed-prekey rotation.

Domain-aware Signal addresses distinguish phone-number, LID, hosted and hosted-LID domains, reject empty/dotted protocol names and reject device 99 outside hosted domains. Session information exposes the tagged base key and remote registration ID. Bulk session deletion is atomic within the store transaction.

The default identity policy follows Baileys' automatic trust/replacement behavior; it is not manual identity verification. A changed remote identity clears the previous session only after the new prekey message authenticates and the transaction commits. A forged replacement cannot erase the existing session. The SQLite store is bound to the local public identity and registration ID so another local account cannot accidentally reuse its sessions.

## Persistence contract

The `Store` and `Transaction` traits let a host supply another backend. A backend must serialize concurrent read-modify-write operations, commit all changes atomically, and roll everything back on any error. Returning success before durability would violate the contract.

`SqliteStore` implements that contract using an immediate SQLite transaction, WAL and FULL synchronization. Message/session updates, identity changes and one-time prekey deletion are committed together before returning plaintext or ciphertext. The engine's reservation opt-out is used only inside that persistence-before-publication boundary: every encrypted message is persisted before it can leave the repository. Failed commits return no message and retain the previous chain position. This does not yet make application-message ingestion/outbox persistence atomic with Signal state: durable message delivery/recovery still needs integration in the future send/receive layer. SQLite errors retain operation names and extended error codes without exposing SQL text, parameters, paths or key material.

The database uses native protobuf state snapshots in the `rustleys_signal_keys` table, not libsignal-node SessionRecord v1 JSON. Session-state blobs are bounded to 128 MiB and message inputs to the engine's 16 MiB envelope budget (outbound plaintext leaves room for framing). Database files are private (0600) on Unix and symlink database paths are rejected. Canonical parent aliases, including macOS /var, are resolved before SQLite's no-follow open. SQLite's own WAL/journal files are managed by SQLite; no claim is made about an encrypted-at-rest store or complete zeroization of SQLite's internal memory.

Calls perform blocking database/crypto work and must run off a future async network executor. Use one store/account; callers should not place unrelated accounts into a single repository database. The current backend serializes transactions and is not a claim of multi-host/distributed storage availability. Power-loss behavior beyond SQLite's documented durability guarantees has not been physically fault-tested.

## Evidence

- Sixteen committed prekey message vectors were produced by the original libsignal-node implementation, with and without one-time prekeys. Rust decrypts them in a different order and across reopened store instances.
- The active cross-runtime test runs independent Node and Rust peers in four sessions (both initiator directions, both prekey modes). Eighty-four messages are decrypted by the opposite implementation, including binary/empty-size vectors in the committed corpus, five reply rounds, reordered batches, duplicate rejection and actual Rust process termination/restart. Base-key and registration metadata agree with the Node session.
- Seven hundred twenty address outcomes come from executing the original Baileys repository helper and libsignal ProtocolAddress constructor.
- Native tests cover multiple ratchet rounds, duplicates, bad MACs, bad signatures, missing/corrupt state, signed-key rotation, remote identity replacement, session deletion, local account binding and private files.
- A deferred SQLite foreign-key violation forces COMMIT itself to fail after session/identity/prekey mutations have executed. The test confirms that the session and identity are absent and the prekey remains; the same packet succeeds after reopening once the injected failure is removed.
- A failed encryption transaction leaves the stored sending chain unchanged and exposes no ciphertext. Four concurrent independent SQLite connections generate unique sending counters and all messages decrypt, proving that the read-modify-write operations do not lose updates.

## Remaining compatibility work

Group sender keys now have their own [partial checkpoint](group-sessions.md). PN↔LID mapping and native session migration now have a [partial checkpoint](lid-mapping.md). Full libsignal-node v1 record round-tripping, generic auth-store transaction/cache wrappers, trust-policy configuration, lookup of older signed prekeys for previously unknown sessions and the rest of the repository/socket API remain pending. The native session repository is not yet automatically connected to the multi-file JSON key adapter; bounded explicit import is available as described below. Strict malformed-input and identity-update ordering differences are intentional and must remain explicit.

Rust unsigned JID numbers do not reproduce legacy JS NaN/fractional/prefix coercions. The 720-address check covers valid numeric domains/devices plus ordinary invalid names/hosted combinations; it does not prove those known coercion differences absent. Native retention limits and stored metadata are inherited from the pinned engine; complete legacy retention/order/timestamp behavior and every upstream fixture are not claimed as equivalent.

No WebSocket/QR pairing or live WhatsApp session was used. Offline Signal interoperability is not proof of a working WhatsApp client or full Baileys parity. FarenX production, both fronts and all existing services are unchanged.

```sh
npm run fixtures:signal -- /tmp/baileys-reference
npm run fixtures:signal-addresses -- /tmp/baileys-reference
CARGO_BUILD_JOBS=1 cargo test --locked --test signal_compatibility
npm run verify:signal -- /tmp/baileys-reference
```

Checkpoint: 51 native Rust tests passed, Clippy passed with warnings denied, and the separate 84-message Node/Rust exchange passed. All builds and checks ran locally with CARGO_BUILD_JOBS=1 and low priority. This checkpoint changes only the independent rustleys-whatsapp repository.


A bounded [legacy JSON importer](legacy-sessions.md) now covers established and pending pairwise records, skipped keys and archives. Reading an archive updates that archive without changing the open session. This is tested against original Node peers, including continued traffic after import; full legacy storage import/export remains incomplete.


[Native prekey reservation/upload](prekeys.md) now supplies transactional one-time keys to this repository. A narrowly scoped authenticated adapter handles the original Node encoder omitting ID zero; malformed/replayed packets and failed commits still release no plaintext or private-key state. Signed-key history remains pending.
