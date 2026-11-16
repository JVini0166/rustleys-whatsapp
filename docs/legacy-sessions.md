# Legacy pairwise session import — 2026-11-16

Baseline: Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`, using its development dependency libsignal-node 6.0.0 as the independent JSON/wire oracle. This module independently converts the serialized data format; it does not translate the JavaScript cryptographic implementation. The Rust runtime keeps the pinned native engine and invokes no Node/JS/WASM code.

## Import contract

`Repository::import_legacy_session(jid, json_bytes)` converts a libsignal-node `SessionRecord.serialize()` object into the native session store. The host must authenticate the file's provenance and supply the **same local identity and registration credentials** as the original account. Legacy session JSON does not include the local identity, so the importer cannot establish that relationship from this file alone. Do not use this API as an untrusted network endpoint or merge sessions from different accounts.

The import resolves committed PN/LID aliases and writes the session and current remote identity in one transaction. It rejects an existing session at the resolved address, even for a repeated identical import. It also rejects a conflicting persisted remote identity. This deliberately prevents a stale snapshot from rolling back a ratchet. The report exposes only counts of open/archived sessions, receiving chains and skipped keys.

Supported data includes v1 records, the original unversioned registration fallback, pending signed/one-time prekeys, outgoing chains, active and closed receiving chains, skipped message-key seeds, an open session and up to 40 archives. Stored chain counters refer to the last generated key; the native representation refers to the next key. The converter accounts for that difference and preserves the legacy previous-counter wire value, including `-1` represented as unsigned protobuf `0xffffffff`.

Private/public ephemeral key correspondence, base-key indexes, key sizes, canonical padded base64, chain roles, timestamps, counter ranges and skipped-key indexes are validated. Duplicate object keys, ambiguous multiple open sessions, unsupported versions/fields and malformed state fail explicitly. Unknown state is never silently dropped. Errors contain no supplied key strings or JSON. Parsed key strings and temporary encoded buffers are zeroized when dropped; the caller remains responsible for its input buffer and exported credential material.

Bounds are 16 MiB of input, 41 total sessions, 1,024 chains per session and 32,768 skipped keys across the whole record. These are explicit resource limits, not claims that every legacy backlog or malformed JavaScript value is supported. The native engine still applies its own future-message and receiving-chain retention policies during later traffic; full retention-policy parity with libsignal-node remains pending.

## Archive behavior

The native engine normally promotes a successfully decrypted archive to current. libsignal-node's ordinary backlog handling does not reopen a closed session. The repository now restores the pre-existing open session after successful archived decryption while persisting the archive's consumed keys. A closed-only record stays closed. A new authenticated prekey handshake can still establish a new open session. MAC failures, duplicate packets and failed database commits never publish plaintext or modify durable state.

The live-peer comparison checks this distinction by importing a record containing both an open session and an older archive, reading delayed packets from both, and then continuing the open conversation in both directions. Merely decrypting a fixed archived message would not have detected the erroneous promotion.

## Original implementation regression

The fixture generator also runs a separate, deliberately tied synthetic clock. With equal usage timestamps, libsignal-node can try an older session first and modify its ratchet before checking the MAC; a later valid-session attempt saves the mutated archive along with the successful result. A previously queued packet for that archive then fails in the original Node implementation as well as after a faithful Rust import.

`legacy-archive-regression.json` retains that original-produced synthetic record and the failing packet. Rust rejects the packet and preserves its durable state byte-for-byte. Import cannot reconstruct keys already lost/corrupted by the source implementation; it does not fabricate successful recovery. Ordinary interoperability fixtures use a strictly increasing synthetic clock and are independently checked by Node before Rust receives them.

## Evidence and remaining scope

The generator creates 12 original JSON records covering both handshake initiators, with/without one-time prekeys, an unsent pending outgoing session, skipped packets, ordinary archives and delayed archived prekey envelopes after the one-time key was consumed. The active peer verifier repeats these scenarios five times: **780 messages across 60 contexts**, including process restarts, continued bidirectional ratchets and overwrite rejection. Nine native import tests also exercise malformed/ambiguous state, duplicate JSON keys, limits, closed-only records, alias resolution, identity conflicts, transactional rollback and a deferred SQLite COMMIT failure. The full native suite currently has 92 passing tests. The independent PN/LID migration regression also passed with 92 bidirectional messages after this repository change.

No production/customer account or WhatsApp server was used. Full export to legacy JSON, timestamp/index metadata round-tripping, automatic multi-file import, arbitrary historical variants, group-key import and complete async storage/network integration remain pending. Signal files remain partial in the compatibility inventory. This checkpoint does not make the WhatsApp client operational or establish full Baileys parity.

```sh
npm run fixtures:legacy-sessions -- /tmp/baileys-reference
nice -n 15 env CARGO_BUILD_JOBS=1 cargo test --locked --test legacy_sessions
nice -n 15 npm run verify:legacy-sessions -- /tmp/baileys-reference
```
