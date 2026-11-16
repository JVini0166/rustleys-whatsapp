# Group sender keys — 2026-11-16

Baseline: Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`. Native cryptographic primitives use the already pinned MIT/BSD `wacore-libsignal` engine. The Rust runtime does not execute JavaScript or WASM.

## Implemented operations

`signal::Repository` now supports group sender-key distribution creation/processing, group encryption/decryption, existence checks and explicit sender-key deletion for host-driven rekeying. Distribution state, counters, skipped keys and private signing material use the existing transactional SQLite backend. No plaintext, ciphertext or new distribution leaves an operation until its transaction commits.

`group_signal::SenderKeyName` provides serialization, equality, group/sender/device getters and the original signed 32-bit hash using UTF-16 code units. Typed Message.SenderKeyDistributionMessage helpers connect the generated protobuf payload to repository validation; exporting that payload deliberately copies the secret seed into the protobuf object and must never be logged. The repository helper maps PN/LID/hosted domains through the same Signal address conversion as pairwise sessions. Names use `group::signal-user::device`.

The pinned Baileys GroupCipher intentionally observed in tests sends iterations 0, 2, 4…: after the first encryption it requests the current iteration plus one and saves the skipped seed. Rust preserves that wire/state progression rather than silently using the engine's ordinary 0, 1, 2… sender progression. Generated sender IDs also preserve the exclusive upper bound of `crypto.randomInt(2147483647)`.

Receivers verify XEdDSA signatures before consuming message keys, handle reordered messages, reject replay/invalid frames and retain at most five sender states and 2,000 skipped keys per state. Counter exhaustion fails without wrapping. A receive-only distribution never becomes private signing material.

## Authenticated refresh and bounded recovery

A sender-key distribution is not self-authenticating and contains a secret chain seed. The host must obtain it from the authenticated pairwise envelope for the declared author, enforce group membership/routing and distribute it only to authorized members. These network/product layers are not implemented yet.

A repeat distribution for the same ID/signing public key does not rewind consumed keys. A newer distribution within the 2,000-key window advances the known chain, checks the supplied seed in constant time and retains intermediate skipped seeds. An inconsistent seed aborts without changing stored state. A fresh authenticated distribution beyond the normal gap limit resumes from its supplied seed without hashing an unbounded backlog; previously retained skipped keys remain, but the unmaterialized middle gap is abandoned. This is bounded recovery for future traffic, not a promise to recover every missed historical message.

This refresh policy is explicit and differs from the legacy duplicate-state append/selection behavior. Different key IDs retain five distinct states; a reused ID with a different signing key follows the native engine's replacement policy. Malformed/version-invalid inputs fail strictly. Full equivalence for every legacy duplicate-ID, reset and retention edge case is not claimed.

## Original legacy JSON bug found by the oracle

The original `signalStorage.storeSenderKey` writes `JSON.stringify(record.serialize())`. Buffer seeds become `{type: 'Buffer', data: [...]}` objects. The original `SenderKeyRecord.deserialize` uses BufferJSON.reviver, which restores base64-string buffers but does not restore that array-backed Buffer shape. The ordinary current-chain path calls Buffer.from and often works; the skipped-message-key path passes the object directly to libsignal's deriveSecrets and fails with `Expected Buffer instead of: Object`.

The committed fixture generator and cross-runtime verifier reproduce this on the pinned original modules: receive a later packet, persist the record, then receive the earlier packet. This failure is retained as reference evidence, not reproduced in the Rust implementation. Native protobuf snapshots preserve the skipped seeds as bytes, and the corresponding reordered sequence succeeds in Rust across reopened stores.

To test cryptographic interoperability beyond this legacy adapter failure, the active JS peer runs the unchanged original Baileys group modules with a correctly typed BufferJSON store (the original BufferJSON.replacer plus original SenderKeyRecord.deserialize). This is a storage adapter used by the test oracle. It does not claim that the unmodified original signalStorage factory passes those reorder tests. The legacy serializer failure is separately asserted on every run before the typed-store comparison.

## Validation scope

- Sixteen messages and two initial distributions come from the original Baileys group modules, using the legacy serializer for the generating sender. Rust decrypts them out of order and across reopened SQLite stores. The reference fixture records the original legacy receiver error described above.
- Ninety-six original SenderKeyName cases cover empty/long/non-ASCII/astral strings, device IDs up to u32::MAX, serialization, equality and UTF-16 hash behavior.
- The active comparison verifies forty messages in four contexts, both Node→Rust and Rust→Node, using PN and hosted-LID authors. It checks empty/binary payloads, original counter progression, signatures, reordered batches, rekeys and actual native process restarts. The JS cryptographic peer uses the typed BufferJSON adapter, with the original legacy-adapter regression checked separately.
- Native tests cover two receivers, late joiners, five-state retention, sender rekeying, malformed input, signature tampering, wrong author/group, skipped keys, future limits, counter exhaustion and receive-only state.
- Deferred SQLite foreign-key failures exercise COMMIT failure during distribution creation, first/existing-chain encryption and decryption. No result is returned; failed sends retain the previous counter, and failed receives remain decryptable after reopening.
- Authenticated refresh tests resume beyond a 5,000-step gap, retain in-window delayed keys, reject inconsistent seeds and ensure that a stale distribution cannot revive a consumed message.

## Remaining work

These are cryptographic group primitives and repository operations. Group creation/metadata, participant administration, actual membership changes, network distribution acknowledgements, media/history/message ingestion, PN↔LID mapping and the WhatsApp socket are still pending. Application message/outbox storage is not yet committed together with Signal state. Rekey deletion is only a host hook; it does not update membership or notify clients on its own.

Native records are protobuf snapshots, not the original sender-key JSON format. Legacy record import/export, every public JS helper/getter/class API, custom JS Sender objects, coercion/default semantics, full older-key compatibility and all upstream tests remain to be completed. Group files stay marked partial. The typed SenderKeyName mirrors standard Signal sender addresses; arbitrary custom JS toString implementations are outside that tested representation.

All data is synthetic. No live WhatsApp account, customer session or FarenX production component was used or changed. There is still no operational WhatsApp client.

```sh
npm run fixtures:groups -- /tmp/baileys-reference
CARGO_BUILD_JOBS=1 cargo test --locked --test group_compatibility
npm run verify:groups -- /tmp/baileys-reference
```

Checkpoint validation: all 63 Rust tests passed. The separate group comparison passed 40 messages with the typed JS oracle adapter, and the pairwise regression still passed 84 messages after sharing the oracle process harness. Builds/tests run locally with one Cargo job and low priority.
