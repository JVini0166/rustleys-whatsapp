# Prekey reservation, upload and login bootstrap — 2026-11-16

Baseline: Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`, using the original `Utils/signal.ts` prekey helpers and the upload/count/passive/digest logic in `Socket/socket.ts`. Both files remain partial in the inventory. This library and its tests are independent of FarenX production.

## Native durable key state

`prekeys::plan` reproduces the exercised range/counter arithmetic: reuse keys from `firstUnuploadedPreKeyId`, generate the remainder from `nextPreKeyId`, and advance the reserved range. `Manager::prepare` saves new private keys and the resulting counters in **one Store transaction before returning a public upload node**. It uses the same native prekey codec and account binding as `signal::Repository`, so both must use the same account-specific backend. Private keys remain available until an authenticated incoming Signal handshake consumes them transactionally.

The upload node contains registration ID, key type, public identity, prekey list and signed prekey. Three-byte wire IDs are bounded to `0xffffff`; the exclusive counter sentinel `0x1000000` is supported, but another reservation cannot wrap back to zero. Batches are bounded to 8,192 keys. The defaults preserve `MIN_PREKEY_COUNT=5` and `INITIAL_PREKEY_COUNT=812` from the pinned source.

Existing records are decoded and their private/public correspondence checked before inclusion. A hole, malformed record, ID collision, foreign identity or failed commit prevents publication and rolls back the reservation. Fresh secure-generated public keys are reused directly while building the node, avoiding a read and repeated public-key derivations immediately after writing those same keys. Large existing ranges use the backend's batch-read path.

Counters are persisted under native metadata and become authoritative after initialization. Reopening with stale lower JSON counters does not reuse IDs. A JSON cursor ahead of native metadata fails explicitly and requires reconciliation. `sync_counters` can mirror the authoritative values into matching credentials; credential-file persistence remains a separate host operation. There is no distributed transaction between a legacy JSON credential file and the native store. The metadata means **reserved/attempted**, not remotely acknowledged: the source also advances counters before the upload response.

`get_pre_keys(first, end)` explicitly exports private key pairs with an exclusive upper bound; missing rows remain `None`. Its KeyPair/Bytes diagnostics are redacted. It is intended for authenticated storage integration, not an unauthenticated API or logging endpoint. Missing/deleted private keys are never fabricated as a recovery shortcut.

## Upload lifecycle

`Uploader` accepts a typed `Query` endpoint; `socket::Connection` implements it. New key generation and blocking storage run on a blocking worker, while the socket reader remains independent. Cloned uploaders share one in-flight upload, including when the first waiter is cancelled. As in the original promise cache, overlapping requests with different counts join the first request; the result reports the actual reserved count.

The default policy permits four attempts, with 1/2/4-second backoff and a 30-second whole-operation deadline. Each network retry reserves a **fresh range** while retaining earlier private keys, matching the original retry logic. Generation/storage failures do not send or retry. An unknown network outcome does not roll back or delete keys the server may already have received. Invalid policy values fail before work starts.

The in-flight task has an independently enforced deadline and clears its slot on completion/failure. Cancellation of one caller does not cancel shared work for others. Expiry cancels subsequent async network/backoff work; a blocking key-generation transaction already running can finish afterward, but it cannot start a later network request through the expired operation. This fixes the original Promise.race behavior that could report timeout while its background retry logic continued. There is no claim that an expired network request was not delivered.

The policy gate is per cloned uploader family, not a distributed account/socket lease. Independent managers still reserve disjoint IDs through the backend transaction. A host must coordinate connection ownership. The manager reads the authoritative active signed key inside each reservation transaction; see [durable signed-key history](signed-keys.md). A shared Manager serializes Uploader/Rotator publication; independent managers and manual prepare calls still require host ownership coordination.

## Authenticated success bootstrap

`initialize(success_node)` processes the prekey/active/digest portion of an authenticated server `success` stanza. It queries the server count, checks whether the current local key exists, applies the original upload threshold, sends passive `active`, and checks for the digest child. A missing digest triggers the original five-key upload fallback and remains a reported failure afterward. This checks **digest presence**, not a newly invented cryptographic digest comparison.

Prekey, active and digest outcomes are reported separately. The original continues its open path after these auxiliary failures; the Rust report makes them visible without fabricating success for a failed stage. It does not itself mark an account logged in or a closed transport open. The host must keep draining socket events during initialization, persist its credential updates, handle stream restart/failure and perform the remaining post-login tasks.

## Protocol regressions found during comparison

Complete binary-node comparisons exposed a wrong server destination in earlier pairing/keepalive helpers: the source uses `@s.whatsapp.net`, not the bare domain string `s.whatsapp.net`. Those helpers and the new queries now use `jid::S_WHATSAPP_NET`. Pair-success verification now compares the complete serialized response with the original, after independently verifying the newly randomized device signature.

libsignal-node also omits `preKeyId=0` by checking truthiness before encoding. Rust first honors true absence as an ordinary three-DH handshake. Only if that fresh version-3 handshake fails authentication and local key zero exists does it retry the single legacy-zero interpretation from the untouched state snapshot. The original inner message/MAC remains unchanged; a successful MAC is mandatory. Key zero is consumed with session/identity persistence, and failed authentication or commit returns no plaintext. Genuine no-prekey messages succeed normally without consuming an unrelated zero key. This is a narrowly scoped compatibility adapter, not a signature/MAC bypass or a search over arbitrary private keys.

## Evidence and remaining scope

Fixtures execute the exact original prekey functions, including reused pools and the 24-bit boundary. The active verifier compares six native upload packets/counter results with those functions, supplying native-generated entropy to the source oracle. It also performs six actual Node→Rust prekey handshakes, including zero, maximum wire ID and the 812-key initial batch, and verifies private-key consumption.

Native tests cover rollback at deferred SQLite COMMIT, holes/collisions/corruption, reopening, concurrent reservations, cursor authority, retry limits, single-flight cancellation, deadlines, upload decisions and partial bootstrap failures. A real loopback WebSocket/Noise test observes the complete count→812-key upload→active→digest exchange and verifies that private keys were durably stored before the server receives their public bundle. Legacy-zero tests also cover altered MACs, replay, genuine absence and failed-commit recovery.

The checkpoint full suite passed **143 native tests**. Independent regressions passed 152 pairing comparisons, 92 ordinary pairwise messages and 780 messages after session import because the destination and Signal compatibility fixes cross those paths. Clippy passed with warnings denied.

No live account/server was used. Automatic signed-prekey rotation scheduling/reconciliation, prekey-low notification orchestration, complete multi-file key-store migration, automatic credential/events wiring, own PN/LID migration after login, unified-session telemetry and the full pairing/reconnect/post-login facade remain pending. JavaScript coercions, malformed response acceptance and unrestricted/unbounded counters are not reproduced. This is not full Baileys parity or an operational client.

```sh
npm run fixtures:prekeys -- /tmp/baileys-reference
nice -n 15 env CARGO_BUILD_JOBS=1 cargo test --locked
nice -n 15 npm run verify:prekeys -- /tmp/baileys-reference
```
