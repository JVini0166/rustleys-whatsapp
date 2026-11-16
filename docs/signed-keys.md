# Signed-prekey rotation and history (partial client API)

Reference: Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`,
`src/Socket/socket.ts:rotateSignedPreKey`, `src/Utils/signal.ts:xmppSignedPreKey`.
Native records use the pinned MIT/BSD wacore engine codec; signatures are verified
against the local identity and the tagged public key. The adapter also validates
private/public correspondence, record IDs and the 24-bit upload range.

`Authority::prepare_rotation` reserves the next monotonic ID and commits its
private key, signature and expected previous active ID in one transaction before
returning the exact rotate IQ. `confirm` activates it only after the host has
received the corresponding server IQ result; storage failure rolls back
activation. Repeated confirmation of the currently active candidate is
idempotent. Competing acknowledgements use compare-and-swap: one active branch
wins; a stale acknowledgement cannot replace a newer active key.

All previous and uncertain keys remain readable by ID, including after a process
restart. A new incoming Signal handshake loads its indicated signed-key record;
an established handshake continues without requiring the original signed key
(for imported legacy sessions). Missing/corrupt keys fail within the transaction,
before exposing plaintext or committing any session/one-time-key change.

The prekey upload Manager reads the authoritative active key when reserving a
batch, rather than retaining the constructor's signed-key snapshot. Opening
Repository/Manager/Authority with stale JSON can add historical keys but never
reactivates a retired one. A supplied key ID cannot be rebound to different key
material. Explicit `sync_credentials` exports the active record for the host's
normal credential compare-and-save mechanism; SQLite and JSON are not a
single distributed transaction. External legacy rotations are not automatically
activated merely by opening a newer JSON snapshot: adopt them through an explicit
host migration, keeping one authoritative writer.

## Intentional differences and remaining integration

The upstream code emits the new credential only after query success and does not
retain old signed keys. Its comment mentions digest fallback, but the actual
pinned function has no catch/fallback. Native storage deliberately retains old
and unconfirmed private keys. After a failed/unknown attempt, the next reservation
uses a fresh ID rather than replacing a possibly accepted key at the same ID.
IDs never wrap; exhaustion is an explicit error. No automatic pruning is done.

`Rotator` supplies an asynchronous facade over the durable authority and the
same Query contract used by `socket::Connection`. Share its `Arc<Manager>` with
`Uploader`: their publication lock serializes normal uploads with signed-key
rotation, and uploads read the active key after acquiring that lock. Blocking
reservation/activation runs on `spawn_blocking`. A spawned bounded task owns the
operation after caller cancellation; the lock is not dropped merely because the
caller stops waiting. The host supplies a deadline (source query default: 60s),
bounded here to 1ns..5min and including lock wait. Query/storage errors and panics
are typed; no automatic rotation network retry or invented digest fallback runs.

The host still must keep one account/transport owner, project/persist credentials,
and coordinate any manual use of the synchronous Authority/Manager prepare APIs.
Independent Manager instances do not share an async lock; their database
transactions prevent ID reuse and stale activation but are not a distributed
publication lease. A timeout does not prove that a started socket write was not
delivered. A blocking commit already started can finish after the deadline;
reload authoritative state before host recovery decisions. All candidate keys
remain available regardless. Automatic scheduling, server-side reconciliation,
owner replacement, pruning and end-to-end live account rotation remain pending.
The native engine timestamp field preserves its numeric value; an absent optional
`timestampS` and an explicit zero both export as absent. Exact optional timestamp
presence round-tripping remains pending. This is not a claim of a complete
WhatsApp client.

## Offline validation

`cargo test --locked --test signed_keys` covers fresh handshakes with retired,
active and unconfirmed keys after reopening SQLite, stale JSON, active-key upload
selection, ID collisions, foreign credentials, corrupted record signatures and
private keys, exhaustion, reservation/activation rollback and competing ACKs. Async tests cover cancelled
waiters, serialization with uploads, deadline release, preserved uncertain
candidates, non-reused IDs and server errors without implicit retries.

`node scripts/verify-signed-keys-cross-runtime.cjs /path/to/pinned/Baileys`
executes the exact original rotation closure extracted from the pinned TypeScript
AST, compares encoded IQ bytes and acknowledgement/update behavior, checks the
raw Node signature verifier's actual boolean, and uses real local libsignal-node
peers to encrypt fresh handshakes for native decryption with each history class
after restarting the Rust process. Test credentials are synthetic and no server
or customer account is contacted.

Validated checkpoint: 152 native tests, all-target Clippy with warnings denied,
2 original rotation IQ/ack comparisons and 3 fresh Node→Rust history handshakes.
Regression peers also passed 92 active-session messages, 780 messages after legacy
session import, and the existing prekey upload wire/handshake oracle. All local.
