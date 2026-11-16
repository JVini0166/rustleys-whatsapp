# PN/LID mappings and session migration — 2026-11-16

Pinned Baileys baseline: `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`. This is an independent Rust implementation and offline comparison; no FarenX service or customer session is involved.

## Lookup and cache

`LidMappingStore` stores normalized PN/LID user pairs and projects device-specific JIDs for forward/reverse and batch lookups. Device zero keeps the original forward format without `:0`; reverse output includes `:0`, as in the original helper. PN and hosted-PN inputs project to LID and hosted-LID respectively. Valid swapped field roles are normalized. Invalid pairs are ignored and malformed/inconsistent persisted rows fail explicitly.

Forward and reverse entries form a bijection. Reassignment removes obsolete counterparts in the same transaction and increments an eight-byte revision under `meta/lid-mapping-revision`. Every lookup checks that revision before using cached values, so separately opened native instances observe committed changes. Custom backends/importers must preserve this revision contract and use the mapping writer rather than writing those rows directly. The cryptographic repository resolves aliases from persisted data inside each operation's transaction, rather than relying on an independently stale contact cache.

The cache is bounded (default 10,000 directional entries), uses a sliding three-day TTL and never caches missing results. The upstream comment says seven days, but its expression is three days; Rust uses the expression. There is no background purge thread: expiry is enforced on access, capacity eviction, explicit cache inspection or close. Closing clears the cache; it does not permanently disable the object or cancel a running resolver, matching the original lifecycle intent.

SQLite batch reads use parameterized IN queries in chunks of 400, including reciprocal checks. Cache locks are released before backend I/O. A 1,000-contact test verifies batched trait calls and bounded cache size. Other backends can override Transaction.get_many; its default loops over get for compatibility. Each lookup rechecks a revision, so a cache hit is not advertised as zero database I/O.

An optional synchronous Resolver receives deduplicated normalized PN JIDs. Identical outstanding user sets share one resolver call, even when callers request different devices or order. Each caller then projects its own request order/devices from a fresh revision-consistent snapshot. Resolver results outside the requested phone set are ignored. Missing-only merges prevent a delayed network response from replacing a newer explicit mapping. Errors/panics release the in-flight entry; no failed lookup becomes a permanent negative cache entry.

Resolver calls are blocking and must run off a future async network executor, with deadlines supplied by the host. They must return authenticated USync data and must not recursively resolve the same batch. Reverse lookups use cached/batched database data, with no network provider. The full asynchronous socket/USync facade and original async storage integration remain pending.

## Atomic session migration

`Repository::migrate_session` authenticates no network assertion itself: the host must verify that the PN/LID relationship is legitimate. It moves native pairwise session state and identity records for the known device list and input device, and writes the mapping in one transaction. Subsequent PN and LID crypto operations use the same canonical state. Hosted device 99 keeps the hosted PN/LID namespaces; normal sibling devices remain separate. Missing device lists fall back to the input device, and device IDs are deduplicated. Lists are bounded to 1,024 entries/64 KiB.

An active destination is never overwritten by an older PN snapshot. If its remote identity agrees, it remains authoritative and the source is preserved under session-migration-conflict, outside the active session namespace. This prevents later alias changes from reviving the stale sending counter. The explicit migration_conflict_snapshot export returns redacted/zeroizing bytes for host reconciliation; it contains private keys and must never be logged. A different pre-existing quarantine is not overwritten.

Conflicting identities, corrupt snapshots and archived destination histories requiring a merge return an error and roll back the whole migration. An empty destination can be replaced. Closed source sessions are counted as skipped. Archive merging and conflict reconciliation remain pending; do not treat this as complete legacy session migration coverage.

Native records validate their local identity and registration against the repository credentials, including archived states. A row accidentally copied from another local account fails before encryption, validation or migration. Session validation reports missing versus non-open state; storage/corruption errors propagate rather than being reported as an ordinary missing session. Session deletion also resolves committed aliases inside its transaction.

## Reproduced upstream differences

The fixture generator executes the original LIDMappingStore and makeLibSignalRepository, not a handwritten JavaScript imitation. It characterizes five regressions at the pinned source:

- Reassigning a PN leaves the old reverse mapping behind, including after cache clear.
- Swapped mapping roles pass validation but are stored backwards and fail normal forward lookup.
- Hosted-LID reverse lookup is skipped even when the corresponding user mapping exists.
- Coalesced requests with opposite order receive the first caller's order.
- Migrating a stale PN record over an already advanced LID record restores an already-used sending counter. The generator demonstrates counter zero before and after the overwrite.

Rust does not reproduce those regressions. These are intentional behavior differences, not evidence of byte-for-byte equivalence for every invalid/edge case. Lookup results preserve the caller's requested PN strings/order; the original USync path can canonicalize those differently from its cache path. Native migration also supports missing device-list fallback, correct hosted addressing, identity transfer and atomic mapping registration that the legacy migration does not perform the same way. There is no migrated-device TTL cache that could suppress a newly recreated source session.

## Evidence and limits

Checkpoint validation: all 83 native tests passed, with no Clippy warnings. Independent checks passed 10 mapping comparisons/regressions, 92 bidirectional pairwise messages (including PN→LID migration), and 40 group messages as a regression check. All ran locally with one Cargo build job at low priority.

Original forward/reverse vectors cover device projection, explicit device zero, deduplication, missing values and cold/warm cache paths. Independent JS/native checks compare normal outputs and separately assert selected corrected regressions. Native tests cover sliding expiry using an injected clock, bounded eviction, 1,000-item batches, concurrency/coalescing, per-caller ordering, callbacks returning unrelated rows, delayed updates, provider failure/panic and deferred SQLite COMMIT failure.

Session tests cover multiple devices, hosted namespaces, interruption/rollback, preserving a newer destination counter, repeated migration, missing device lists, empty and archived destinations, malformed rows and cross-account state rejection. The active Node/Rust peer test now moves the session PN→LID mid-conversation, continues both directions, then restarts the Rust process and continues from persisted aliases and ratchets.

No live WhatsApp number or server was used. Resolver authentication and network USync remain host responsibilities until the socket layer is implemented. Legacy libsignal-node JSON import/export, archived-history merging, async callback/storage APIs, all original coercions/cache timing edge cases and membership/group-key migration remain incomplete. Mapping files stay partial in the inventory. This does not establish full Baileys parity or an operational client.

```sh
npm run fixtures:lid -- /tmp/baileys-reference
CARGO_BUILD_JOBS=1 cargo test --locked --test lid_compatibility --test session_migration
npm run verify:lid -- /tmp/baileys-reference
npm run verify:signal -- /tmp/baileys-reference
```
