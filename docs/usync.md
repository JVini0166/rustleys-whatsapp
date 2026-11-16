# USync queries and protocol parsers — 2026-11-16

Reference: Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`,
`src/WAUSync/**`, `src/Types/USync.ts` and the nested socket methods
`executeUSyncQuery`, `onWhatsApp`, `pnFromLIDUSync`.

## Native API

`usync::User` preserves ID, LID, phone, username, username key, type and persona ID,
with consuming `with_*` builders. `Query` preserves the original interactive/query
defaults, caller context/mode, user order, protocol order and duplicate protocols.
It accepts extensible `Protocol: Send + Sync` implementations, with these seven
builtins:

| Builtin | Request and response behavior |
|---|---|
| Contact | Phone wins over username/PIN/LID, then type, then empty contact. Response type `in` means true. |
| Devices | Version 2 request; device ID/key index/hosted flag, signed key-index bytes and timestamps. |
| Status | Status text, UTF-8 byte decoding, empty/401 distinction and timestamp. |
| DisappearingMode | Duration and timestamp. |
| Lid | Optional per-user LID element; response `val`. |
| Username | String response only; a Buffer response is null/omitted as in the pinned parser. |
| Bot | Versioned profile request, persona selection, fields, default marker, commands and prompts. See nesting limitation below. |

`Query::build(sid)` creates the original ordered IQ to `@s.whatsapp.net` with
query/list children, context/mode/SID/last/index attributes. A truthy phone omits
the user's JID attribute. Empty protocols fail before sending; empty user lists
are allowed by this low-level API, matching the original socket method.

`Query::parse` returns None for absent/non-result stanzas. It preserves user order,
nonempty IDs, last registered parser for duplicate protocol names, last non-null
result for duplicate response fields, omission of unknown/null results and final
ID precedence over a custom `id` protocol. `sideList` stays empty: the pinned
source does not implement side-list parsing either. It does not invent backoff or
refresh support for ignored USync result metadata.

`Client<Q>` uses the same async Query endpoint contract as `socket::Connection`.
It generates unique opaque SIDs from a random prefix and a checked atomic counter
shared by clones; its 60-second deadline bounds the endpoint wait. Its SID format
is intentionally native, rather than the original socket's message-tag format.
`execute`, `on_whatsapp` and `pn_from_lid` expose the corresponding source flows.
The latter keeps the source's confusing name: it accepts phone-number JIDs and
returns PN→LID mappings. Both helpers skip `@lid` inputs and return early for an
empty effective list; the contact helper preserves source phone normalization
and filters only positive contact results. Lookup results are returned to the
host, without silently updating the native identity/session database. Persist
validated mappings through `LidMappingStore` as a separate blocking operation.

## Representation, bounds and explicit differences

Protocol payloads are ordered `serde_json::Value` objects, not JavaScript runtime
objects. Date-valued `setAt` fields use Unix milliseconds (`Date.getTime()`);
invalid/out-of-range dates become null. Nonfinite numeric protocol values
(NaN/Infinity) normalize to null, as in the original result's JSON serialization.
Valid numeric coercion uses IEEE-754; long binary/octal/hexadecimal integers are
rounded once with guard/sticky bits, avoiding accumulated floating-point errors.
Byte arrays in results remain arrays. The native Node type does not distinguish
JavaScript Buffer and Uint8Array runtime classes; decoded wire bytes follow Buffer
UTF-8 behavior. Arbitrary JS null/undefined/object coercions, Date objects, custom
non-JSON parser values and every malformed content union are not claimed as
API-equivalent.

Only explicitly registered protocol names can invoke a parser. The original's
plain object lookup accidentally executes inherited `toString`/`constructor` and
throws for an unregistered `__proto__`; committed oracle evidence records these
three cases. Native lookup ignores them unless registered. Protocol errors carry
only a bounded numeric code, not arbitrary remote error text.

Default limits: 8,192 users, 32 protocols, 65,535 nodes, 65,535 attributes, 16 MiB of
node content/attributes and depth 128. Request fragments are charged before
retention, preventing repeated protocols from multiplying a large payload before
aggregate rejection. Oversized source strings fail before cloning; responses are
bounded iteratively before parsing. Builtin direct parser calls use the same
safe default node bounds, while Query limits can impose smaller bounds. Custom
protocol implementation code itself is trusted host code, not a resource sandbox.
The native library does not reproduce unrestricted upstream allocation.

The pinned bot parser looks for `bot/profile` inside its input. Direct parsing of
a user node with that structure works, but aggregate USync parsing hands it a
child already tagged `bot`; ordinary non-nested responses then throw upstream.
Rust reports `InvalidBotProfile` for the same missing nesting instead of panicking.
Nested bot fixtures match original output. A repaired bot schema cannot be called
upstream-equivalent without an explicit compatibility decision and real protocol
evidence.

## Evidence and remaining work

The fixture generator compiles exact classes and nested socket methods extracted
from the pinned source. Native tests exercise 11 successful exact wire builders
(plus empty-protocol rejection), 111 original protocol cases and five aggregate
results. Independent Node→Rust comparisons add 160 deterministic large-radix
numeric cases, for 271 parser comparisons, and 21 asynchronous socket/helper flows.
The three inherited-property safety differences are checked against both original
and native behavior. Native tests also cover custom parsers, duplicate resolution,
limits, early helper returns, normalization, transport errors, shared-client SID
uniqueness and early request-budget rejection.

```sh
nice -n 15 node scripts/generate-usync-fixtures.cjs /path/to/pinned/Baileys
nice -n 15 env CARGO_BUILD_JOBS=1 cargo test --locked --test usync
nice -n 15 node scripts/verify-usync-cross-runtime.cjs /path/to/pinned/Baileys
nice -n 15 env CARGO_BUILD_JOBS=1 cargo clippy --locked --all-targets -- -D warnings
```

Everything here is offline and synthetic; no customer account or live WhatsApp
server was used. All related inventory entries remain partial. Automatic device
lookup/cache wiring, asynchronous LID resolver/session migration coordination,
full socket lifecycle, outbound message orchestration and real-server schema
validation remain pending. This checkpoint does not make an operational client.

Validated repository checkpoint: 162 native tests passed; all-target Clippy passed
with warnings denied. All builds and comparisons ran locally with one Cargo job
and low priority, following the explicit project-specific user override.
