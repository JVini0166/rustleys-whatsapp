# Registration payloads and authenticated pairing — 2026-11-16

Baseline: Baileys `bb0a87e0326ca8f882fe716c7ee42da362f73fc0`. The new `pairing` module ports the exercised parts of `Utils/validate-connection.ts` and `Utils/companion-reg-client-utils.ts`. These files remain partial in the inventory. This independent library is not connected to FarenX production.

## Payloads and QR data

`ClientConfig` carries the version, browser tuple, country, full-history flag and optional push name used by the original helpers. Its default version is the pinned source's version, not a claim about the latest live service. `registration_payload` constructs the build MD5, four-byte registration ID, three-byte signed-prekey ID, identity bundle, DeviceProps and history flags. `login_payload` constructs passive/pull state and numeric user/device fields. `client_payload` selects by `creds.me`, as the original does. `Connection::connect_account` builds that payload and forwards the persisted routing data to the existing TLS/Noise transport.

DeviceProps platform selection and the companion web-client ID are separate mappings in the original. Both are preserved: for example, Firefox has different numeric values in those two contexts. Android detection, desktop full-history web subplatforms and optional push-name behavior are covered by original-generated vectors.

`pairing_qr_data` emits the pinned source's full `https://wa.me/settings/linked_devices#` URL, containing the reference, public Noise/identity keys, ADV secret and companion type. Its value has redacted Debug, explicit `expose()` access and a zeroizing buffer. A QR value contains an authentication secret and should be passed to a renderer rather than logged.

`QrRotation::from_stanza` parses a `pair-device` challenge and returns the required IQ acknowledgement plus a clock-driven rotation. The host sends that acknowledgement before displaying a QR. `poll(now)` yields the first reference for 60 seconds, subsequent references for 20 seconds, a waiting deadline or exhaustion. A custom nonzero duration overrides both periods. Cancel clears retained references and the ADV-bearing suffix. There are no detached timers or retained private identity/noise keys. Initial credentials must be durably saved before connecting/displaying any QR, and the host must cancel rotation after pairing or disconnect.

## Pair-success authentication and durability

`configure_successful_pairing` expects a stanza from an already authenticated Noise connection. The ADV signatures do not independently authenticate arbitrary outer JID/platform/business attributes, so this helper must not be exposed as an unauthenticated HTTP/JSON endpoint.

The implementation verifies the ADV HMAC in constant time, handles the hosted HMAC/account-signature prefixes, verifies the account signature against the local identity, creates the device signature and constructs `pair-device-sign`. The account signature key is omitted from the response identity, as in the original. Stored account byte fields use protobuf.js's base64-string JSON representation; SignalIdentity bytes keep BufferJSON. Existing opaque credential extensions are retained.

The returned `PairingUpdate` holds the new credentials privately and does not expose the acknowledgement until persistence succeeds. `persist_and_reply` checks the original in-memory snapshot and uses `MultiFileStore::compare_and_save_credentials` to compare/replace the original persisted credentials while holding the directory lock. Only after durable replacement does it update the in-memory credentials and return the reply. A competing update, absent original credential file, failed write or stale snapshot returns an error without releasing an acknowledgement or changing the caller's memory.

`commit_and_reply` supports other backends, whose callback must compare the expected state and durably commit the update before returning success. The filesystem lock coordinates cooperating Rust stores; it cannot make legacy Node writers or unrelated unconditional file writes transactional. `save_credentials` remains an unconditional initialization/legacy helper. A filesystem error after rename can leave a visible update even though durability was not established; callers must reload/reconcile instead of assuming that failure means nothing was written. No acknowledgement is released in that case.

Repeated identical SignalIdentity entries are deduplicated, including legacy Buffer arrays versus modern BufferJSON. A different key for the same LID/device is rejected. This deliberately avoids the original's repeated append behavior and requires explicit reconciliation for a real identity replacement.

## Confirmed original signature bug

The fixture generator executes the pinned original `configureSuccessfulPairing` and its actual crypto helper. An altered account signature, wrapped in a correctly computed ADV HMAC, is accepted by the original in all four exercised normal/hosted combinations. Its `Curve.verify` wrapper ignores the raw verifier's false return value. Rust checks the verification result and rejects those stanzas before any credential update.

The independent Node verifier checks Rust's generated device signatures with the raw libsignal-node boolean result, and also confirms that a mutated device signature returns false. It does not use the defective wrapper as a success oracle.

## Validation and limits

Original-generated fixtures cover 20 registration/QR configurations, 100 login payloads, four signed pair-success combinations and eight rejection cases. Independent runtime checks perform 152 comparisons, including Node validation of Rust-generated device signatures. Native tests cover exact payload bytes, QR timing/cancellation, serialization, malformed input, signature/HMAC failure, persistence failure, stale memory/disk snapshots, repeated pairing and a concurrent compare-and-save race with exactly one durable winner. The full local suite has 126 passing tests.

Input bounds include three-byte signed-prekey IDs, bounded config strings, a 1 MiB device-identity message, up to 4,096 stored signal identities and up to 256 QR references/1 MiB of reference text. Malformed UTF-8/reference separators, duplicate required stanza children/attributes and unknown encryption enum values fail explicitly. Numeric login values above JavaScript's safe integer range, arbitrary JS coercions and unsupported user-JID domains are rejected rather than silently rounded. These stricter behaviors are documented differences, not complete malformed-input compatibility.

No live account or WhatsApp server was used. Automatic connection-update/credential event orchestration, QR rendering, phone-number/link-code pairing, stream success/restart/failure handling, prekey upload and post-login initialization remain pending. These primitives and the transport do not yet constitute an operational WhatsApp client or full Baileys parity.

```sh
npm run fixtures:pairing -- /tmp/baileys-reference
nice -n 15 env CARGO_BUILD_JOBS=1 cargo test --locked --test pairing_compatibility
nice -n 15 npm run verify:pairing -- /tmp/baileys-reference
```
