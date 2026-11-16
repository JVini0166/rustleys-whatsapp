# rustleys-whatsapp

Independent Rust port of [WhiskeySockets/Baileys](https://github.com/WhiskeySockets/Baileys).

## Objective

Port all Baileys functionality to Rust with protocol/API compatibility tracked against a pinned upstream commit, differential tests and measured performance. Preserve the upstream MIT attribution.

**Status: initial development. This repository does not connect to WhatsApp yet. No functional parity or production readiness is claimed.**

Protocol utilities implemented so far: JID helpers and a binary-node encoder/decoder with generated token dictionaries. See [compatibility progress](docs/compatibility.md) for tested behavior and pending differences.

The initial inventory is in `docs/upstream-inventory.json`. Every file starts as `not_ported`; completing a module requires behavioral tests, including error cases and interoperability where applicable. Export extraction is an initial source inventory, not a complete public API specification (re-exports and dynamically returned socket methods require separate analysis).

## Implementation sequence

1. Pin upstream and map public exports, socket methods, types, events and tests.
2. JIDs, binary nodes/tokens/codec and protobuf schema.
3. Cryptographic primitives, Noise, Signal sessions, keys and auth storage.
4. WebSocket lifecycle, pairing/QR, reconnect, receipts and acknowledgements.
5. Send/receive messages, media streaming, retries, history and app-state sync.
6. Groups, communities, newsletters, privacy, business, presence and remaining exported functionality.
7. Differential tests, authorized live interoperability tests, resource/load benchmarks and documentation.

Production FarenX services are outside this repository and are not modified by this project. Never copy production credentials, messages, customer data or session keys into this public repository.

## Build policy

Explicit user decision on 2026-11-16: builds, tests and benchmarks for this project run locally, without cluster nodes. This is a project-specific override of the FarenX infrastructure policy. Use `CARGO_BUILD_JOBS=1 cargo test` to limit build parallelism. No CI workflow is enabled yet.

The crate is initially non-publishable. Rust source setup alone is not evidence of a working WhatsApp client.

## License

MIT. See LICENSE and NOTICE for upstream attribution. Not affiliated with WhatsApp/Meta.
