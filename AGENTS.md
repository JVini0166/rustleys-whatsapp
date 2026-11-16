# rustleys-whatsapp

Independent public Rust port; never copy production secrets or customer data.

Explicit user override on 16/11/2026: build and test this project locally, without cluster nodes. This overrides the inherited US-only execution policy for this repository only. Use CARGO_BUILD_JOBS=1 and low priority for resource-heavy tasks. Do not run or replace FarenX production services.

Track compatibility honestly: partial modules remain partial until their full API, malformed inputs, wire behavior and relevant upstream tests are covered. Never label a WhatsApp client operational before pairing and protocol interoperability are verified.

Retain MIT attribution for translated upstream code. Pin all upstream reference inputs by commit. Do not use live customer WhatsApp sessions for tests.
