//! Atomic PN to LID migration of native Signal state. No network lookup here.
use crate::{
    jid,
    lid_mapping::{Mapping, decode, write_pairs},
    signal::{Error, Result, Store, Transaction},
};
use std::collections::HashSet;
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationReport {
    pub migrated: u32,
    pub skipped: u32,
    pub total: u32,
}
fn devices(tx: &mut dyn Transaction, user: &str) -> Result<Option<Vec<u32>>> {
    let Some(bytes) = tx.get("device-list", user)? else {
        return Ok(None);
    };
    if bytes.len() > 65536 {
        return Err(Error::TooLarge);
    }
    let values: Vec<String> = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidMapping)?;
    if values.len() > 1024 {
        return Err(Error::TooLarge);
    }
    values
        .into_iter()
        .map(|value| value.parse::<u32>().map_err(|_| Error::InvalidMapping))
        .collect::<Result<_>>()
        .map(Some)
}
impl<S: Store> crate::signal::Repository<S> {
    /// Discovery also receives LID-addressed lists; keep the same user-keyed
    /// persistence category consumed by migration, but validate either identity.
    pub fn set_discovery_device_list(&self, jid: &str, devices: &[u32]) -> Result<()> {
        let d = crate::jid::jid_decode(jid).map_err(|_| Error::InvalidAddress)?;
        if !matches!(d.server, "s.whatsapp.net" | "hosted" | "lid" | "hosted.lid")
            || d.user.is_empty()
        {
            return Err(Error::InvalidAddress);
        }
        if devices.len() > 1024 {
            return Err(Error::TooLarge);
        }
        let mut seen = HashSet::new();
        let values: Vec<_> = devices
            .iter()
            .filter(|id| seen.insert(**id))
            .map(u32::to_string)
            .collect();
        let bytes = serde_json::to_vec(&values).map_err(|_| Error::InvalidMapping)?;
        self.store.transaction(|tx| {
            tx.put(
                if matches!(d.domain_type, 1 | 129) {
                    "device-list-lid"
                } else {
                    "device-list"
                },
                d.user,
                &bytes,
            )
        })
    }
    pub fn set_device_list(&self, pn: &str, devices: &[u32]) -> Result<()> {
        let phone = decode(pn, true).ok_or(Error::InvalidAddress)?;
        if devices.len() > 1024 {
            return Err(Error::TooLarge);
        }
        let mut seen = HashSet::new();
        let values: Vec<_> = devices
            .iter()
            .filter(|id| seen.insert(**id))
            .map(u32::to_string)
            .collect();
        let bytes = serde_json::to_vec(&values).map_err(|_| Error::InvalidMapping)?;
        self.store
            .transaction(|tx| tx.put("device-list", phone.user, &bytes))
    }
    /// Caller must authenticate the asserted PN/LID relationship. Session,
    /// identity and mapping changes commit together. A destination session is
    /// never overwritten; conflicting source data is preserved outside the
    /// active session namespace so removing an alias cannot revive old counters.
    pub fn migrate_session(&self, from: &str, to: &str) -> Result<MigrationReport> {
        self.store
            .transaction(|tx| self.migrate_in_transaction(tx, from, to, true))
    }
    /// Discovery migrates the complete authenticated batch before any alias is
    /// visible. Bare PNs include their persisted list; explicit devices address
    /// just that device, including non-99 hosted devices.
    pub fn migrate_sessions(&self, pairs: &[(String, String)]) -> Result<Vec<MigrationReport>> {
        if pairs.len() > 16384 {
            return Err(Error::TooLarge);
        }
        self.store.transaction(|tx| {
            pairs
                .iter()
                .map(|(from, to)| {
                    let include_stored =
                        crate::jid::jid_decode(from).is_ok_and(|d| d.device.is_none());
                    self.migrate_in_transaction(tx, from, to, include_stored)
                })
                .collect()
        })
    }
    fn migrate_in_transaction(
        &self,
        tx: &mut dyn Transaction,
        from: &str,
        to: &str,
        include_stored: bool,
    ) -> Result<MigrationReport> {
        let Some(target) = decode(to, false) else {
            return Ok(MigrationReport::default());
        };
        let Some(source) = decode(from, true) else {
            return Ok(MigrationReport {
                total: u32::from(!from.is_empty()),
                ..Default::default()
            });
        };
        {
            let mut device_ids = if include_stored {
                devices(tx, source.user)?.unwrap_or_default()
            } else {
                Vec::new()
            };
            let own = source.device.unwrap_or(0);
            if !device_ids.contains(&own) {
                device_ids.push(own);
            }
            let mut unique = HashSet::new();
            let mut report = MigrationReport::default();
            for device in device_ids
                .into_iter()
                .filter(|device| unique.insert(*device))
            {
                let hosted = device == 99 || (source.domain_type == 128 && device == own);
                let from_jid = jid::jid_encode(
                    source.user,
                    if hosted { "hosted" } else { "s.whatsapp.net" },
                    Some(device),
                    None,
                );
                let to_jid = jid::jid_encode(
                    target.user,
                    if hosted { "hosted.lid" } else { "lid" },
                    Some(device),
                    None,
                );
                let from_address = crate::signal::protocol_address(&from_jid)?;
                let to_address = crate::signal::protocol_address(&to_jid)?;
                let Some(bytes) = tx.get("session", &from_address)? else {
                    continue;
                };
                report.total += 1;
                let state = wacore_libsignal::engine::codec::decode_session_record(
                    &wacore_libsignal::engine::RustCrypto,
                    &bytes,
                )?;
                self.check_record(&state)?;
                let Some(current) = state.current.as_ref() else {
                    report.skipped += 1;
                    continue;
                };
                if from_address == to_address {
                    report.skipped += 1;
                    continue;
                }
                let identity = tx.get("identity-key", &from_address)?;
                if identity
                    .as_ref()
                    .is_some_and(|identity| identity.as_slice() != current.remote_identity)
                {
                    return Err(Error::MigrationConflict);
                }
                let target_identity = tx.get("identity-key", &to_address)?;
                if target_identity
                    .as_ref()
                    .is_some_and(|identity| identity.as_slice() != current.remote_identity)
                {
                    return Err(Error::MigrationConflict);
                }
                if let Some(existing) = tx.get("session", &to_address)? {
                    let destination = wacore_libsignal::engine::codec::decode_session_record(
                        &wacore_libsignal::engine::RustCrypto,
                        &existing,
                    )?;
                    self.check_record(&destination)?;
                    if let Some(active) = destination.current.as_ref() {
                        if active.remote_identity != current.remote_identity {
                            return Err(Error::MigrationConflict);
                        }
                        if let Some(quarantined) =
                            tx.get("session-migration-conflict", &from_address)?
                            && quarantined.as_slice() != bytes.as_slice()
                        {
                            return Err(Error::MigrationConflict);
                        }
                        if let Some(quarantined) =
                            tx.get("identity-migration-conflict", &from_address)?
                            && quarantined.as_slice() != current.remote_identity
                        {
                            return Err(Error::MigrationConflict);
                        }
                        tx.put("session-migration-conflict", &from_address, &bytes)?;
                        tx.put(
                            "identity-migration-conflict",
                            &from_address,
                            &current.remote_identity,
                        )?;
                        tx.put("identity-key", &to_address, &active.remote_identity)?;
                        tx.remove("session", &from_address)?;
                        tx.remove("identity-key", &from_address)?;
                        report.skipped += 1;
                        continue;
                    } else if !destination.previous.is_empty() {
                        return Err(Error::MigrationConflict);
                    }
                }
                tx.put("session", &to_address, &bytes)?;
                tx.remove("session", &from_address)?;
                tx.put(
                    "identity-key",
                    &to_address,
                    identity
                        .as_deref()
                        .map_or(current.remote_identity.as_slice(), |value| value.as_slice()),
                )?;
                tx.remove("identity-key", &from_address)?;
                report.migrated += 1;
            }
            write_pairs(
                tx,
                &[Mapping {
                    pn: from.into(),
                    lid: to.into(),
                }],
                false,
            )?;
            Ok(report)
        }
    }
    /// Explicit export of preserved conflicting source state for host-side
    /// reconciliation. This contains private session keys; never log it.
    pub fn migration_conflict_snapshot(&self, pn: &str) -> Result<Option<crate::auth::Bytes>> {
        let address = crate::signal::protocol_address(pn)?;
        self.store.transaction(|tx| {
            Ok(tx
                .get("session-migration-conflict", &address)?
                .map(|bytes| crate::auth::Bytes::new(bytes.to_vec())))
        })
    }
}
