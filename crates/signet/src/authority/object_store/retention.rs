//! Pure retention planning only. No delete method exists on the normal writer.
//! Caller supplies a verified committed catalog, not arbitrary bucket listing results.
use std::collections::BTreeSet;
#[derive(Debug, Clone)]
pub struct Version {
    pub hash: String,
    /// Storage write time for display/age only; never used as authority ordering.
    pub written_at: i64,
}
/// Both conditions are mandatory: older than cutoff AND at least minimum_newer
/// strictly newer committed versions. Preserve active, pinned and all versions
/// referenced by unresolved operations/recovery chains. Do not infer policy defaults.
/// A privileged cleanup job must re-read current pins/head and fence writers before
/// deletion; this plan alone is not authorization for deletion.
pub fn eligible<'a>(
    committed: &'a [Version],
    cutoff: i64,
    minimum_newer: usize,
    active: &str,
    pinned_or_referenced: &BTreeSet<String>,
) -> Vec<&'a str> {
    committed
        .iter()
        .filter(|v| {
            v.written_at < cutoff
                && v.hash != active
                && !pinned_or_referenced.contains(&v.hash)
                && committed
                    .iter()
                    .filter(|n| n.written_at > v.written_at)
                    .map(|n| &n.hash)
                    .collect::<BTreeSet<_>>()
                    .len()
                    >= minimum_newer
        })
        .map(|v| v.hash.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
