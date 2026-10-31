//! Trust-on-first-use record of RDP server public-key fingerprints - the SSH `known_hosts`
//! idea for RDP. Plaintext JSON in the app data dir: fingerprints are public, and this is a
//! per-machine trust decision, not shared or secret data.

use std::collections::HashMap;
use std::path::Path;

fn load(path: &Path) -> HashMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(path: &Path, map: &HashMap<String, String>) {
    if let Ok(bytes) = serde_json::to_vec_pretty(map) {
        let _ = std::fs::write(path, bytes);
    }
}

/// The pinned fingerprint for a host, if one was recorded.
pub fn get(path: &Path, host: &str) -> Option<String> {
    load(path).get(host).cloned()
}

/// Pins a host's fingerprint (first use, or after an explicit reset).
pub fn set(path: &Path, host: &str, fingerprint: &str) {
    let mut map = load(path);
    map.insert(host.to_owned(), fingerprint.to_owned());
    save(path, &map);
}

/// Drops a host's pin, so the next connect trusts on first use again.
pub fn forget(path: &Path, host: &str) {
    let mut map = load(path);
    if map.remove(host).is_some() {
        save(path, &map);
    }
}
