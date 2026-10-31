//! Passphrase key derivation (Argon2id).
//!
//! The passphrase is the login to the tool (`DESIGN.md` 4), so this is the only barrier
//! between a stolen laptop and the vault. Parameters are stored *alongside* each sealed
//! key rather than hardcoded, so they can be raised over time without invalidating
//! existing data.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// Length of a derived symmetric key.
pub const KEY_LEN: usize = 32;

/// Length of a KDF salt.
pub const SALT_LEN: usize = 16;

/// A derived 32-byte key, zeroed on drop.
///
/// Not `Clone`: every copy is another chance to leave key material in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; KEY_LEN]);

impl DerivedKey {
    /// Borrows the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material, not even truncated.
        f.write_str("DerivedKey(<redacted>)")
    }
}

/// Argon2id cost parameters, persisted next to whatever they protect.
///
/// Stored rather than assumed so that raising the cost later does not strand keys sealed
/// under the old parameters: each sealed blob remembers how it was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// 256 MiB, 3 passes, 4 lanes - the values recorded in `DESIGN.md` 4.
    ///
    /// Chosen to be painful to brute-force while staying tolerable on the oldest machine
    /// that must unlock a vault. Interactive cost is roughly a second; adjust only with
    /// measurements from real hardware, not by intuition.
    fn default() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Weakest permitted `memory_kib`: 19 MiB, the OWASP minimum for Argon2id.
pub const MIN_MEMORY_KIB: u32 = 19_456;

/// Largest permitted `memory_kib`: 2 GiB.
///
/// The ceiling is a denial-of-service bound, not a tuning suggestion. `KdfParams` are
/// read from shared storage, and `argon2` itself accepts `m_cost` up to `u32::MAX` -
/// a stored identity edited to demand a ~4 TiB allocation would kill every client that
/// tried to unlock it, permanently. The AAD binding (see [`crate::identity`]) cannot
/// prevent that, because the allocation happens *before* the AAD is checked.
pub const MAX_MEMORY_KIB: u32 = 2_097_152;

/// Weakest permitted pass count, per the OWASP minimum of `t = 2` at 19 MiB.
pub const MIN_ITERATIONS: u32 = 2;

/// Largest permitted pass count. With [`MAX_MEMORY_KIB`] this bounds a hostile
/// parameter set to expensive-but-survivable, instead of unbounded.
pub const MAX_ITERATIONS: u32 = 16;

/// Largest permitted parallelism. More lanes than any real machine benefits from.
pub const MAX_PARALLELISM: u32 = 16;

impl KdfParams {
    /// The weakest parameters [`KdfParams::validate`] accepts.
    ///
    /// This is the OWASP Argon2id minimum (19 MiB, 2 passes, 1 lane) - a real, if
    /// bottom-of-the-range, work factor. It exists as a named constructor because tests
    /// need the cheapest *legitimate* parameters, and the previous answer to that need -
    /// a `pub` `insecure_for_tests()` at 8 KiB / 1 pass - was both callable from
    /// production code and below any defensible floor. There are deliberately no
    /// parameters weaker than this anywhere in the API.
    #[must_use]
    pub const fn floor() -> Self {
        Self {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    /// Checks the parameters against the policy window.
    ///
    /// Called by [`derive`], so *every* derivation is bounded - parameters read from a
    /// stored identity included. The window defends in both directions:
    ///
    /// - **Ceiling:** a hostile store cannot demand an allocation that kills the client
    ///   on every unlock (the `argon2` crate itself accepts up to `u32::MAX` KiB).
    /// - **Floor:** a re-sealed identity cannot be silently downgraded to parameters
    ///   that make the passphrase trivially brute-forceable. The KDF is the only
    ///   barrier between a stolen laptop and the vault; a floor is part of the design,
    ///   not an implementation detail.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if any parameter falls outside the window.
    pub fn validate(self) -> Result<()> {
        if self.memory_kib < MIN_MEMORY_KIB || self.memory_kib > MAX_MEMORY_KIB {
            return Err(Error::Malformed("argon2 memory cost outside policy window"));
        }
        if self.iterations < MIN_ITERATIONS || self.iterations > MAX_ITERATIONS {
            return Err(Error::Malformed("argon2 iteration count outside policy window"));
        }
        if self.parallelism < 1 || self.parallelism > MAX_PARALLELISM {
            return Err(Error::Malformed("argon2 parallelism outside policy window"));
        }
        Ok(())
    }

    fn to_argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| Error::Malformed("argon2 parameters out of range"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Derives a symmetric key from a passphrase and salt.
///
/// The salt must be unique per sealed object; see [`crate::identity`] for how it is
/// generated and stored.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the parameters fall outside the policy window
/// ([`KdfParams::validate`]) or Argon2's own accepted range.
pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<DerivedKey> {
    // Validated here, at the single choke point, rather than at call sites: parameters
    // arrive from shared storage, and a caller that forgot the check would hand an
    // attacker either a memory-exhaustion crash or a silent cost downgrade.
    params.validate()?;
    let argon2 = params.to_argon2()?;
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|_| Error::Malformed("argon2 derivation failed"))?;
    Ok(DerivedKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

    #[test]
    fn derivation_is_deterministic() {
        let p = KdfParams::floor();
        let a = derive("correct horse", &SALT, p).unwrap();
        let b = derive("correct horse", &SALT, p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_passphrase_gives_different_key() {
        let p = KdfParams::floor();
        let a = derive("correct horse", &SALT, p).unwrap();
        let b = derive("correct horsf", &SALT, p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let p = KdfParams::floor();
        let a = derive("correct horse", &[1u8; SALT_LEN], p).unwrap();
        let b = derive("correct horse", &[2u8; SALT_LEN], p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn params_change_the_key() {
        // Guards the stored-parameters design: if params did not affect output, raising
        // cost later would silently produce the same key and the upgrade would be a lie.
        let a = derive("pw", &SALT, KdfParams::floor()).unwrap();
        let b = derive(
            "pw",
            &SALT,
            KdfParams {
                iterations: 3,
                ..KdfParams::floor()
            },
        )
        .unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn hostile_memory_cost_cannot_reach_allocation() {
        // REVIEW-EXTERNAL.md finding 6, ceiling half. A stored identity edited to demand
        // memory_kib = 4_000_000_000 (~4 TiB) previously reached argon2 unchecked and
        // died allocating - one file write, permanent lockout for every client. The
        // window must refuse before any work happens.
        let p = KdfParams {
            memory_kib: 4_000_000_000,
            iterations: 3,
            parallelism: 4,
        };
        assert!(matches!(derive("pw", &SALT, p), Err(Error::Malformed(_))));
    }

    #[test]
    fn downgraded_params_are_refused_not_silently_accepted() {
        // Finding 6, floor half. Re-sealing an identity at 8 KiB / 1 pass previously
        // unlocked without complaint, silently reducing the stolen-laptop defence to
        // nothing. Below-floor parameters must fail loudly.
        let p = KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        assert!(matches!(derive("pw", &SALT, p), Err(Error::Malformed(_))));
    }

    #[test]
    fn validation_window_edges() {
        assert!(KdfParams::floor().validate().is_ok());
        assert!(KdfParams::default().validate().is_ok());
        assert!(KdfParams { memory_kib: MIN_MEMORY_KIB - 1, ..KdfParams::floor() }
            .validate()
            .is_err());
        assert!(KdfParams { memory_kib: MAX_MEMORY_KIB + 1, ..KdfParams::floor() }
            .validate()
            .is_err());
        assert!(KdfParams { iterations: MIN_ITERATIONS - 1, ..KdfParams::floor() }
            .validate()
            .is_err());
        assert!(KdfParams { iterations: MAX_ITERATIONS + 1, ..KdfParams::floor() }
            .validate()
            .is_err());
        assert!(KdfParams { parallelism: 0, ..KdfParams::floor() }.validate().is_err());
        assert!(KdfParams { parallelism: MAX_PARALLELISM + 1, ..KdfParams::floor() }
            .validate()
            .is_err());
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let k = derive("pw", &SALT, KdfParams::floor()).unwrap();
        let rendered = format!("{k:?}");
        assert!(!rendered.contains(&hex::encode(k.as_bytes())));
        assert!(rendered.contains("redacted"));
    }
}
