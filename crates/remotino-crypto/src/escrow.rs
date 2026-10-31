//! Escrow: recovering data when a passphrase is lost (`DESIGN.md` 9.4a).
//!
//! # The property that makes growth cheap
//!
//! Content keys are wrapped to the escrow **public** key, which never changes. Only the
//! protection of the escrow **private** key is re-sharded when the admin set changes. So
//! moving from one admin to a 2-of-3 quorum re-wraps *no content keys* - it re-splits one
//! private key. Preserve this property; losing it turns every admin change into a repo
//! migration.
//!
//! # The configuration is a signed object, and the types enforce it
//!
//! Every user can write to the shared store, so a bare configuration file is
//! attacker-writable. An unauthenticated config would let any enrolled user swap in
//! their own "escrow" public key and have every honest client thereafter wrap folder
//! keys to *them* - defeating "permission is key possession" without touching a single
//! primitive. Flipping the scope's `personal_vaults` bit would do the same to every
//! user's private vault (REVIEW-EXTERNAL.md criticals 1 and 2).
//!
//! So the stored form is [`SignedEscrowConfig`]: the config plus an admin signature
//! over a domain-separated canonical encoding. Deserialisation gives you only that
//! signed-but-unverified form, whose escrow key is unreachable. Wrapping and recovery
//! live exclusively on [`VerifiedEscrowConfig`], which can only be obtained by passing
//! signature verification against an admin key the caller already trusts. The
//! type system, not caller discipline, is what keeps an unverified config away from a
//! wrap call.
//!
//! Where the trusted admin key comes from is the caller's problem *by design*: this
//! crate has no storage. The intended wiring (Phase 2) is TOFU-pinning plus the audit
//! chain - a config change must ride an `EscrowQuorumChanged` entry, and the optional
//! [`SignedEscrowConfig::binding`] head ties a config to the chain state it was
//! established under.
//!
//! # Admin is not escrow holder
//!
//! Two separate roles. An admin enrols users and manages ACLs; an escrow holder can
//! recover data belonging to others. A new admin does not become an escrow holder by
//! default, which is what lets a second admin administer without gaining recovery power.
//! The admin who *signs* the config authorises policy; signing grants no share.
//!
//! # Limitations, stated rather than hidden
//!
//! - Re-sharding reconstructs the escrow private key in memory on one machine. Inherent
//!   to secret sharing.
//! - Raising the quorum is forward-looking only: it cannot retract a copy a previous sole
//!   holder retained.
//! - The signature authenticates the config against *users*; an attacker holding the
//!   authorising admin's key can still rewrite it. That is the trust anchor, not a gap.

use serde::{Deserialize, Serialize};

use crate::chain::Head;
use crate::envelope::{self, ContentKey, WrappedKey, CONTEXT_ESCROW_SHARE};
use crate::identity::{cbor, Identity, KeyId, PublicIdentity};
use crate::{Error, Result};

/// Domain tag for the escrow-config signature. Length-prefixed CBOR follows it, so this
/// signature can never be confused with a chain-entry signature or any other kind.
const CONFIG_SIGNING_DOMAIN: &[u8] = b"remotino/v1/escrow-config";

/// Quorum configuration: `k` of `n` shares required to recover.
///
/// Serialised from day one even at `k = n = 1`, so raising the quorum later is a policy
/// change rather than a format migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quorum {
    /// Shares required to recover.
    pub k: u8,
    /// Shares issued.
    pub n: u8,
}

impl Quorum {
    /// A single holder - the founding-admin case.
    pub const SOLE: Self = Self { k: 1, n: 1 };

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `k` is zero or exceeds `n`.
    pub fn validate(self) -> Result<()> {
        if self.k == 0 {
            return Err(Error::Malformed("quorum k must be at least 1"));
        }
        if self.k > self.n {
            return Err(Error::Malformed("quorum k exceeds n"));
        }
        Ok(())
    }

    /// Whether recovery needs cooperation between holders.
    #[must_use]
    pub const fn requires_cooperation(self) -> bool {
        self.k > 1
    }
}

/// Scope of what escrow may recover (`DESIGN.md` 8.4).
///
/// Separate from [`Quorum`]: the quorum governs *who* can recover, this governs *what* is
/// recoverable at all. Enforced at the point of use by
/// [`VerifiedEscrowConfig::wrap_key`], and authenticated by the config signature -
/// widening the scope requires re-signing by an admin, which in turn (Phase 2) requires
/// a quorum-authorised `EscrowQuorumChanged` chain entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowScope {
    /// Shared folder keys. Defaults on: org data should survive a forgotten passphrase.
    pub shared_folders: bool,
    /// Personal vaults. Defaults **off**: enabling it lets admins read users' personal
    /// credentials, which must be a deliberate and disclosed choice, never a silent one.
    pub personal_vaults: bool,
}

impl Default for EscrowScope {
    fn default() -> Self {
        Self {
            shared_folders: true,
            personal_vaults: false,
        }
    }
}

/// What kind of key an escrow wrap is for. Determines which [`EscrowScope`] flag
/// governs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowClass {
    /// A shared folder's content key.
    SharedFolder,
    /// A user's personal vault key.
    PersonalVault,
}

/// The escrow configuration proper.
///
/// Fields are private on purpose: a value of this type may have come off disk without
/// any authentication, so nothing outside this module can reach the escrow public key
/// or the shares through it. All consumption goes through [`VerifiedEscrowConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowConfig {
    /// Escrow public key. Content keys are additionally wrapped to this.
    ///
    /// Stable across re-shards - that stability is what keeps admin changes cheap.
    public: PublicIdentity,
    /// Current quorum.
    quorum: Quorum,
    /// What may be recovered.
    scope: EscrowScope,
    /// One entry per holder.
    shares: Vec<EscrowShare>,
}

/// One holder's share of the escrow private key, sealed to that holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowShare {
    /// Holder this share is sealed to.
    pub holder: KeyId,
    /// Share index, `1..=n`. Meaningful only when `k > 1`.
    ///
    /// Constrained now, while the format is cheap to constrain: index 0 is the Shamir
    /// evaluation point where the polynomial *equals the secret itself*, so a future
    /// combiner that trusted an unvalidated index could be handed the secret's own
    /// x-coordinate by a hostile config (REVIEW-EXTERNAL.md finding 10).
    pub index: u8,
    /// The sealed share.
    pub wrapped: WrappedKey,
}

impl EscrowConfig {
    /// Creates a sole-holder configuration.
    ///
    /// The escrow private key is generated, sealed to `holder`, and dropped. This is the
    /// starting state described in `DESIGN.md` 9.4a: one admin who can recover anything.
    ///
    /// The result is inert until signed ([`SignedEscrowConfig::sign`]) and later
    /// verified - an unsigned config cannot wrap or recover anything.
    ///
    /// # Errors
    ///
    /// Propagates randomness and wrapping failures.
    pub fn create_sole(holder: &PublicIdentity, scope: EscrowScope) -> Result<Self> {
        let escrow_identity = Identity::generate()?;

        // For k = 1 the "share" is the escrow secret itself, sealed to the single holder -
        // no splitting is involved. Represented as a one-element list so the format is
        // identical to the k > 1 case.
        //
        // It must be the *actual* escrow secret. An earlier version sealed an unrelated
        // random key here, so recovery reported success and returned material that could
        // decrypt nothing. See REVIEW.md finding 2.
        let wrapped = envelope::seal_to(
            holder,
            &escrow_identity.secret_bytes(),
            CONTEXT_ESCROW_SHARE,
        )?;

        // escrow_identity is dropped here. The only surviving copy is inside `wrapped`,
        // retrievable solely by the holder - which is the point.
        Ok(Self {
            public: escrow_identity.public().clone(),
            quorum: Quorum::SOLE,
            scope,
            shares: vec![EscrowShare {
                holder: holder.key_id(),
                index: 1,
                wrapped,
            }],
        })
    }

    /// Structural validation, run before signing and again after signature verification.
    ///
    /// Signature verification proves the config is the one an admin authorised;
    /// this proves the authorised config is itself coherent. Both run on every
    /// verify so a buggy (or old) signer cannot put a malformed config into
    /// circulation.
    fn validate(&self) -> Result<()> {
        self.quorum.validate()?;

        // Exactly one share per issued slot. A count mismatch means the config was
        // assembled inconsistently, and a surplus share is exactly the shape of the
        // shadowing attack in REVIEW-EXTERNAL.md finding 9.
        if self.shares.len() != usize::from(self.quorum.n) {
            return Err(Error::Malformed("share count does not match quorum n"));
        }

        for (i, share) in self.shares.iter().enumerate() {
            if share.index == 0 || share.index > self.quorum.n {
                return Err(Error::Malformed("share index outside 1..=n"));
            }
            // O(n^2), and fine: n is at most 255 and in practice single digits.
            for other in self.shares.get(..i).unwrap_or(&[]) {
                if other.holder == share.holder {
                    return Err(Error::Malformed("duplicate share holder"));
                }
                if other.index == share.index {
                    return Err(Error::Malformed("duplicate share index"));
                }
            }
        }
        Ok(())
    }
}

/// The signed form of the escrow configuration - the only form that is stored.
///
/// Carries the admin signature over `domain || CBOR((config, authorized_by, binding))`.
/// Decoding one of these gives you nothing usable: to wrap or recover you must
/// first obtain a [`VerifiedEscrowConfig`] via [`SignedEscrowConfig::verify`].
///
/// No `Deserialize` on purpose: bytes become a value of this type only through
/// [`SignedEscrowConfig::from_bytes`], which rejects non-canonical CBOR - the same
/// contract as [`crate::chain::Entry`]. The stored byte form of a given config is
/// thereby unique, so a store cannot hold two byte-distinct copies of "the same"
/// signed config.
#[derive(Debug, Clone, Serialize)]
pub struct SignedEscrowConfig {
    config: EscrowConfig,
    /// The admin who authorised this configuration. Covered by the signature.
    authorized_by: KeyId,
    /// Chain head at the moment the config was established, if the caller supplied one.
    ///
    /// Covered by the signature. This is the hook that lets Phase 2 tie a config to the
    /// `EscrowQuorumChanged` entry that authorised it: a client that knows the chain can
    /// demand that the binding head actually exists in it, which turns "replay an old
    /// signed config" from silent into detectable. This crate does not resolve the
    /// binding itself - `Repository` is the seam, and there is deliberately no storage
    /// layer here.
    binding: Option<Head>,
    #[serde(with = "serde_big_array::BigArray")]
    signature: [u8; 64],
}

/// Wire form of [`SignedEscrowConfig`]: same fields, no invariants, `Deserialize`
/// only, so decoding funnels through [`SignedEscrowConfig::from_bytes`]. Field names
/// and order must stay identical to `SignedEscrowConfig` or the canonical encoding
/// silently changes.
#[derive(Deserialize)]
struct SignedEscrowConfigWire {
    config: EscrowConfig,
    authorized_by: KeyId,
    binding: Option<Head>,
    #[serde(with = "serde_big_array::BigArray")]
    signature: [u8; 64],
}

fn config_signing_message(
    config: &EscrowConfig,
    authorized_by: &KeyId,
    binding: Option<&Head>,
) -> Result<Vec<u8>> {
    let mut msg = CONFIG_SIGNING_DOMAIN.to_vec();
    msg.extend_from_slice(&cbor(&(config, authorized_by, binding))?);
    Ok(msg)
}

impl SignedEscrowConfig {
    /// Signs `config` with the authorising admin's identity.
    ///
    /// Pass the current chain [`Head`] as `binding` when one is available; it is
    /// covered by the signature and lets verifiers tie the config to chain state.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the config fails structural validation - a malformed
    /// config must not be signable, or the signature would launder it.
    pub fn sign(config: EscrowConfig, binding: Option<Head>, admin: &Identity) -> Result<Self> {
        config.validate()?;
        let authorized_by = admin.key_id();
        let msg = config_signing_message(&config, &authorized_by, binding.as_ref())?;
        Ok(Self {
            signature: admin.sign(&msg),
            config,
            authorized_by,
            binding,
        })
    }

    /// Verifies the signature against a trusted admin key and returns the verified
    /// configuration - the only route to one.
    ///
    /// `trusted_admin` must come from somewhere the attacker cannot write: the caller's
    /// TOFU pin, or resolution through the verified audit chain. Verifying against a
    /// `PublicIdentity` read from the same store the config came from would be
    /// circular and worthless.
    ///
    /// # Errors
    ///
    /// [`Error::ChainIntegrity`] if the config claims a different authoriser than
    /// `trusted_admin`; [`Error::Signature`] if the signature does not verify;
    /// [`Error::Malformed`] if the signed config fails structural validation.
    pub fn verify(&self, trusted_admin: &PublicIdentity) -> Result<VerifiedEscrowConfig> {
        // The claimed authoriser must BE the trusted key, not merely some key whose
        // signature checks out - otherwise any enrolled user could self-sign a config.
        if trusted_admin.key_id() != self.authorized_by {
            return Err(Error::ChainIntegrity(
                "escrow config not authorised by the trusted admin",
            ));
        }
        let msg = config_signing_message(&self.config, &self.authorized_by, self.binding.as_ref())?;
        trusted_admin.verify(&msg, &self.signature)?;
        self.config.validate()?;
        Ok(VerifiedEscrowConfig {
            config: self.config.clone(),
            binding: self.binding,
        })
    }

    /// Encodes this signed config as its canonical bytes - the only form to store.
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] if the config cannot be canonically encoded.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        cbor(self)
    }

    /// Decodes a signed config from stored bytes, rejecting non-canonical encodings.
    ///
    /// The only way to obtain a [`SignedEscrowConfig`] from bytes; the type has no
    /// `Deserialize` impl. The input must be byte-identical to the canonical encoding
    /// of the value it decodes to, exactly as [`crate::chain::Entry::from_bytes`]
    /// requires - one contract for everything read back from shared storage that
    /// carries a signature.
    ///
    /// # Errors
    ///
    /// [`Error::Encoding`] if the bytes do not decode (which includes an embedded
    /// public key failing its own canonical-encoding validation), or decode but are
    /// not the canonical encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let wire: SignedEscrowConfigWire =
            ciborium::from_reader(bytes).map_err(|_| Error::Encoding("cbor decode"))?;
        let config = Self {
            config: wire.config,
            authorized_by: wire.authorized_by,
            binding: wire.binding,
            signature: wire.signature,
        };
        if cbor(&config)? != bytes {
            return Err(Error::Encoding(
                "non-canonical CBOR encoding of an escrow config",
            ));
        }
        Ok(config)
    }

    /// The admin this config claims as its authoriser. Useful for choosing which pinned
    /// key to verify against; trusting it for anything else defeats the signature.
    #[must_use]
    pub fn authorized_by(&self) -> KeyId {
        self.authorized_by
    }

    /// The chain head this config was bound to at signing, if any.
    #[must_use]
    pub fn binding(&self) -> Option<Head> {
        self.binding
    }
}

/// An escrow configuration whose admin signature has been verified.
///
/// This type is the whole point of the escrow authentication design: it has no
/// `Deserialize`, no public constructor, and can only be produced by
/// [`SignedEscrowConfig::verify`]. Holding one *is* the proof that the config was
/// authorised. Every operation that consumes escrow policy - wrapping a key to escrow,
/// checking holdership, recovery - lives here and nowhere else.
#[derive(Debug, Clone)]
pub struct VerifiedEscrowConfig {
    config: EscrowConfig,
    binding: Option<Head>,
}

impl VerifiedEscrowConfig {
    /// The escrow identity's stable id, for display and out-of-band fingerprinting.
    ///
    /// Deliberately *not* the [`PublicIdentity`] itself: handing out the raw public key
    /// would invite callers to wrap to it directly, bypassing the scope check that
    /// [`VerifiedEscrowConfig::wrap_key`] enforces. All escrow wraps go through
    /// `wrap_key`.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.config.public.key_id()
    }

    /// Current quorum.
    #[must_use]
    pub fn quorum(&self) -> Quorum {
        self.config.quorum
    }

    /// What this configuration permits recovering.
    #[must_use]
    pub fn scope(&self) -> EscrowScope {
        self.config.scope
    }

    /// The chain head the config was bound to at signing, if any.
    #[must_use]
    pub fn binding(&self) -> Option<Head> {
        self.binding
    }

    /// The holders issued shares, for display.
    pub fn holders(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.config.shares.iter().map(|s| s.holder)
    }

    /// Wraps `key` to the escrow public key, if and only if the configured scope
    /// covers keys of `class`.
    ///
    /// This is the sole path from a key to an escrow wrap, and it is where
    /// [`EscrowScope`] stops being documentation and becomes a control: with
    /// `personal_vaults: false`, no code path exists that wraps a personal vault key to
    /// escrow (REVIEW-EXTERNAL.md critical 2).
    ///
    /// # Errors
    ///
    /// [`Error::EscrowScope`] if the scope excludes `class`; otherwise propagates
    /// wrapping failures.
    pub fn wrap_key(&self, key: &ContentKey, class: EscrowClass) -> Result<WrappedKey> {
        let allowed = match class {
            EscrowClass::SharedFolder => self.config.scope.shared_folders,
            EscrowClass::PersonalVault => self.config.scope.personal_vaults,
        };
        if !allowed {
            return Err(Error::EscrowScope(match class {
                EscrowClass::SharedFolder => "shared folders are not escrowed by this configuration",
                EscrowClass::PersonalVault => {
                    "personal vaults are not escrowed by this configuration"
                }
            }));
        }
        key.wrap_to(&self.config.public)
    }

    /// Finds the share addressed to `identity`, if any.
    fn share_for(&self, identity: &Identity) -> Option<&EscrowShare> {
        let id = identity.key_id();
        self.config.shares.iter().find(|s| s.holder == id)
    }

    /// Whether `identity` holds a share - i.e. is an escrow holder, not merely an admin.
    #[must_use]
    pub fn is_holder(&self, identity: &Identity) -> bool {
        self.share_for(identity).is_some()
    }

    /// Recovers the escrow **identity** from the supplied holders.
    ///
    /// Returns an [`Identity`], not a bare key: the caller needs something that can
    /// actually unwrap content keys sealed to the escrow public key. Returning opaque
    /// key material was what let the earlier bug go unnoticed.
    ///
    /// Holders are counted as **distinct identities holding shares**, never as
    /// arguments: the same identity supplied three times contributes one
    /// (REVIEW-EXTERNAL.md finding 3). This matters more than it looks - the quorum
    /// check runs before the (future) Shamir combination, so this count is the gate a
    /// `k > 1` implementation will inherit and trust.
    ///
    /// # Errors
    ///
    /// [`Error::QuorumNotMet`] if fewer than `k` distinct holders supplied a share.
    /// [`Error::Unsupported`] for `k > 1`: Shamir combination is not implemented yet. The
    /// format already carries `k` and `n`, so enabling it is an implementation change and
    /// not a migration.
    /// [`Error::Malformed`] if a share disagrees with its holder's actual wrapping key.
    /// [`Error::ChainIntegrity`] if the recovered identity does not match the configured
    /// escrow public key - which would mean the config and the shares disagree.
    pub fn recover(&self, holders: &[&Identity]) -> Result<Identity> {
        // Deduplicate by KeyId before counting. `share_for` alone would happily match
        // the same share once per duplicate argument.
        let mut seen: Vec<KeyId> = Vec::new();
        let mut present: Vec<(&EscrowShare, &Identity)> = Vec::new();
        for holder in holders {
            let id = holder.key_id();
            if seen.contains(&id) {
                continue;
            }
            if let Some(share) = self.share_for(holder) {
                seen.push(id);
                present.push((share, holder));
            }
        }

        // Fail closed: if the count ever cannot be represented, that is an error, not a
        // saturation. The previous `unwrap_or(u8::MAX)` rounded a security counter UP.
        let have = u8::try_from(present.len())
            .map_err(|_| Error::Malformed("holder count exceeds representable range"))?;
        if have < self.config.quorum.k {
            return Err(Error::QuorumNotMet {
                have,
                need: self.config.quorum.k,
            });
        }

        if self.config.quorum.requires_cooperation() {
            return Err(Error::Unsupported(
                "k-of-n share combination not implemented; only k = 1 is supported so far",
            ));
        }

        let (share, holder) = present.first().ok_or(Error::QuorumNotMet {
            have: 0,
            need: self.config.quorum.k,
        })?;

        // The share's routing hint must agree with the holder it names. Decryption
        // would fail anyway on a mismatch (the KEK never trusts this field), but
        // checking here turns "escrow silently broken by an inconsistent config" into
        // a diagnosable error before any recovery attempt (REVIEW-EXTERNAL.md
        // finding 9).
        if share.wrapped.recipient != *holder.public().wrapping() {
            return Err(Error::Malformed(
                "share recipient does not match its holder's wrapping key",
            ));
        }

        let secret = envelope::open_sealed(&share.wrapped, holder, CONTEXT_ESCROW_SHARE)?;
        let recovered = Identity::from_secret_slice(&secret)?;

        // The recovered identity must be the one the config advertises. A mismatch means
        // config and shares disagree - refuse rather than hand back a key that silently
        // decrypts nothing.
        if recovered.public().wrapping() != self.config.public.wrapping()
            || recovered.public().verifying() != self.config.public.verifying()
        {
            return Err(Error::ChainIntegrity(
                "recovered escrow identity does not match the configured escrow public key",
            ));
        }
        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ContentKey;

    /// Sign-and-verify round trip an honest config, as production code would.
    fn establish(
        holder: &Identity,
        admin: &Identity,
        scope: EscrowScope,
    ) -> VerifiedEscrowConfig {
        let config = EscrowConfig::create_sole(holder.public(), scope).unwrap();
        let signed = SignedEscrowConfig::sign(config, None, admin).unwrap();
        signed.verify(admin.public()).unwrap()
    }

    #[test]
    fn sole_holder_can_recover() {
        let admin = Identity::generate().unwrap();
        let config = establish(&admin, &admin, EscrowScope::default());
        assert!(config.recover(&[&admin]).is_ok());
    }

    #[test]
    fn escrow_recovered_identity_unwraps_content_keys() {
        // THE test this module exists for, and the one whose absence let a critical bug
        // pass 39 green tests: recovery must return material that actually decrypts.
        // Previously recover() returned an unrelated random key and still reported Ok.
        let admin = Identity::generate().unwrap();
        let config = establish(&admin, &admin, EscrowScope::default());

        // A folder key wrapped to the escrow public key, as the design requires -
        // through the scope-checked path, since that is now the only path.
        let folder_key = ContentKey::generate().unwrap();
        let wrapped_to_escrow = config
            .wrap_key(&folder_key, EscrowClass::SharedFolder)
            .unwrap();
        let sealed = folder_key.seal(b"production credentials", b"folder-1").unwrap();

        // Simulate the user being gone: only the escrow path remains.
        let recovered_escrow = config.recover(&[&admin]).unwrap();
        let recovered_key = ContentKey::unwrap_for(&wrapped_to_escrow, &recovered_escrow).unwrap();

        assert_eq!(
            recovered_key.open(&sealed, b"folder-1").unwrap().as_slice(),
            b"production credentials",
            "escrow must recover data, not merely report success"
        );
    }

    #[test]
    fn recovered_identity_matches_the_configured_public_key() {
        let admin = Identity::generate().unwrap();
        let raw = EscrowConfig::create_sole(admin.public(), EscrowScope::default()).unwrap();
        let expected = raw.public.clone();
        let signed = SignedEscrowConfig::sign(raw, None, &admin).unwrap();
        let config = signed.verify(admin.public()).unwrap();

        let recovered = config.recover(&[&admin]).unwrap();
        assert_eq!(recovered.public().wrapping(), expected.wrapping());
        assert_eq!(recovered.public().verifying(), expected.verifying());
    }

    #[test]
    fn mismatched_share_is_rejected() {
        // If config and shares disagree, fail loudly rather than return a key that
        // silently decrypts nothing.
        let admin = Identity::generate().unwrap();
        let mut config = EscrowConfig::create_sole(admin.public(), EscrowScope::default()).unwrap();
        let other = EscrowConfig::create_sole(admin.public(), EscrowScope::default()).unwrap();
        config.shares = other.shares;
        let verified = SignedEscrowConfig::sign(config, None, &admin)
            .unwrap()
            .verify(admin.public())
            .unwrap();
        assert!(verified.recover(&[&admin]).is_err());
    }

    #[test]
    fn second_admin_is_not_a_holder() {
        // The core of DESIGN.md 9.4a: admin 2 administers but cannot recover, because
        // being an admin does not imply holding a share.
        let admin1 = Identity::generate().unwrap();
        let admin2 = Identity::generate().unwrap();
        let config = establish(&admin1, &admin1, EscrowScope::default());

        assert!(config.is_holder(&admin1));
        assert!(!config.is_holder(&admin2));
        assert!(matches!(
            config.recover(&[&admin2]),
            Err(Error::QuorumNotMet { .. })
        ));
    }

    #[test]
    fn personal_vaults_are_not_escrowed_by_default() {
        let scope = EscrowScope::default();
        assert!(scope.shared_folders);
        assert!(!scope.personal_vaults, "personal vault escrow must be opt-in");
    }

    #[test]
    fn quorum_validation_rejects_nonsense() {
        assert!(Quorum { k: 0, n: 3 }.validate().is_err());
        assert!(Quorum { k: 4, n: 3 }.validate().is_err());
        assert!(Quorum { k: 2, n: 3 }.validate().is_ok());
    }

    // ------------------------------------------------------------------
    // Adversarial constructions. Per the meta-lesson in REVIEW-EXTERNAL.md, each of
    // these builds its hostile structure FROM SCRATCH - the way an attacker with write
    // access to the store actually would - rather than perturbing one field of an
    // honest value. Tests are named for the attack they foreclose.
    // ------------------------------------------------------------------

    /// Builds a from-scratch k-of-n config with `holders.first()` holding the real
    /// escrow secret and the rest holding filler shares. Only structurally valid;
    /// recovery past the quorum gate is not the point of the tests that use it.
    fn config_from_scratch(k: u8, holders: &[&Identity], scope: EscrowScope) -> EscrowConfig {
        let escrow_identity = Identity::generate().unwrap();
        let shares = holders
            .iter()
            .enumerate()
            .map(|(i, h)| EscrowShare {
                holder: h.key_id(),
                index: u8::try_from(i).unwrap() + 1,
                wrapped: envelope::seal_to(
                    h.public(),
                    &escrow_identity.secret_bytes(),
                    CONTEXT_ESCROW_SHARE,
                )
                .unwrap(),
            })
            .collect();
        EscrowConfig {
            public: escrow_identity.public().clone(),
            quorum: Quorum { k, n: u8::try_from(holders.len()).unwrap() },
            scope,
            shares,
        }
    }

    #[test]
    fn wholesale_config_swap_cannot_redirect_wraps() {
        // REVIEW-EXTERNAL.md critical 1. Mallory, an enrolled user with store write
        // access, replaces the stored config wholesale: her own keypair as the escrow
        // key, one share sealed to herself, self-signed with her own key. Every field
        // is internally consistent - the earlier recovered-identity check passes,
        // because she controls both operands. The ONLY thing that stops every honest
        // client from wrapping future folder keys to her is that verification is
        // against the pinned admin key, which she does not hold.
        let admin = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();

        let hostile = config_from_scratch(1, &[&mallory], EscrowScope::default());
        let self_signed = SignedEscrowConfig::sign(hostile, None, &mallory).unwrap();

        // Round-trip through bytes: the attack arrives from storage, not from memory.
        let stored = self_signed.to_bytes().unwrap();
        let read_back = SignedEscrowConfig::from_bytes(&stored).unwrap();

        // Sanity: her own signature is internally valid...
        assert!(read_back.verify(mallory.public()).is_ok());
        // ...but an honest client verifies against the admin it trusts, and the swap
        // dies before any wrap call is reachable.
        assert!(read_back.verify(admin.public()).is_err());
    }

    #[test]
    fn scope_widened_in_storage_is_rejected() {
        // REVIEW-EXTERNAL.md critical 2: the two-byte edit that flips
        // personal_vaults to true. The signature covers the scope, so the edited
        // config no longer verifies.
        let admin = Identity::generate().unwrap();
        let signed = SignedEscrowConfig::sign(
            EscrowConfig::create_sole(admin.public(), EscrowScope::default()).unwrap(),
            None,
            &admin,
        )
        .unwrap();

        let mut tampered = signed.clone();
        tampered.config.scope.personal_vaults = true;
        assert!(matches!(
            tampered.verify(admin.public()),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn out_of_scope_wrap_is_refused_at_the_point_of_use() {
        // Even with an honestly-signed config, scope is a control, not a comment:
        // there is no code path that wraps a personal vault key while the scope
        // excludes it.
        let admin = Identity::generate().unwrap();
        let config = establish(&admin, &admin, EscrowScope::default());
        let vault_key = ContentKey::generate().unwrap();

        assert!(matches!(
            config.wrap_key(&vault_key, EscrowClass::PersonalVault),
            Err(Error::EscrowScope(_))
        ));
        // The scoped-in class still wraps.
        assert!(config.wrap_key(&vault_key, EscrowClass::SharedFolder).is_ok());
    }

    #[test]
    fn opted_in_personal_vault_scope_wraps() {
        let admin = Identity::generate().unwrap();
        let scope = EscrowScope { shared_folders: true, personal_vaults: true };
        let config = establish(&admin, &admin, scope);
        let vault_key = ContentKey::generate().unwrap();
        assert!(config.wrap_key(&vault_key, EscrowClass::PersonalVault).is_ok());
    }

    #[test]
    fn replaying_one_admin_does_not_meet_a_higher_quorum() {
        // REVIEW-EXTERNAL.md finding 3: recover(&[&a, &a, &a]) once yielded have == 3.
        // The quorum gate must count distinct holders, because it runs BEFORE the
        // (future) Shamir combination and is the gate that implementation will trust.
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let c = Identity::generate().unwrap();
        let config = config_from_scratch(2, &[&a, &b, &c], EscrowScope::default());
        let verified = SignedEscrowConfig::sign(config, None, &a)
            .unwrap()
            .verify(a.public())
            .unwrap();

        match verified.recover(&[&a, &a, &a]) {
            Err(Error::QuorumNotMet { have: 1, need: 2 }) => {}
            other => panic!("expected QuorumNotMet have=1, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_holder_shares_cannot_shadow_the_real_one() {
        // REVIEW-EXTERNAL.md finding 9: a config carrying two shares for the same
        // holder - a bogus one first, the real one second - would permanently kill
        // escrow, because share_for returns the first match. Such a config must not
        // survive validation, however it was assembled.
        let admin = Identity::generate().unwrap();
        let victim = Identity::generate().unwrap();
        let honest = config_from_scratch(1, &[&victim], EscrowScope::default());

        let bogus_first = EscrowConfig {
            public: honest.public.clone(),
            quorum: Quorum { k: 1, n: 2 },
            scope: honest.scope,
            shares: vec![
                // The shadow: victim's KeyId, garbage sealed to the attacker.
                EscrowShare {
                    holder: victim.key_id(),
                    index: 1,
                    wrapped: envelope::seal_to(admin.public(), &[0u8; 64], CONTEXT_ESCROW_SHARE)
                        .unwrap(),
                },
                honest.shares.into_iter().next().map(|mut s| {
                    s.index = 2;
                    s
                })
                .unwrap(),
            ],
        };

        assert!(
            SignedEscrowConfig::sign(bogus_first, None, &admin).is_err(),
            "a config with duplicate holders must not even be signable"
        );
    }

    #[test]
    fn share_whose_recipient_disagrees_with_its_holder_is_diagnosed() {
        // The single-share variant of finding 9: the share names the victim as holder
        // but is actually sealed to the attacker. Recovery must fail with a
        // diagnosable error before any decryption attempt.
        let attacker = Identity::generate().unwrap();
        let victim = Identity::generate().unwrap();
        let escrow_identity = Identity::generate().unwrap();

        let hostile = EscrowConfig {
            public: escrow_identity.public().clone(),
            quorum: Quorum::SOLE,
            scope: EscrowScope::default(),
            shares: vec![EscrowShare {
                holder: victim.key_id(),
                index: 1,
                wrapped: envelope::seal_to(
                    attacker.public(),
                    &escrow_identity.secret_bytes(),
                    CONTEXT_ESCROW_SHARE,
                )
                .unwrap(),
            }],
        };
        // Structurally valid, so it signs; the inconsistency is only observable
        // against the victim's actual key at recovery time.
        let verified = SignedEscrowConfig::sign(hostile, None, &attacker)
            .unwrap()
            .verify(attacker.public())
            .unwrap();

        assert!(matches!(
            verified.recover(&[&victim]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn share_index_zero_is_unrepresentable() {
        // Index 0 is the Shamir evaluation point where the polynomial equals the
        // secret itself. A hostile config must not be able to put one in circulation.
        let admin = Identity::generate().unwrap();
        let mut config = config_from_scratch(1, &[&admin], EscrowScope::default());
        if let Some(s) = config.shares.first_mut() {
            s.index = 0;
        }
        assert!(SignedEscrowConfig::sign(config, None, &admin).is_err());
    }

    #[test]
    fn share_count_must_match_n() {
        let admin = Identity::generate().unwrap();
        let mut config = config_from_scratch(1, &[&admin], EscrowScope::default());
        config.quorum = Quorum { k: 1, n: 3 };
        assert!(SignedEscrowConfig::sign(config, None, &admin).is_err());
    }

    #[test]
    fn multi_holder_recovery_reports_unimplemented_not_wrong_answer() {
        // Failing loudly is correct here. Silently accepting one share under a k = 2
        // policy would be a security hole disguised as a partial implementation.
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let config = config_from_scratch(2, &[&a, &b], EscrowScope::default());
        let verified = SignedEscrowConfig::sign(config, None, &a)
            .unwrap()
            .verify(a.public())
            .unwrap();

        match verified.recover(&[&a]) {
            Err(Error::QuorumNotMet { have: 1, need: 2 }) => {}
            other => panic!("expected QuorumNotMet, got {other:?}"),
        }
        assert!(matches!(
            verified.recover(&[&a, &b]),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn noncanonical_encoding_of_a_stored_escrow_config_is_rejected() {
        // Same contract as chain entries (REVIEW.md, "CBOR is not canonical"): the
        // stored bytes of a signed config are unique. Rewrite the definite-length
        // top-level map as an indefinite-length one - same decoded value, different
        // bytes - and the decode path must refuse it.
        let admin = Identity::generate().unwrap();
        let signed = SignedEscrowConfig::sign(
            EscrowConfig::create_sole(admin.public(), EscrowScope::default()).unwrap(),
            None,
            &admin,
        )
        .unwrap();
        let bytes = signed.to_bytes().unwrap();
        assert_eq!(*bytes.first().unwrap(), 0xa4, "config must encode as a 4-entry map");

        let mut aliased = bytes.clone();
        aliased[0] = 0xbf;
        aliased.push(0xff);
        assert!(matches!(
            SignedEscrowConfig::from_bytes(&aliased),
            Err(Error::Encoding(_))
        ));
        // The canonical bytes still decode, and to the same config.
        let back = SignedEscrowConfig::from_bytes(&bytes).unwrap();
        assert!(back.verify(admin.public()).is_ok());
    }

    #[test]
    fn binding_is_covered_by_the_signature() {
        // The chain-binding hook is only worth having if it cannot be stripped or
        // swapped without re-signing.
        let admin = Identity::generate().unwrap();
        let head = Head { seq: 7, digest: crate::Digest::of(b"somewhere in the chain") };
        let signed = SignedEscrowConfig::sign(
            EscrowConfig::create_sole(admin.public(), EscrowScope::default()).unwrap(),
            Some(head),
            &admin,
        )
        .unwrap();

        let mut stripped = signed.clone();
        stripped.binding = None;
        assert!(stripped.verify(admin.public()).is_err());

        let mut swapped = signed.clone();
        swapped.binding = Some(Head { seq: 3, digest: crate::Digest::of(b"elsewhere") });
        assert!(swapped.verify(admin.public()).is_err());

        assert_eq!(signed.verify(admin.public()).unwrap().binding(), Some(head));
    }
}
