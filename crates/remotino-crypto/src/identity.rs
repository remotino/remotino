//! User identity: an Ed25519 signing key and an X25519 wrapping key.
//!
//! Two keys, not one, because the roles differ. The signing key attributes audit entries
//! ([`crate::chain`]); the wrapping key receives content keys sealed to it
//! ([`crate::envelope`]). Keeping them separate means a signing key can be rotated
//! without re-wrapping every folder key in the repository.
//!
//! At rest the private halves are sealed with a passphrase-derived key
//! ([`crate::kdf`]), which is what makes the passphrase the login to the tool.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::envelope::{self, SealedBlob};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::{Digest, Error, Result};

/// Stable identifier for an identity: SHA-256 over both public keys.
///
/// Derived rather than random so two parties independently holding the same public keys
/// always compute the same id, and a mismatched id is detectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub Digest);

impl core::fmt::Display for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 16 hex chars is plenty to disambiguate a handful of users and fits in a UI.
        let prefix = self.0.0.get(..8).unwrap_or(&self.0.0);
        f.write_str(&hex::encode(prefix))
    }
}

/// The public half of an identity - safe to publish in `users/<keyid>.pub`.
///
/// # Every value of this type holds canonical key encodings
///
/// Both curves accept multiple byte encodings of the same key: Ed25519 point decoding
/// tolerates non-canonical y-coordinates (ZIP-215 rules), and X25519 discards bit 255
/// and reduces the field element mod p. Left unchecked, one keypair therefore admits
/// several distinct byte encodings - and since [`KeyId`] hashes the bytes, several
/// distinct *identities* (REVIEW-EXTERNAL.md findings 4 and 5). Anything that counts
/// distinct parties - the escrow quorum above all - would be counting encodings, not
/// people.
///
/// So construction validates: [`PublicIdentity::new`] and the `Deserialize` impl both
/// reject non-canonical encodings and small-order Ed25519 keys. The fields are
/// `pub(crate)` rather than `pub` precisely so no path outside this module can build an
/// unvalidated value. `KeyId` is thereby a genuine one-to-one function of the keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "PublicIdentityWire")]
pub struct PublicIdentity {
    /// Ed25519 verifying key, for checking chain signatures.
    pub(crate) verifying: [u8; 32],
    /// X25519 public key, for receiving wrapped content keys.
    pub(crate) wrapping: [u8; 32],
}

/// Wire form of [`PublicIdentity`]: same fields, no invariants.
///
/// Exists so deserialisation can funnel through [`PublicIdentity::new`]. Field names
/// and order must stay identical to `PublicIdentity` or the CBOR encoding (and every
/// AAD built from it) silently changes.
#[derive(Deserialize)]
struct PublicIdentityWire {
    verifying: [u8; 32],
    wrapping: [u8; 32],
}

impl TryFrom<PublicIdentityWire> for PublicIdentity {
    type Error = Error;

    fn try_from(wire: PublicIdentityWire) -> Result<Self> {
        Self::new(wire.verifying, wire.wrapping)
    }
}

/// Little-endian encoding of the Curve25519 field prime `p = 2^255 - 19`.
const FIELD_PRIME_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x7f,
];

/// Whether `bytes` is the canonical encoding of an X25519 public key.
///
/// Canonical means: interpreted as a little-endian integer, the value is `< p`. The
/// X25519 function itself masks bit 255 and reduces mod p, so any value `>= p` is an
/// alias of some smaller one - same key, different bytes, different [`KeyId`].
fn x25519_encoding_is_canonical(bytes: &[u8; 32]) -> bool {
    // Compare as little-endian integers, most significant byte first.
    for (b, p) in bytes.iter().rev().zip(FIELD_PRIME_LE.iter().rev()) {
        if b < p {
            return true;
        }
        if b > p {
            return false;
        }
    }
    // Equal to p: reduces to zero, so it aliases the all-zero encoding.
    false
}

impl PublicIdentity {
    /// Validating constructor - the only way to build a `PublicIdentity`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if either key is not a canonical encoding, the Ed25519
    /// bytes do not decode to a curve point, or the Ed25519 key has small order (a
    /// "weak" key, with which one signature can validate for many messages).
    pub fn new(verifying: [u8; 32], wrapping: [u8; 32]) -> Result<Self> {
        let vk = VerifyingKey::from_bytes(&verifying)
            .map_err(|_| Error::Malformed("ed25519 key is not a valid point"))?;
        if vk.is_weak() {
            return Err(Error::Malformed("ed25519 key has small order"));
        }
        // `from_bytes` accepts non-canonical encodings and preserves the original bytes
        // through `to_bytes()`, so a round-trip through `to_bytes` would NOT detect
        // them. Recompressing the decoded point yields the canonical encoding.
        if vk.to_edwards().compress().to_bytes() != verifying {
            return Err(Error::Malformed("ed25519 key encoding is not canonical"));
        }
        if !x25519_encoding_is_canonical(&wrapping) {
            return Err(Error::Malformed("x25519 key encoding is not canonical"));
        }
        Ok(Self { verifying, wrapping })
    }

    /// The Ed25519 verifying key bytes.
    #[must_use]
    pub fn verifying(&self) -> &[u8; 32] {
        &self.verifying
    }

    /// The X25519 public key bytes.
    #[must_use]
    pub fn wrapping(&self) -> &[u8; 32] {
        &self.wrapping
    }
    /// Computes the identity's stable id: a domain-separated hash of **both** public keys.
    ///
    /// Both halves must be bound. An id derived from the wrapping key alone would let an
    /// attacker substitute their own signing key while keeping the victim's id, and
    /// [`crate::chain::Entry::verify`] would then accept their signature as the victim's.
    /// An earlier version had exactly that defect; see `REVIEW.md` finding 1.
    ///
    /// Fed to the hasher directly rather than assembled in a buffer - the buffer version
    /// needed slice indexing, which the workspace lints forbid, and the workaround is
    /// where the original bug hid.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"remotino/v1/keyid");
        hasher.update(self.verifying);
        hasher.update(self.wrapping);
        KeyId(Digest(hasher.finalize().into()))
    }

    /// Verifies `signature` over `message`.
    ///
    /// Uses `verify_strict`, not `verify`: the strict variant additionally rejects
    /// small-order components and non-canonical `R` values. Without it, an
    /// adversarially chosen key with a torsion component can produce one signature
    /// that validates for two different messages - repudiation, in a log whose stated
    /// purpose is unforgeable attribution (REVIEW-EXTERNAL.md finding 4). Every user
    /// chooses their own keypair, so this is an insider capability, not a theoretical
    /// one.
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if the signature does not verify strictly, or the key is
    /// not a valid Ed25519 point.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.verifying).map_err(|_| Error::Signature)?;
        let sig = Signature::from_bytes(signature);
        vk.verify_strict(message, &sig).map_err(|_| Error::Signature)
    }

    pub(crate) fn wrapping_public(&self) -> X25519Public {
        X25519Public::from(self.wrapping)
    }
}

/// A full identity, private halves included. Unlocked in memory only.
///
/// Zeroisation: both secret fields scrub themselves on drop - `SigningKey` and
/// `StaticSecret` implement `ZeroizeOnDrop` under the `zeroize` features this crate
/// enables (verified against the vendored 3.0.0 sources of both dalek crates). There
/// is no blanket `ZeroizeOnDrop` on `Identity` itself only because `PublicIdentity`
/// is not secret and not `Zeroize`; do not add secret fields here without zeroising
/// them.
pub struct Identity {
    signing: SigningKey,
    wrapping: X25519Secret,
    public: PublicIdentity,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Print the id, never the secrets.
        f.debug_struct("Identity")
            .field("key_id", &self.public.key_id())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generates a fresh identity from the OS random source.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the OS random source is unavailable.
    pub fn generate() -> Result<Self> {
        let mut sk = Zeroizing::new([0u8; 32]);
        let mut wk = Zeroizing::new([0u8; 32]);
        envelope::fill_random(sk.as_mut())?;
        envelope::fill_random(wk.as_mut())?;
        Ok(Self::from_secret_bytes(&sk, &wk))
    }

    fn from_secret_bytes(signing: &[u8; 32], wrapping: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(signing);
        let wrapping = X25519Secret::from(*wrapping);
        // Constructed directly rather than through `PublicIdentity::new`: keys derived
        // from secret scalars by the dalek crates are canonical by construction, and
        // this path must be infallible.
        let public = PublicIdentity {
            verifying: signing.verifying_key().to_bytes(),
            wrapping: X25519Public::from(&wrapping).to_bytes(),
        };
        Self {
            signing,
            wrapping,
            public,
        }
    }

    /// The publishable half.
    #[must_use]
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    /// This identity's stable id.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.public.key_id()
    }

    /// Signs `message` with the Ed25519 key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    pub(crate) fn wrapping_secret(&self) -> &X25519Secret {
        &self.wrapping
    }

    /// Exports the private halves as `signing || wrapping`.
    ///
    /// Used by [`crate::escrow`] to seal the escrow keypair to its holders. Deliberately
    /// `pub(crate)` and returning `Zeroizing`: this is the whole identity, and it should
    /// never be casually reachable or left in memory.
    pub(crate) fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.signing.to_bytes());
        out.extend_from_slice(&self.wrapping.to_bytes());
        Zeroizing::new(out)
    }

    /// Reconstructs an identity from [`Identity::secret_bytes`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the input is not exactly 64 bytes.
    pub(crate) fn from_secret_slice(bytes: &[u8]) -> Result<Self> {
        let signing: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Malformed("identity secret too short"))?,
        );
        let wrapping: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .get(32..64)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Malformed("identity secret too short"))?,
        );
        Ok(Self::from_secret_bytes(&signing, &wrapping))
    }

    /// Seals the private halves under a passphrase, producing something storable.
    ///
    /// # Errors
    ///
    /// Propagates KDF and AEAD failures.
    pub fn seal(&self, passphrase: &str, params: KdfParams) -> Result<SealedIdentity> {
        let mut salt = [0u8; SALT_LEN];
        envelope::fill_random(&mut salt)?;
        let key = kdf::derive(passphrase, &salt, params)?;

        let mut plaintext = Zeroizing::new([0u8; 64]);
        // The `to_bytes()` returns are unavoidable transient copies; keep them in
        // `Zeroizing` so at least the named copies are scrubbed.
        let sk = Zeroizing::new(self.signing.to_bytes());
        let wk = Zeroizing::new(self.wrapping.to_bytes());
        if let Some(s) = plaintext.get_mut(..32) {
            s.copy_from_slice(sk.as_ref());
        }
        if let Some(s) = plaintext.get_mut(32..) {
            s.copy_from_slice(wk.as_ref());
        }

        let aad = sealed_identity_aad(&self.public, &salt, params)?;
        let blob = envelope::seal_with_key(key.as_bytes(), plaintext.as_ref(), &aad)?;

        Ok(SealedIdentity {
            public: self.public.clone(),
            salt,
            params,
            blob,
        })
    }
}

/// An identity at rest: public halves in the clear, private halves sealed.
///
/// Everything stored in the clear here - `public`, `salt`, and `params` - is bound as
/// AAD over `blob` (see [`sealed_identity_aad`]), so editing any of them yields
/// [`Error::Decrypt`] instead of a confused unlock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedIdentity {
    /// The publishable half.
    pub public: PublicIdentity,
    /// Per-identity KDF salt.
    pub salt: [u8; SALT_LEN],
    /// KDF parameters in force when this was sealed. Checked against the policy
    /// window in [`crate::kdf`] before any derivation runs.
    pub params: KdfParams,
    /// The sealed private halves.
    pub blob: SealedBlob,
}

impl SealedIdentity {
    /// Unlocks the identity with a passphrase.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] for a wrong passphrase or tampered blob - deliberately
    /// indistinguishable.
    pub fn unlock(&self, passphrase: &str) -> Result<Identity> {
        // `derive` validates `self.params` against the policy window before doing any
        // work - that check is what stops a stored identity edited to demand a terabyte
        // allocation (or downgraded to a trivial cost) from ever reaching argon2.
        let key = kdf::derive(passphrase, &self.salt, self.params)?;
        let aad = sealed_identity_aad(&self.public, &self.salt, self.params)?;
        let plaintext = envelope::open_with_key(key.as_bytes(), &self.blob, &aad)?;

        let bytes = plaintext.as_slice();
        let signing: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Malformed("sealed identity too short"))?,
        );
        let wrapping: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .get(32..64)
                .and_then(|s| s.try_into().ok())
                .ok_or(Error::Malformed("sealed identity too short"))?,
        );

        let identity = Identity::from_secret_bytes(&signing, &wrapping);

        // A blob that decrypts but yields different public keys means the file was
        // assembled from mismatched parts. AAD should already prevent it; check anyway,
        // because silently adopting the wrong identity would be far worse than an error.
        if identity.public.verifying != self.public.verifying
            || identity.public.wrapping != self.public.wrapping
        {
            return Err(Error::Malformed("sealed identity does not match its public half"));
        }
        Ok(identity)
    }
}

/// Associated data for a [`SealedIdentity`] blob: a domain tag plus the CBOR of
/// `(public, salt, params)`.
///
/// Everything stored in the clear next to the blob is bound here, not just the public
/// half. Binding `salt` and `params` means an attacker who edits either - to redirect
/// derivation or to tamper with cost - produces a blob that fails to authenticate
/// rather than one that derives a wrong key with attacker-chosen work factors
/// (REVIEW-EXTERNAL.md finding 6). The KDF policy window in [`crate::kdf`] is the
/// *pre-derivation* defence; this is the post-derivation one. Both are needed: the AAD
/// check runs only after derivation has already spent the (attacker-chosen) cost.
fn sealed_identity_aad(
    public: &PublicIdentity,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Vec<u8>> {
    let mut aad = b"remotino/v1/sealed-identity".to_vec();
    aad.extend_from_slice(&cbor(&(public, salt, params))?);
    Ok(aad)
}

pub(crate) fn cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| Error::Encoding("cbor encode"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::floor()
    }

    #[test]
    fn seal_then_unlock_roundtrips() {
        let id = Identity::generate().unwrap();
        let sealed = id.seal("hunter2", params()).unwrap();
        let opened = sealed.unlock("hunter2").unwrap();
        assert_eq!(opened.key_id(), id.key_id());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let id = Identity::generate().unwrap();
        let sealed = id.seal("hunter2", params()).unwrap();
        assert!(matches!(sealed.unlock("hunter3"), Err(Error::Decrypt)));
    }

    #[test]
    fn signatures_verify_and_reject_tampering() {
        let id = Identity::generate().unwrap();
        let sig = id.sign(b"attack at dawn");
        id.public().verify(b"attack at dawn", &sig).unwrap();
        assert!(id.public().verify(b"attack at dusk", &sig).is_err());
    }

    #[test]
    fn foreign_key_does_not_verify() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let sig = a.sign(b"msg");
        assert!(b.public().verify(b"msg", &sig).is_err());
    }

    #[test]
    fn swapping_the_public_half_is_rejected() {
        // The attack this defends against: take someone's sealed blob, attach your own
        // public keys, and hope the client adopts a confused identity.
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let mut sealed = a.seal("pw", params()).unwrap();
        sealed.public = b.public().clone();
        assert!(sealed.unlock("pw").is_err());
    }

    #[test]
    fn key_id_binds_both_keys() {
        // REVIEW.md finding 1: key_id once hashed only the wrapping key, so an attacker
        // could keep a victim's id while substituting their own signing key.
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();

        let swapped_signing = PublicIdentity {
            verifying: b.public().verifying,
            wrapping: a.public().wrapping,
        };
        assert_ne!(swapped_signing.key_id(), a.public().key_id());

        let swapped_wrapping = PublicIdentity {
            verifying: a.public().verifying,
            wrapping: b.public().wrapping,
        };
        assert_ne!(swapped_wrapping.key_id(), a.public().key_id());
    }

    #[test]
    fn key_id_is_stable_and_distinct() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_eq!(a.key_id(), a.public().key_id());
        assert_ne!(a.key_id(), b.key_id());
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let id = Identity::generate().unwrap();
        let rendered = format!("{id:?}");
        assert!(!rendered.contains(&hex::encode(id.signing.to_bytes())));
    }

    // ------------------------------------------------------------------
    // Canonical-encoding enforcement (REVIEW-EXTERNAL.md findings 4 and 5). Built as
    // an attacker would build them: raw bytes fed through deserialisation, not honest
    // values perturbed after the fact.
    // ------------------------------------------------------------------

    /// Wire-shaped stand-in an attacker would serialise: same field names as
    /// `PublicIdentity`, no invariants.
    #[derive(serde::Serialize)]
    struct AttackerWire {
        verifying: [u8; 32],
        wrapping: [u8; 32],
    }

    fn decode(wire: &AttackerWire) -> core::result::Result<PublicIdentity, ciborium::de::Error<std::io::Error>> {
        let bytes = cbor(wire).unwrap();
        ciborium::from_reader(bytes.as_slice())
    }

    #[test]
    fn x25519_bit255_alias_cannot_mint_a_second_key_id() {
        // Finding 5: X25519 discards bit 255, so flipping it yields the same key under
        // a different encoding - one keypair, a second KeyId, and any count of
        // "distinct parties" (the escrow quorum above all) counts encodings instead.
        let honest = Identity::generate().unwrap();
        let mut aliased = *honest.public().wrapping();
        aliased[31] |= 0x80;
        assert_ne!(&aliased, honest.public().wrapping(), "test needs the bit to actually flip");

        let wire = AttackerWire {
            verifying: *honest.public().verifying(),
            wrapping: aliased,
        };
        assert!(decode(&wire).is_err(), "non-canonical X25519 encoding must not deserialise");
        assert!(PublicIdentity::new(*honest.public().verifying(), aliased).is_err());
    }

    #[test]
    fn x25519_field_overflow_alias_is_rejected() {
        // Values in [p, 2^255) reduce mod p: a second encoding of a smaller key. The
        // encoding of p itself aliases zero.
        let honest = Identity::generate().unwrap();
        let p_bytes: [u8; 32] = {
            let mut b = [0xffu8; 32];
            b[0] = 0xed;
            b[31] = 0x7f;
            b
        };
        assert!(PublicIdentity::new(*honest.public().verifying(), p_bytes).is_err());
    }

    #[test]
    fn noncanonical_ed25519_encoding_is_rejected_at_decode() {
        // Finding 4, encoding half: VerifyingKey::from_bytes accepts ZIP-215
        // (non-canonical) encodings and to_bytes() preserves the original bytes, so
        // without the recompression check one signing key admits multiple KeyIds.
        // p + 1 encodes y = 1 non-canonically: the identity point under different bytes.
        let honest = Identity::generate().unwrap();
        let p_plus_one: [u8; 32] = {
            let mut b = [0xffu8; 32];
            b[0] = 0xee;
            b[31] = 0x7f;
            b
        };
        let wire = AttackerWire {
            verifying: p_plus_one,
            wrapping: *honest.public().wrapping(),
        };
        assert!(decode(&wire).is_err());
        assert!(PublicIdentity::new(p_plus_one, *honest.public().wrapping()).is_err());
    }

    #[test]
    fn small_order_ed25519_key_is_rejected() {
        // A weak (small-order) verifying key can validate one signature for many
        // messages. Nobody gets to enrol one. [1, 0, ...] is the canonical encoding of
        // the identity point.
        let honest = Identity::generate().unwrap();
        let identity_point: [u8; 32] = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        assert!(PublicIdentity::new(identity_point, *honest.public().wrapping()).is_err());
    }

    #[test]
    fn honest_public_identity_roundtrips_through_serde() {
        // The validation must not reject what honest key generation produces.
        let id = Identity::generate().unwrap();
        let bytes = cbor(id.public()).unwrap();
        let back: PublicIdentity = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.key_id(), id.key_id());
        assert!(PublicIdentity::new(*id.public().verifying(), *id.public().wrapping()).is_ok());
    }

    #[test]
    fn tampering_with_stored_salt_or_params_fails_closed() {
        // REVIEW-EXTERNAL.md finding 6, AAD half: salt and params are stored in the
        // clear next to the blob, so both must be inside the authenticated envelope.
        let id = Identity::generate().unwrap();
        let sealed = id.seal("hunter2", params()).unwrap();

        let mut salted = sealed.clone();
        salted.salt[0] ^= 0x01;
        assert!(salted.unlock("hunter2").is_err());

        let mut cost_tampered = sealed.clone();
        cost_tampered.params.iterations += 1;
        assert!(cost_tampered.unlock("hunter2").is_err());
    }
}
