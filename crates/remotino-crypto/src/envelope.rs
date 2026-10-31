//! Envelope encryption: content keys, and wrapping them to recipients.
//!
//! This module implements the property that makes access control real (`DESIGN.md` 4):
//!
//! > With a shared file backend everyone can read every byte, so permission cannot be
//! > enforced by the application - only by key possession.
//!
//! Each folder has a random [`ContentKey`]. Granting access to a user means wrapping that
//! key to their X25519 public key. Revoking means rotating the content key and re-wrapping
//! for whoever remains - which is why revocation is forward-only: anyone who cached the
//! old key keeps what they already read.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::identity::{Identity, PublicIdentity};
use crate::{Error, Result};

/// Length of a content key.
pub const CONTENT_KEY_LEN: usize = 32;

/// Length of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;

/// Context label for wrapping a folder [`ContentKey`] to a recipient.
///
/// # Why seals carry a context label at all
///
/// The same ECIES construction seals both 32-byte content keys and the 64-byte escrow
/// secret. Without a label, the only thing separating those domains was the plaintext
/// length check downstream - an accident of key sizes, not a design, and one that
/// evaporates the first time anything else 32 bytes long is sealed
/// (REVIEW-EXTERNAL.md finding 7). The label is mixed into the KEK derivation, so a
/// blob sealed under one context simply fails to decrypt under another.
pub const CONTEXT_CONTENT_KEY: &[u8] = b"remotino/v1/wrap/content-key";

/// Context label for sealing an escrow share to its holder. See
/// [`CONTEXT_CONTENT_KEY`] for why labels exist.
pub const CONTEXT_ESCROW_SHARE: &[u8] = b"remotino/v1/wrap/escrow-share";

/// Context label for sealing a user's SQL Server login password to their identity.
///
/// The SQL backend seals a per-user database password to the user's wrapping key so the
/// passphrase unlocks the database connection without the user ever seeing a credential
/// (`DESIGN.md` 3). A distinct label keeps such a blob from being interchangeable with a
/// content-key or escrow-share wrap - the same defence [`CONTEXT_CONTENT_KEY`] documents.
pub const CONTEXT_SQL_PASSWORD: &[u8] = b"remotino/v1/wrap/sql-password";

/// The key-agreement suite in force for a repository.
///
/// Recorded per-repository rather than compiled in, so the suite can change without a
/// format break - the algorithm agility argued for in `DESIGN.md` 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Suite {
    /// X25519 key agreement, XChaCha20-Poly1305 content encryption.
    #[default]
    X25519,
    /// Reserved: X25519 + ML-KEM-768 hybrid, for post-quantum resistance.
    ///
    /// Not implemented. Present so the discriminant is allocated now and adding it later
    /// is not a format change. `DESIGN.md` 4 explains why this, rather than a larger RSA
    /// key, is the right dial for future-proofing.
    X25519MlKem768,
}

/// A symmetric key protecting one folder's contents. Zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentKey([u8; CONTENT_KEY_LEN]);

impl core::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ContentKey(<redacted>)")
    }
}

impl ContentKey {
    /// Generates a fresh random content key.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the OS random source is unavailable.
    pub fn generate() -> Result<Self> {
        let mut k = [0u8; CONTENT_KEY_LEN];
        fill_random(&mut k)?;
        Ok(Self(k))
    }

    /// Encrypts `plaintext`, binding `aad` into the authentication tag.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] if the AEAD refuses (in practice only on absurd input sizes).
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedBlob> {
        seal_with_key(&self.0, plaintext, aad)
    }

    /// Decrypts a blob produced by [`ContentKey::seal`] with the same `aad`.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] on a wrong key, wrong aad, or tampered ciphertext.
    pub fn open(&self, blob: &SealedBlob, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open_with_key(&self.0, blob, aad)
    }

    /// Wraps this content key to a recipient's public identity.
    ///
    /// # Errors
    ///
    /// Propagates randomness and AEAD failures.
    pub fn wrap_to(&self, recipient: &PublicIdentity) -> Result<WrappedKey> {
        seal_to(recipient, &self.0, CONTEXT_CONTENT_KEY)
    }

    /// Unwraps a content key addressed to `identity`.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for an unimplemented suite, [`Error::Decrypt`] if the wrap
    /// was not addressed to this identity or has been tampered with,
    /// [`Error::Malformed`] if the recovered material is not a content key.
    pub fn unwrap_for(wrapped: &WrappedKey, identity: &Identity) -> Result<Self> {
        let plaintext = open_sealed(wrapped, identity, CONTEXT_CONTENT_KEY)?;
        let bytes: [u8; CONTENT_KEY_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed("wrapped key wrong length"))?;
        Ok(Self(bytes))
    }
}

/// Seals arbitrary bytes to a recipient's public identity (ephemeral-static ECIES).
///
/// Generalised from content-key wrapping because escrow must seal a full keypair's secret
/// material, not a 32-byte symmetric key. Keeping one implementation matters: the earlier
/// escrow bug came from a second, divergent path that only appeared to do the same thing.
///
/// `context` separates the domains that share this implementation - see
/// [`CONTEXT_CONTENT_KEY`]. Callers must pass a fixed, crate-defined label; a blob can
/// only be opened under the same label it was sealed with.
///
/// # Errors
///
/// Propagates randomness and AEAD failures.
pub fn seal_to(recipient: &PublicIdentity, plaintext: &[u8], context: &[u8]) -> Result<WrappedKey> {
    // A fresh ephemeral key per seal means the same plaintext sealed twice produces
    // unlinkable outputs.
    let mut eph_bytes = Zeroizing::new([0u8; 32]);
    fill_random(eph_bytes.as_mut())?;
    let eph_secret = X25519Secret::from(*eph_bytes);
    let eph_public = X25519Public::from(&eph_secret);

    let shared = eph_secret.diffie_hellman(&recipient.wrapping_public());
    reject_degenerate(shared.as_bytes())?;
    let kek = derive_kek(
        shared.as_bytes(),
        eph_public.as_bytes(),
        &recipient.wrapping,
        context,
    )?;

    // The recipient is bound as AAD so a seal cannot be replayed at a different user.
    let blob = seal_with_key(&kek, plaintext, &recipient.wrapping)?;

    Ok(WrappedKey {
        suite: Suite::X25519,
        ephemeral: eph_public.to_bytes(),
        recipient: recipient.wrapping,
        blob,
    })
}

/// Opens bytes sealed by [`seal_to`], addressed to `identity`, under the same `context`.
///
/// # Errors
///
/// [`Error::Unsupported`] for an unimplemented suite, [`Error::Decrypt`] if the seal was
/// not addressed to this identity, was sealed under a different context, or has been
/// tampered with.
pub fn open_sealed(
    wrapped: &WrappedKey,
    identity: &Identity,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if wrapped.suite != Suite::X25519 {
        return Err(Error::Unsupported("key agreement suite"));
    }
    let eph_public = X25519Public::from(wrapped.ephemeral);
    // The KEK is derived from *this identity's own* wrapping key, deliberately not from
    // the attacker-controllable `wrapped.recipient` field. That field is a routing hint
    // only. Using it here would reintroduce a confused deputy: a wrap relabelled with
    // someone else's key would derive their KEK. This is what gives the
    // `redirected_wrap_is_rejected` test real content - a well-meaning refactor that
    // "used the field we already have" would silently reopen the hole.
    let shared = identity.wrapping_secret().diffie_hellman(&eph_public);
    reject_degenerate(shared.as_bytes())?;
    let kek = derive_kek(
        shared.as_bytes(),
        &wrapped.ephemeral,
        &identity.public().wrapping,
        context,
    )?;
    open_with_key(&kek, &wrapped.blob, &identity.public().wrapping)
}

/// Rejects an all-zero X25519 shared secret.
///
/// Produced by a low-order point, where the "shared" secret is a constant an attacker
/// knows. Cheap insurance; `x25519-dalek` does not reject these itself.
fn reject_degenerate(shared: &[u8; 32]) -> Result<()> {
    use subtle::ConstantTimeEq as _;
    if bool::from(shared.ct_eq(&[0u8; 32])) {
        return Err(Error::Malformed("degenerate X25519 shared secret"));
    }
    Ok(())
}

/// A content key sealed to one recipient's public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Suite used to produce this wrap.
    pub suite: Suite,
    /// Ephemeral X25519 public key for this wrap.
    pub ephemeral: [u8; 32],
    /// Recipient's X25519 public key, so a client can find its own wrap without trying
    /// every one.
    pub recipient: [u8; 32],
    /// The wrapped key material.
    pub blob: SealedBlob,
}

/// Ciphertext plus the nonce it was produced under.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    /// XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with appended authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Derives a key-encryption key from an X25519 shared secret, per RFC 5869
/// (HKDF-SHA256, Extract-then-Expand):
///
/// ```text
/// salt = "remotino/v1/kek"
/// ikm  = shared secret (raw DH output)
/// info = len(context) || context || ephemeral_pk || recipient_pk
/// kek  = HKDF-Expand(HKDF-Extract(salt, ikm), info, 32)
/// ```
///
/// The ephemeral and recipient public keys are bound in via `info` so the derived key
/// is tied to this specific exchange - without that, a shared secret reused in another
/// context would produce the same KEK. The context label is length-prefixed so
/// distinct labels can never produce colliding `info` streams, and it separates the
/// plaintext domains that share this ECIES path (content keys vs escrow shares).
///
/// # Why HKDF rather than a single domain-separated SHA-256
///
/// An earlier version computed `SHA-256(domain || len(ctx) || ctx || shared || eph ||
/// recipient)`. That construction was sound - all inputs fixed-length or
/// length-prefixed, domain-separated, one 32-byte output - and no attack against it is
/// known. HKDF is used **for reviewability, not because the hash was weak**: it is the
/// standard extract-then-expand KDF (the same shape HPKE, RFC 9180, uses after a DH),
/// it carries security proofs the ad-hoc hash does not, and an external reviewer can
/// sign it off by citation instead of by argument. The switch was made pre-release,
/// where the format break costs nothing; see REVIEW.md.
///
/// # Errors
///
/// [`Error::Malformed`] if HKDF-Expand refuses the output length - statically
/// impossible for 32 bytes (the limit is 255 * 32), kept as an error rather than a
/// panic because this crate does not panic on any path.
fn derive_kek(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
    context: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"remotino/v1/kek"), shared);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(
        &[
            // usize -> u64 is lossless on every supported platform.
            &(context.len() as u64).to_le_bytes(),
            context,
            ephemeral,
            recipient,
        ],
        kek.as_mut(),
    )
    .map_err(|_| Error::Malformed("hkdf output length"))?;
    Ok(kek)
}

pub(crate) fn seal_with_key(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<SealedBlob> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Decrypt)?;
    Ok(SealedBlob { nonce, ciphertext })
}

pub(crate) fn open_with_key(
    key: &[u8; 32],
    blob: &SealedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            &XNonce::from(blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

/// Fills `buf` from the OS random source.
///
/// # Errors
///
/// [`Error::Malformed`] if the OS source is unavailable - which is fatal, so callers
/// should not attempt to continue with weaker randomness.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    // `getrandom` rather than a userspace RNG: no seeding to get wrong, no state to fork
    // across a process boundary, and it fails loudly instead of degrading.
    getrandom::fill(buf).map_err(|_| Error::Malformed("OS random source unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrips() {
        let key = ContentKey::generate().unwrap();
        let blob = key.seal(b"secret entry", b"folder-42").unwrap();
        let out = key.open(&blob, b"folder-42").unwrap();
        assert_eq!(out.as_slice(), b"secret entry");
    }

    #[test]
    fn wrong_aad_fails() {
        // AAD binds ciphertext to its context; without this, a blob could be moved to a
        // different folder and still decrypt.
        let key = ContentKey::generate().unwrap();
        let blob = key.seal(b"secret", b"folder-42").unwrap();
        assert!(matches!(key.open(&blob, b"folder-43"), Err(Error::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = ContentKey::generate().unwrap();
        let mut blob = key.seal(b"secret", b"aad").unwrap();
        if let Some(b) = blob.ciphertext.first_mut() {
            *b ^= 0x01;
        }
        assert!(matches!(key.open(&blob, b"aad"), Err(Error::Decrypt)));
    }

    #[test]
    fn wrap_unwrap_roundtrips() {
        let alice = Identity::generate().unwrap();
        let key = ContentKey::generate().unwrap();
        let wrapped = key.wrap_to(alice.public()).unwrap();
        let unwrapped = ContentKey::unwrap_for(&wrapped, &alice).unwrap();

        let blob = key.seal(b"payload", b"").unwrap();
        assert_eq!(unwrapped.open(&blob, b"").unwrap().as_slice(), b"payload");
    }

    #[test]
    fn other_user_cannot_unwrap() {
        // This is the whole access-control model in one assertion: not being granted
        // means being cryptographically unable, not merely being told no.
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let key = ContentKey::generate().unwrap();
        let wrapped = key.wrap_to(alice.public()).unwrap();
        assert!(ContentKey::unwrap_for(&wrapped, &mallory).is_err());
    }

    #[test]
    fn wraps_are_unlinkable() {
        // Fresh ephemeral per wrap: the same key wrapped twice must not produce equal
        // ciphertext, or an observer could tell that two folders share a key.
        let alice = Identity::generate().unwrap();
        let key = ContentKey::generate().unwrap();
        let a = key.wrap_to(alice.public()).unwrap();
        let b = key.wrap_to(alice.public()).unwrap();
        assert_ne!(a.ephemeral, b.ephemeral);
        assert_ne!(a.blob.ciphertext, b.blob.ciphertext);
    }

    #[test]
    fn nonces_do_not_repeat() {
        let key = ContentKey::generate().unwrap();
        let a = key.seal(b"x", b"").unwrap();
        let b = key.seal(b"x", b"").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn escrow_share_cannot_be_opened_as_a_content_key() {
        // REVIEW-EXTERNAL.md finding 7. Before context labels, the only separation
        // between "sealed content key" and "sealed escrow secret" was a downstream
        // length check - an accident of key sizes. Here both plaintexts are 32 bytes,
        // so only the label separates them, which is the point.
        let alice = Identity::generate().unwrap();
        let wrapped = seal_to(alice.public(), &[7u8; 32], CONTEXT_ESCROW_SHARE).unwrap();

        // Same recipient, same length - wrong domain. Must fail.
        assert!(ContentKey::unwrap_for(&wrapped, &alice).is_err());
        assert!(matches!(
            open_sealed(&wrapped, &alice, CONTEXT_CONTENT_KEY),
            Err(Error::Decrypt)
        ));
        // The honest path still works.
        assert!(open_sealed(&wrapped, &alice, CONTEXT_ESCROW_SHARE).is_ok());
    }

    #[test]
    fn kek_derivation_matches_the_pinned_vector() {
        // Pins the KDF wire format: HKDF-SHA256 with salt = "remotino/v1/kek",
        // ikm = shared secret, info = len(context) || context || ephemeral ||
        // recipient. If this fails, the derivation changed and every wrap in every
        // existing store silently stops opening - that must be a deliberate versioned
        // decision, never a refactoring accident. Vector cross-checked against an
        // independent RFC 5869 implementation (Python hmac/hashlib:
        // PRK = HMAC(salt, ikm); OKM = HMAC(PRK, info || 0x01)) at the switch to
        // HKDF (REVIEW.md) - both produced this value.
        let kek = derive_kek(&[0x01; 32], &[0x02; 32], &[0x03; 32], CONTEXT_CONTENT_KEY)
            .unwrap();
        assert_eq!(
            hex::encode(kek.as_ref()),
            "b6eea7579f789fbd6b822f4c06d63bc7ef2aa7e83b36445c05a6c7f54667076c"
        );
    }

    #[test]
    fn redirected_wrap_is_rejected() {
        // Recipient is bound as AAD, so relabelling a wrap for someone else fails rather
        // than silently producing garbage.
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let key = ContentKey::generate().unwrap();
        let mut wrapped = key.wrap_to(alice.public()).unwrap();
        wrapped.recipient = mallory.public().wrapping;
        assert!(ContentKey::unwrap_for(&wrapped, &mallory).is_err());
    }
}
