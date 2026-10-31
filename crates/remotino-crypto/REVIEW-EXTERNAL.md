# External adversarial review - 2026-07-21

Independent review of `remotino-crypto` at commit `07c2120`, performed by a separate model
(Fable) with no involvement in writing the code. Findings verified against the vendored
crate sources rather than from memory.

**Fifteen findings: 2 critical, 4 high, 5 medium, 4 low.** None had been found by the
author's own review (`REVIEW.md`).

---

## The theme

> The crate protects bytes well and protects *policy* not at all.

Every genuine break is in a structure **deserialised from shared storage and consumed
without authentication**. The AEAD, ECIES and chain primitives are sound. The self-review
in `REVIEW.md` examined primitives; the breaks are one level up, at the trust boundary.

---

## CRITICAL 1 - `EscrowConfig` is unauthenticated

`escrow.rs` - the struct has public fields, derives `Deserialize`, and carries no
signature, no MAC, and no binding to the audit chain. Per the threat model, **every user
can write to the shared store.**

Attack, available to any enrolled user:

1. Generate their own keypair.
2. Overwrite the stored config: `public` = their key, `shares` = one share sealed to
   themselves.
3. Every honest client that later creates or rotates a folder key runs
   `folder_key.wrap_to(&config.public)` - wrapping it to **the attacker**.
4. They read every folder key created from that moment on, including folders they were
   never granted.

This defeats the headline property - "permission is key possession" - without breaking a
single primitive.

The recovered-identity check added in the previous fix does **not** help: it compares
`recovered.public()` against `self.public`, and the attacker controls both operands. That
check defends against *share* substitution only. Its test perturbs one field of an honest
config; it says nothing about a wholesale config swap.

**Fix:** the config must be established by a signed chain entry and never read as a bare
file. Clients TOFU-pin `public` and refuse changes not accompanied by a verifying
`EscrowQuorumChanged`. Model it in the type system - a `VerifiedEscrowConfig` - so an
unvalidated config cannot reach a wrap call.

## CRITICAL 2 - `EscrowScope` is a comment that looks like a control

`EscrowScope { shared_folders: bool, personal_vaults: bool }` sits in the same
unauthenticated struct, and **no function in the crate ever reads `scope`.** `recover()`
never consults it.

Flip `personal_vaults` to `true` in the stored file and every honest client thereafter
wraps personal-vault keys to the escrow key. Chained with Critical 1, an attacker harvests
every user's personal vault - no audit entry, no UI disclosure, no error.

A two-byte edit inverts the design's central privacy promise.

**Fix:** same signing and pinning, plus enforce `scope` at the point of use. Widening
scope must require a quorum-authorised chain entry.

---

## HIGH 3 - the quorum gate counts arguments, not distinct holders

`recover(&[&admin1, &admin1, &admin1])` yields `have == 3` and satisfies any `k <= 3`.
`holders` is deduplicated nowhere, and `self.shares` is not checked for duplicate
`holder` values either.

Masked today only because `k > 1` returns `Unsupported` - but **the quorum check runs
first**, so the gate a future Shamir implementation will trust is already wrong. Combining
a share with itself is either garbage or a division by zero on `x_i - x_j == 0`: a panic,
in a crate whose lints exist to prevent exactly that.

Aggravating: `u8::try_from(present.len()).unwrap_or(u8::MAX)` **saturates upward**. A
security counter that fails open.

## HIGH 4 - signatures verified non-strictly

`identity.rs` uses `Verifier::verify`, not `verify_strict`. Confirmed against
`ed25519-dalek-3.0.0/src/verifying.rs`: the strict variant exists specifically to reject
small-order points, and the library documents that as its purpose.

Consequence is **repudiation**: with an adversarially chosen key carrying a torsion
component, one signature can validate for two different messages. Every user chooses their
own keypair, so this is an insider capability. An author can later present a different
`EntryBody` the same signature validates - "that is not what I signed" - against a log
whose stated purpose is unforgeable attribution.

Also, `VerifyingKey::from_bytes` accepts non-canonical encodings, so **one signing key
admits multiple distinct `KeyId`s** - falsifying the docstring claim that the id is a
stable function of the keys.

## HIGH 5 - X25519 public keys are not canonicalised

Confirmed in `curve25519-dalek-5.0.0`: bit 255 of the final byte is **discarded** during
field decoding, and `x25519-dalek` validates nothing on construction. Setting that bit
produces a different `KeyId` backed by the same secret - one keypair, unbounded
identities. Relevant anywhere the system counts distinct parties, which is exactly what
the escrow quorum does.

Confidentiality is not broken (the KEK binds the literal bytes); identity uniqueness is.

## HIGH 6 - KDF params unauthenticated and unbounded

The AAD covers `public` only - **`salt` and `params` are outside the authenticated
envelope**. Confirmed in `argon2-0.5.3`: `MAX_M_COST = u32::MAX`, unchecked.

- **Remote OOM:** set `memory_kib = 4_000_000_000` in a stored identity. The client
  attempts a ~4 TiB allocation and dies on every unlock. One file write, permanent
  lockout. AAD binding alone would not fix it - the AAD is checked *after* derivation runs.
- **Silent downgrade:** there is no floor either. Re-seal an identity with
  `insecure_for_tests()` (8 KiB, 1 pass) and it unlocks without complaint, reducing the
  sole defence against a stolen laptop to trivially brute-forceable.

---

## MEDIUM

7. **`seal_to` has no context label.** The same construction seals folder content keys and
   the escrow private identity. Only the downstream length check (32 vs 64) separates
   them - an accident of key sizes, not a design. It evaporates the first time anything
   else 32 bytes is sealed.
8. **`recover()` demands fully unlocked `Identity` values**, including Ed25519 signing
   keys, when only the X25519 half is needed. A `k`-of-`n` recovery therefore concentrates
   `k` admins' *signing* authority on one machine - the opposite of what the quorum exists
   to achieve, and avoidable.
9. **`share_for` returns the first match and `holder` is never cross-checked against
   `wrapped.recipient`.** Prepending a bogus share with a victim's `KeyId` permanently
   kills escrow: the real share is never tried. `is_holder` can likewise be made to return
   an attacker-chosen answer.
10. **`shares.len()` is never reconciled with `n`, and `index` is unvalidated** - including
    `index = 0`, which in Shamir is the evaluation point where the polynomial equals the
    secret itself. The format is treated as frozen; constraining it now is free.
11. **The reference `MemoryRepo` pins a contract with no validation** - `append` never
    checks seq contiguity, links or signatures, and `read_from` never sorts by `seq`. A
    `SqlRepo` written to this specification inherits the gap.

## LOW

12. `Digest::of` has no domain separation, breaking the crate's own convention at the one
    place it protects the chain.
13. Unzeroized stack copies of secret material in three places; `Identity` has no explicit
    `ZeroizeOnDrop`.
14. `KdfParams::insecure_for_tests` is `pub` - `#[doc(hidden)]` hides it from docs, not
    from the API.
15. `verify_chain` returns `Ok(None)` on an empty slice, which reads as success.

---

## Confirmed correct

Stated deliberately, because a clean result on a specific mechanism is information:

- **Actor-to-signer binding**, both directions - `sign` refuses a foreign actor, `verify`
  recomputes the id rather than trusting a field
- **`open_sealed` derives the KEK from the identity's own key, not the attacker-supplied
  `recipient` field.** This is what gives `redirected_wrap_is_rejected` real content. It
  looks redundant, and a well-meaning refactor that "used the field we already have" would
  silently reintroduce a confused deputy. Deserves a comment saying so.
- **Nonce handling** - fresh 24-byte random per seal; XChaCha's 192-bit nonce makes this
  safe without cross-machine counter coordination
- **Fresh ephemeral per seal**, and the unlinkability property is real
- **`fill_random` fails closed**
- **Error coarseness** genuinely denies an oracle, and is applied consistently
- **The `seq`/`prev` walk**, including overflow handling and the genesis constraint

---

## The meta-lesson

> For every structure deserialised from shared storage, write at least one test that
> builds the whole structure **adversarially from scratch**, rather than mutating an
> honest one.

Findings 1, 2, 9 and 10 would all have surfaced from that single rule.

Every existing adversarial test constructs its attacker by taking
`EscrowConfig::create_sole` output and perturbing one field. None construct a config the
way an attacker actually would - by writing the file from nothing. That is the same
failure shape `REVIEW.md` identified in the escrow tests, one level up, and the author's
own review did not catch it either.
