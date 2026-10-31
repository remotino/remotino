# Crypto core review - 2026-07-21

Self-review of `remotino-crypto` at commit `1223e22`. Two serious bugs found, both fixed
in the following commit. Recorded because *how* they survived 39 passing tests is more
instructive than the bugs themselves.

---

## Finding 1 - `KeyId` did not bind the signing key (critical)

### The defect

```rust
// identity.rs, before
if let (Some(a), Some(b)) = (buf.get_mut(..32), None::<&mut [u8]>) {
    a.copy_from_slice(&self.verifying);
    let _ = b;
}
```

The second tuple element is the literal `None`, so **the pattern can never match** and the
verifying key was never copied. `buf[..32]` stayed zero, making

```
KeyId = SHA-256( 0x00 * 32 || wrapping_key )
```

The identity's signing key was not part of its own identifier.

Demonstrated: two identities differing only in verifying key produced byte-identical ids.

### Why it matters

`Entry::verify` rejects impersonation by comparing `author.key_id()` to `body.actor`. With
the signing key unbound, an attacker who can place a crafted `PublicIdentity` into the
directory - same wrapping key as the victim, their **own** verifying key - produces a
matching `KeyId`. The actor check passes, and their signature then verifies.

That is audit-log impersonation: entries attributable to a user they do not control. The
chain would verify perfectly.

### Why it was written

Clippy's `indexing_slicing` is denied workspace-wide, so `buf[..32]` was unavailable. The
replacement was contorted, and the contortion hid a logic error. **A lint pushed the code
into a shape where a bug could hide** - worth remembering: when avoiding a lint produces
something hard to read, that is a signal to restructure, not to be clever.

### Fix

Hash directly, no buffer, no slicing, plus domain separation:

```rust
let mut hasher = Sha256::new();
hasher.update(b"remotino/v1/keyid");
hasher.update(&self.verifying);
hasher.update(&self.wrapping);
```

---

## Finding 2 - escrow recovery recovered the wrong key (critical)

### The defect

```rust
// escrow.rs, before
let escrow_identity = Identity::generate()?;      // the real escrow keypair
let secret = ContentKey::generate()?;             // an UNRELATED random key
let wrapped = secret.wrap_to(holder)?;            // ...and this is what was stored
```

The share held a random key with no relationship to the escrow keypair. Content keys are
wrapped to `escrow_identity.public()`, so the recovered material could not unwrap
anything.

Worse, the escrow **private key was returned to the caller** and never sealed anywhere -
despite the doc comment stating it was "generated, sealed to `holder`, and dropped". If a
caller dropped it, escrow became permanently unusable; if they stored it, it was
unprotected.

Escrow was non-functional in both directions.

### Why the tests missed it

This is the part worth internalising. The tests asserted:

- `recover()` returns `Ok` for a holder
- `recover()` returns `QuorumNotMet` for a non-holder

Both passed. Neither asked the only question that matters: **can the recovered material
actually decrypt something?** The tests verified *plumbing* - that calls succeeded and
errors fired - rather than the *security property* the module exists to provide.

A test of the form "wrap a content key to the escrow public key, recover, and unwrap it"
would have failed immediately.

### Fix

- Generalised `envelope` to seal arbitrary bytes to a recipient (`seal_to` / `open_sealed`),
  with `ContentKey::wrap_to` reimplemented on top so there is one ECIES path, not two
- The share now contains the escrow identity's actual secret material
- `recover()` returns an `Identity` - the thing that can unwrap - not a bare key
- Added the round-trip test that should have existed from the start

---

## Systemic lesson

Both bugs passed 39 tests and a clippy run with `unwrap`, `panic`, indexing and arithmetic
overflow all denied. Strict lints and high test counts measured the wrong things.

The tests were written from the implementation outward - "does this function return what I
expect" - rather than from the threat model inward - "can an attacker do X". The second
kind is what a crypto test suite is for.

Concretely, the tests now added are:

| Test | Attack it forecloses |
|---|---|
| `key_id_binds_both_keys` | Substituting a signing key while keeping the id |
| `forged_identity_cannot_impersonate_in_chain` | Audit-log impersonation end to end |
| `escrow_recovers_a_usable_key` | Escrow that reports success but recovers nothing |
| `escrow_recovered_identity_unwraps_content_keys` | The actual business purpose of escrow |

---

## Previously outstanding - all resolved 2026-07-21

The four items below were open at the time of the self-review. All are now closed;
each entry records what was decided and why.

### CBOR is not canonical (medium) - RESOLVED

**Decision: enforce canonical encoding on decode and reject non-canonical input** -
the fail-closed option - rather than hashing received bytes and carrying them
alongside the parsed form.

How it is made unavoidable, not merely available: `Entry` and `SignedEscrowConfig` no
longer implement `Deserialize` at all. The only path from stored bytes to a value is
`Entry::from_bytes` / `SignedEscrowConfig::from_bytes`, which decode via a private
wire struct, re-encode, and reject any input that is not byte-identical to the
canonical encoding of what it decoded to (the same funnel-through-a-validating-
constructor pattern `PublicIdentity` uses). Structs and canonical bytes are thereby
one-to-one, so digests are injective over stored bytes.

The storage contract this settles for `SqlRepo` (documented on the `Repository`
trait and in `CRYPTO.md` 8): store `Entry::to_bytes` verbatim in the `body` column,
decode with `Entry::from_bytes`; nothing else will decode. Storing structs and
re-encoding on read (`MemoryRepo`) is equally sound because of the bijection. There
is no way to write a backend that skips the check, because the permissive decode
does not exist.

Tests build the aliases from raw bytes up, per the adversarial-construction rule:
`reordered_map_keys_cannot_mint_a_second_encoding_of_an_entry` (also demonstrates
the digest collision a permissive decode would have allowed),
`nonminimal_integer_encoding_of_an_entry_is_rejected`,
`indefinite_length_encoding_of_an_entry_is_rejected`,
`trailing_bytes_after_an_entry_are_rejected`,
`noncanonical_encoding_of_a_stored_escrow_config_is_rejected`.

### `Head::check_advance` does not detect forks (medium) - RESOLVED

**Decision: it cannot be made sound with the information it has, so it was renamed to
say exactly what it checks.** Two `(seq, digest)` pairs alone cannot distinguish a
fork that outruns the pin from honest progress - descent is a property of the entries
in between, and the sound check over those entries already exists:
`verify_chain(new_entries, Some(pinned_head), ..)`.

`check_advance` is now `Head::check_not_rewound`. The name no longer implies the head
validly advanced; its docs state the fork gap explicitly, and `verify_chain`'s docs
name continuation-from-a-pin as the fork check. The intended pattern is documented as:
poll cheaply with `check_not_rewound`, and never re-pin a head that did not come out
of `verify_chain`.

Test:
`fork_with_higher_seq_is_invisible_to_head_comparison_but_caught_by_verify_chain` -
it asserts the cheap check passes on the fork (the documented gap, not a tolerated
bug) and that `verify_chain` from the pin breaks on the first divergent link.

### `derive_kek` uses raw SHA-256 rather than HKDF (low) - RESOLVED

**Decision: switched to HKDF-SHA256 (RFC 5869), explicitly for reviewability, not
security.** Judgement recorded plainly: the previous single domain-separated SHA-256
over fixed-length-or-length-prefixed inputs was sound, and no attack against it is
known; modelling SHA-256 as a random oracle, the two constructions are
security-equivalent here (one 32-byte output, fixed protocol). HKDF does not
materially heighten security in this setting.

It was implemented anyway because reviewability alone justifies it *in this specific
project*: an independent cryptographer review is a hard gate before Phase 2, HKDF is
the standard post-DH KDF (the shape HPKE uses) and can be signed off by citation
rather than argument, and the change is free now (pre-release) and a format break
forever after. Layout: salt = `"remotino/v1/kek"`, IKM = the X25519 shared secret,
info = `len(context) || context || ephemeral_pk || recipient_pk`.

The format is pinned by `kek_derivation_matches_the_pinned_vector`, whose vector was
cross-checked against an independent RFC 5869 implementation.

### X25519 low-order points not rejected (low) - RESOLVED

Addressed during the external-review fixes: `reject_degenerate` refuses an all-zero
shared secret (constant-time compare) on both the seal and open paths in
`envelope.rs`.

### Still unaddressed

**No independent review by a cryptographer.** This document is a self-review by the author
of the code, which catches implementation errors but is structurally poor at catching
design errors. `DESIGN.md` 7 still applies.
