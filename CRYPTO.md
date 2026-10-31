# Remotino cryptography

How the crypto core actually works, why each choice was made, and what it does *not*
protect. Describes `crates/remotino-crypto` as implemented, not as sketched.

Companion to `DESIGN.md` sections 4, 5, 8.4 and 9.4a. Where they disagree, the code and
this document are correct.

---

## 1. What we are defending, and against whom

The backend is shared storage. Whether that is an SMB share or a SQL Server database,
**every user with access can read every byte**. That single fact drives the entire design.

It follows that an access-control list the application checks is decorative: anyone can
bypass the application and read the store directly. So:

> **Permission is key possession.** A user can read a folder if, and only if, that
> folder's content key was wrapped to their public key. There is no application check to
> bypass, because there is no application check.

### Defended

| Threat | Defence |
|---|---|
| Attacker reads the whole store | Everything except the folder graph shape is encrypted |
| User reads a folder they were not granted | They lack the key. No code path exists to grant it to them |
| Someone edits audit history | Hash chain breaks at the edited entry and every one after |
| Someone forges an audit entry | Requires a private key they do not have |
| Laptop stolen | Private keys sealed under Argon2id; useless without the passphrase |
| A wrap is relabelled for another user | Recipient bound as AAD; decryption fails |
| A sealed identity is paired with foreign public keys | Public half bound as AAD, plus an explicit post-unlock check |
| The escrow config is swapped for an attacker's | Config is signed by an admin; unverified configs are unusable by type (section 7) |
| Escrow scope silently widened to personal vaults | Scope inside the signed envelope, enforced at the only wrap path (section 7) |
| Stored KDF params edited (OOM bomb or downgrade) | Policy window checked before derivation; salt and params bound as AAD (section 4) |
| One keypair minting several identities via encoding tricks | Canonical encodings enforced at every `PublicIdentity` construction (section 4) |
| Two byte-distinct stored entries sharing one digest | Non-canonical CBOR rejected at every decode path (section 8) |

### Not defended

| Threat | Why not |
|---|---|
| Compromised client while unlocked | Keys are in RAM by necessity |
| A user re-sharing what they were legitimately granted | Cryptography cannot prevent copying |
| Revocation of already-cached secrets | Forward-only; see section 6 |
| Metadata: entry counts, sizes, timing | Visible to anyone reading the store |
| **Truncation of the audit log** | A hash chain detects mutation, not deletion. See section 8 |

Stating the second table matters as much as the first. A security design that only
advertises its wins teaches its users to trust it in situations where it does not hold.

---

## 2. Primitives

| Purpose | Primitive | Why this one |
|---|---|---|
| Signing | **Ed25519** | 64-byte signatures, microsecond signing. Every audit entry is signed, so this is a hot path |
| Key agreement | **X25519** | Small keys, constant-time, no parameter choices to get wrong |
| Content encryption | **XChaCha20-Poly1305** | 192-bit nonce, so random nonces are safe with no counter to coordinate between machines |
| Passphrase KDF | **Argon2id** | Memory-hard; the only barrier between a stolen laptop and the vault |
| Wrap KDF | **HKDF-SHA256** | Derives the KEK from the X25519 shared secret (RFC 5869; see section 5) |
| Hashing | **SHA-256** | Chain links and key ids |

### Why not RSA-8192

The original requirement was 8192-bit RSA. It was not adopted, for three reasons:

1. **It is slow exactly where it hurts.** RSA-7680 keygen benchmarks around 43 seconds.
   Every audit entry is signed, and RSA-4096 signing is roughly 2000x slower than Ed25519
   with ~1 KB signatures. That builds the very slowness the project exists to escape into
   the write path.
2. **It buys no future-proofing.** RSA-8192 and RSA-2048 both fall to Shor's algorithm.
   If the goal is resisting future attack, key size is the wrong dial - the right one is a
   post-quantum hybrid, which is why `Suite::X25519MlKem768` is reserved.
3. **Classically, 4096 is already beyond any projected attack.** The 4096 -> 8192 gap is
   not an improvement anyone can operationalise.

The suite is nonetheless recorded per repository (`Suite`), so changing it later is a
policy change rather than a format break.

---

## 3. The key hierarchy

```
                        passphrase (only thing a human knows)
                             |
                             |  Argon2id (256 MiB, t=3, p=4, per-identity salt)
                             v
                     +---------------+
                     |  derived key  |   32 bytes, never stored
                     +---------------+
                             |
                             |  XChaCha20-Poly1305, AAD = public identity + salt + params
                             v
        +--------------------------------------------+
        |            SealedIdentity (at rest)        |
        |  public: verifying(32) + wrapping(32)      |  <- cleartext
        |  salt, kdf params                          |  <- cleartext
        |  blob: seal(signing(32) || wrapping(32))   |  <- encrypted
        +--------------------------------------------+
                             |
                             |  unlock
                             v
              +--------------------------------+
              |  Identity (in memory only)     |
              |                                |
              |  Ed25519 signing key ----------+---> signs audit entries
              |  X25519 wrapping key ----------+---> unwraps content keys
              +--------------------------------+
                                                     |
                                                     v
                             +-----------------------------------------+
                             |  ContentKey  (one per folder)           |
                             |  32 random bytes                        |
                             +-----------------------------------------+
                                        |                    |
                        seals entries   |                    |  wrapped to each
                        in that folder  |                    |  granted user
                                        v                    v
                               +---------------+    +------------------+
                               |  SealedBlob   |    |   WrappedKey[]   |
                               +---------------+    +------------------+
```

Two keys per identity, not one, because the roles differ. The signing key attributes audit
entries; the wrapping key receives content keys. Keeping them separate means **a signing
key can be rotated without re-wrapping every folder key in the repository**.

---

## 4. Identity

### Generation

```
32 random bytes ---> Ed25519 signing key ---> verifying key (public)
32 random bytes ---> X25519 static secret ---> wrapping public key

KeyId = SHA-256( verifying || wrapping )
```

The id is *derived*, not random, so two parties holding the same public keys always
compute the same id and a mismatch is detectable.

### The id is one-to-one because encodings are canonical

Both curves accept several byte encodings of the same key: Ed25519 point decoding
tolerates non-canonical y-coordinates (ZIP-215), and X25519 discards bit 255 and
reduces mod p. Since `KeyId` hashes bytes, an unchecked encoding would let one keypair
mint several distinct "identities" - and anything that counts distinct parties (the
escrow quorum above all) would be counting encodings, not people.

So `PublicIdentity` validates on every construction path, deserialisation included:
non-canonical encodings of either key are rejected, as are small-order Ed25519 keys.
Tests: `x25519_bit255_alias_cannot_mint_a_second_key_id`,
`noncanonical_ed25519_encoding_is_rejected_at_decode`.

Signature checks use `verify_strict`, which additionally rejects small-order components
and non-canonical `R` - without it, an insider with an adversarially chosen key could
produce one signature valid for two messages and later repudiate an audit entry.

### Sealing at rest

```
salt        <- 16 random bytes
derived     <- Argon2id(passphrase, salt, params)     (params checked against the policy window first)
plaintext   <- signing_secret(32) || wrapping_secret(32)
aad         <- "remotino/v1/sealed-identity" || CBOR((public, salt, params))
blob        <- XChaCha20-Poly1305(derived, plaintext, aad)
```

**Why the public half is AAD.** Without it, an attacker could take your sealed blob,
attach their own public keys, and hand it back. Binding the public half means such a file
fails to decrypt. The code additionally re-derives the public keys after unlocking and
compares - belt and braces, because silently adopting a confused identity would be far
worse than an error. Test: `swapping_the_public_half_is_rejected`.

**Why salt and params are AAD too.** They are stored in the clear next to the blob;
anything stored in the clear is attacker-writable and must be inside the authenticated
envelope. Test: `tampering_with_stored_salt_or_params_fails_closed`.

**Why KDF parameters are stored, not hardcoded.** Cost should rise as hardware improves.
If parameters were implicit, raising them would strand every existing sealed key. Stored
alongside each object, an old key still opens with its old parameters and can be re-sealed
with new ones.

**And why they are bounded anyway.** Stored parameters are read back from shared
storage, so `derive` refuses anything outside a policy window (19 MiB..2 GiB, 2..16
passes, <=16 lanes). The ceiling stops a hostile store from demanding a multi-terabyte
allocation that kills every client at unlock - the AAD check cannot help there, because
the allocation happens *before* authentication. The floor stops a re-sealed identity
from being silently downgraded to brute-forceable cost. Tests:
`hostile_memory_cost_cannot_reach_allocation`,
`downgraded_params_are_refused_not_silently_accepted`.

### Unlock is the login

There is no separate account system. Unlocking the identity *is* authentication - a wrong
passphrase yields `Error::Decrypt`, indistinguishable from a tampered blob. That
indistinguishability is deliberate: distinguishing them hands an attacker an oracle.

---

## 5. Envelope encryption

Each folder has one random `ContentKey`. Entries in the folder are sealed under it. The
content key is then wrapped separately to each granted user.

### Wrapping (ephemeral-static ECIES)

```
  sender                                             recipient
  ------                                             ---------
  eph_sk <- 32 random bytes
  eph_pk  = X25519(eph_sk)
                                                     recipient_pk (published)
  shared  = X25519(eph_sk, recipient_pk)  ==========  X25519(recipient_sk, eph_pk)
                                          (same value, never transmitted)

  kek = HKDF-SHA256( salt = "remotino/v1/kek",
                     ikm  = shared,
                     info = len(context) || context || eph_pk || recipient_pk )   (RFC 5869)

  WrappedKey {
      suite:     X25519
      ephemeral: eph_pk            <- needed by the recipient to redo the agreement
      recipient: recipient_pk      <- routing hint only; never used for key derivation
      blob:      AEAD(kek, content_key, aad = recipient_pk)
  }
```

Four details that are easy to get wrong:

- **A fresh ephemeral key per wrap.** The same content key wrapped twice produces
  unlinkable ciphertext. Without this, an observer could tell that two folders share a key.
  Test: `wraps_are_unlinkable`.
- **The KEK is bound to the exchange.** Both public keys are fed into the HKDF `info`
  alongside a domain-separating salt, so a shared secret reused in another context
  cannot produce the same KEK.
- **Why HKDF and not a plain domain-separated hash.** An earlier version derived the
  KEK as one SHA-256 over the same inputs. That construction was sound and no attack
  against it is known; the switch to HKDF was made **for reviewability, not
  security** - extract-then-expand is the standard KDF after a DH (the same shape
  HPKE uses), carries proofs the ad-hoc hash does not, and lets an external reviewer
  sign off by citation. Done pre-release, where the format break costs nothing. A
  pinned test vector (`kek_derivation_matches_the_pinned_vector`, cross-checked
  against an independent RFC 5869 implementation) guards the format from silent
  drift.
- **The KEK is bound to a context label.** The same ECIES path seals both content keys
  and escrow shares; before labels, only a length accident separated those domains. A
  blob sealed as one kind cannot open as the other.
  Test: `escrow_share_cannot_be_opened_as_a_content_key`.
- **The recipient is bound as AAD, and never trusted for derivation.** Relabelling a wrap
  for a different user fails rather than silently producing garbage - the opener derives
  the KEK from its *own* key, not the attacker-writable `recipient` field.
  Test: `redirected_wrap_is_rejected`.

### This is the access-control model, entire

```rust
// From envelope.rs tests - the whole authorisation model in one assertion.
let wrapped = key.wrap_to(alice.public())?;
assert!(ContentKey::unwrap_for(&wrapped, &mallory).is_err());
```

Mallory is not *told no*. Mallory is *unable*. There is no flag to flip, no check to
patch out, and a compromised client cannot escalate.

---

## 6. Granting and revoking

### Grant

```
   Folder "Production"                 Grant to Bob
   contentkey K                        ------------
        |                              wrap K to bob_pk
        +--> WrappedKey -> Alice           |
        +--> WrappedKey -> Carol           +--> WrappedKey -> Bob   (appended)
```

Cheap: one wrap, one appended audit entry. No re-encryption of any entry.

### Revoke - and why it is forward-only

Removing Bob's wrap is not enough: Bob may have cached K. Revocation therefore **rotates**
the content key.

```
   Before                          After revoking Bob
   ------                          ------------------
   K  wrapped to Alice, Bob, Carol K' wrapped to Alice, Carol
   entries sealed under K          entries re-sealed under K'

   Bob keeps K, and K still opens any ciphertext he already copied.
```

**Bob retains everything he read before revocation.** This is inherent to shared storage,
not a flaw in the implementation - once someone has read data, no protocol can un-read it.
The UI must say so plainly rather than imply that revocation is retroactive.

Folder key inheritance means a grant high in the tree cascades: a child folder's key is
wrapped by its parent's key.

---

## 7. Escrow

Business continuity for the case where a user is *gone* - not merely locked out. A user who
is present and trusted but forgot their passphrase needs no escrow: enrol a fresh identity
and re-wrap the shared folder keys. Only their personal vault is lost.

### Two roles, deliberately separate

| Role | Can | Basis |
|---|---|---|
| **Admin** | enrol users, grant/revoke ACLs, seal log epochs | keys for folders they manage |
| **Escrow holder** | recover data belonging to *others* | holds a share of the escrow key |

Being an admin does **not** make you an escrow holder. That separation is what allows a
second admin to manage users without gaining recovery power over everyone's vault - a
distinction a bare quorum cannot express. The admin who *signs* the configuration (below)
authorises policy; signing grants no share.

### The configuration is signed, and the types enforce it

Every user can write to the shared store, so a bare config file is attacker-writable.
Unauthenticated, it would be the cheapest full break in the system: swap in your own
"escrow" public key and every honest client wraps future folder keys to *you*; flip
`personal_vaults` to `true` and they escrow private vaults without anyone choosing that.

The stored form is therefore `SignedEscrowConfig` - the config plus an admin signature
over `"remotino/v1/escrow-config" || CBOR((config, authorized_by, binding))`. And the
enforcement is *structural*, not procedural:

```
   deserialise  ->  SignedEscrowConfig      fields private, no wrap or recover API
                          |
                          |  .verify(&trusted_admin)     signature + structural checks
                          v
                    VerifiedEscrowConfig    no Deserialize, no public constructor
                          |
                          +-- wrap_key(key, class)       the ONLY path to an escrow wrap
                          +-- recover(holders)
```

An unverified config cannot reach a wrap call because the API to do so does not exist on
it. `trusted_admin` must come from somewhere the attacker cannot write - the client's
TOFU pin, or resolution through the verified audit chain; verifying against a key read
from the same store would be circular. The optional `binding` field carries the chain
`Head` at establishment, signed, so Phase 2 clients can demand that a config is tied to
the `EscrowQuorumChanged` entry that authorised it.
Tests: `wholesale_config_swap_cannot_redirect_wraps`, `scope_widened_in_storage_is_rejected`.

**Scope is enforced at the point of use.** `wrap_key` takes an `EscrowClass`
(`SharedFolder` or `PersonalVault`) and refuses classes the scope excludes, so with
`personal_vaults: false` there is no code path that escrows a vault key.
Test: `out_of_scope_wrap_is_refused_at_the_point_of_use`.

**Structural validation runs at signing and again at verification**: exactly one share
per issued slot (`shares.len() == n`), no duplicate holders, no duplicate indices,
indices in `1..=n`. Index 0 is rejected now, while the format is cheap to constrain,
because in Shamir it is the evaluation point where the polynomial equals the secret
itself. A duplicate-holder config is rejected outright rather than letting a bogus
share shadow the real one and permanently break recovery.

**The quorum counts distinct holders, never arguments.** `recover(&[&a, &a, &a])`
contributes one. This gate runs before the (future) Shamir combination, so it is the
count a `k > 1` implementation will inherit and trust; and the holder-count conversion
fails closed rather than saturating upward.
Test: `replaying_one_admin_does_not_meet_a_higher_quorum`.

### Why growth is cheap

Content keys are wrapped to the escrow **public** key, which never changes. Re-sharding
changes only how the escrow **private** key is protected.

```
   content keys ---> wrapped to ESCROW_PUB        (never re-wrapped)
                                |
                          ESCROW_PRIV
                                |
              +-----------------+------------------+
              |  protection of ESCROW_PRIV         |  <- only this changes
              |                                    |
              |  1 admin   : sealed to admin1      |
              |  2 admins  : still sealed to admin1|  (admin2 administers only)
              |  3+ admins : Shamir 2-of-3         |
              +------------------------------------+
```

Changing the quorum re-wraps **no content keys**. It re-splits one private key. Seconds,
not a migration. Preserve this property; losing it turns every admin change into a repo
rebuild.

The on-disk format carries `k` and `n` from day one, even at `k = n = 1`, so each
transition is a policy change rather than a format change. Every re-shard emits
`EscrowQuorumChanged` into the audit chain.

### Scope

| Scope | Default | Reasoning |
|---|---|---|
| Shared folder keys | **escrowed** | Org data; losing it to one forgotten passphrase is an availability failure that surprises nobody |
| Personal vaults | **not escrowed** | Enabling it lets admins read users' personal credentials. Must be deliberate, disclosed in the UI, and recorded in the chain |

Widening the scope means producing a new `SignedEscrowConfig` - a re-signing by an
admin, visible in storage, and (Phase 2) accompanied by a chain entry. It cannot be
done by editing the stored file.

### Current state

`k = 1` is implemented. `k > 1` returns `Error::Unsupported` rather than accepting a single
share under a `k = 2` policy - failing loudly beats a security hole dressed as a partial
implementation. Test:
`multi_holder_recovery_reports_unimplemented_not_wrong_answer`.

### Limitations

1. Re-sharding reconstructs the escrow private key in memory on one machine. Inherent to
   secret sharing.
2. Raising the quorum is **forward-looking only**. Moving 1-of-1 to 2-of-3 cannot retract a
   copy the previous sole holder retained. It binds future cooperation and rests on
   trusting whoever performed the re-shard.

---

## 8. The audit chain

Not a blockchain. Consensus solves mutually distrusting parties with no shared authority -
not this situation - and would cost the speed the project exists to gain. This is what Git
and Certificate Transparency use.

### Structure

```
  entry 0 (genesis)        entry 1                  entry 2
  +------------------+     +------------------+     +------------------+
  | seq:  0          |     | seq:  1          |     | seq:  2          |
  | prev: 000...0    |  +->| prev: H(entry 0) |  +->| prev: H(entry 1) |
  | actor, action    |  |  | actor, action    |  |  | actor, action    |
  | payload          |  |  | payload          |  |  | payload          |
  +------------------+  |  +------------------+  |  +------------------+
  | signature        |  |  | signature        |  |  | signature        |
  +------------------+  |  +------------------+  |  +------------------+
          |             |          |             |
          +-- H() ------+          +-- H() ------+

  signature = Ed25519( signing_key, CBOR(body) )
  H(entry)  = SHA-256( len(tag) || "remotino/v1/chain-entry" || CBOR(entry) )   <- covers the signature too
```

The digest covers the signature as well as the body, so a link pins *which* signature was
accepted, not merely the content. It is domain-tagged, so an entry digest can never
collide with a digest of some other kind of object that happens to share bytes.

### Canonical bytes: the digest pins bytes, not just meanings

CBOR admits many encodings of one value - reordered map keys, non-minimal integers,
indefinite lengths. Since digests and signatures are computed over the canonical
encoding, accepting arbitrary encodings on decode would let two byte-distinct stored
entries share a digest: the chain would pin what an entry *means* but not what was
*stored*.

So decoding fails closed. `Entry` (and `SignedEscrowConfig`) have **no `Deserialize`
impl**; the only path from stored bytes to a value is `Entry::from_bytes` /
`SignedEscrowConfig::from_bytes`, which reject any input that is not byte-identical
to the canonical encoding of the value it decodes to. Structs and canonical bytes
are therefore one-to-one.

**The storage contract this fixes for `SqlRepo`:** store `Entry::to_bytes` output
verbatim in the `body` column and decode reads with `Entry::from_bytes`. Nothing
else will decode - a store that re-encodes, normalises, or pads returns bytes that
fail loudly rather than entries with drifted digests. Storing parsed structs and
re-serialising on read (what `MemoryRepo` does) is equally sound *because of* the
bijection; both representations always agree.

Tests, named for the attacks they foreclose:
`reordered_map_keys_cannot_mint_a_second_encoding_of_an_entry`,
`nonminimal_integer_encoding_of_an_entry_is_rejected`,
`indefinite_length_encoding_of_an_entry_is_rejected`,
`trailing_bytes_after_an_entry_are_rejected`,
`noncanonical_encoding_of_a_stored_escrow_config_is_rejected`.

### Verification

- Each entry's `prev` must equal the previous entry's digest
- Sequence numbers must be contiguous
- The author must be **enrolled** - a well-formed signature from an unknown key is
  rejected. Test: `unknown_author_is_rejected`
- An entry cannot be signed on behalf of another actor. Test: `cannot_sign_as_someone_else`

Verification is incremental: a client resumes from its cached `Head` rather than replaying
from genesis.

`verify_chain` returns the verified `Head`, and verifying zero entries against no prior
head is an **error**, not an empty success - `Ok` always means "there is a verified
head". An empty delta against a known head is fine and returns that head unchanged.
Test: `verifying_nothing_is_not_success`.

The reference `MemoryRepo` is public and is the executable form of the `Repository`
contract: `append` rejects empty batches, non-genesis starts, sequence gaps and broken
links (atomically - a bad batch commits nothing), and `read_from` returns ascending
`seq`. A `SqlRepo` must be behaviourally equivalent; signature verification stays with
`verify_chain` above the repository, because the store is untrusted and clients must
re-verify regardless.

### Timestamps are not trusted for ordering

Clocks on a shared network drift and can be set deliberately. `seq` and `prev` establish
order; the timestamp is for humans.

### The limitation: truncation

```
  full chain      0 -- 1 -- 2 -- 3 -- 4      valid
  truncated       0 -- 1 -- 2                ALSO VALID
```

A hash chain detects **mutation**, not **deletion**. Anyone who can write to the store can
delete the newest entries and leave a chain that verifies perfectly. There is a test that
asserts exactly this - `truncation_is_not_detected_by_the_chain_alone` - because a
limitation that is only mentioned in prose eventually gets forgotten.

Two defences, neither of which is hashing:

1. **Head pinning.** Clients persist the highest `(seq, digest)` they have seen. A head
   that moves backwards, or changes digest at the same seq, is an unambiguous alarm -
   `Head::check_not_rewound` is that cheap, entry-free comparison.
   Test: `head_pinning_catches_truncation`.

   What the cheap check cannot see: a **fork** that truncates after the pin and grows
   a *longer* replacement history advances `seq` and passes it. That is inherent to
   comparing two `(seq, digest)` pairs - descent is a property of the entries in
   between. The sound check is `verify_chain(new_entries, Some(pinned_head), ..)`,
   which walks the links from the pin and breaks at the first divergent entry. Poll
   with `check_not_rewound`; never re-pin a head that did not come out of
   `verify_chain`. (The function was renamed from `check_advance`, which read as if
   it proved advancement.) Test:
   `fork_with_higher_seq_is_invisible_to_head_comparison_but_caught_by_verify_chain`.
2. **Append-only storage permissions.** This *prevents* rather than detects, and is the
   main reason the backend is SQL Server: `DENY UPDATE, DELETE` is enforced by the server,
   not requested by the client. See `DESIGN.md` 8.2.

### Pruning without losing verifiability

Logs grow, and pruning is legitimate. It must not delete hashes.

```
  EpochSealed {
      covers:      [1 .. 4700]
      merkle_root: <root over every pruned entry>
      entry_count: 4700
      archived_to: "archive/epoch-0007"
      signature
  }
```

The live log keeps a hot window plus every `EpochSealed` record forever (~200 bytes each),
so the chain stays verifiable from genesis indefinitely. Archived segments can go to cold
storage or be deleted outright - the root still proves what they contained, and any
archived entry can later be proven against it with an inclusion proof.

---

## 9. Use cases, end to end

### 9.1 First install

```
1. Admin enters a passphrase
2. Identity::generate()              -> Ed25519 + X25519 keypairs
3. identity.seal(passphrase, params) -> SealedIdentity, stored
4. EscrowConfig::create_sole(...)    -> escrow keypair, sealed to the admin
5. SignedEscrowConfig::sign(...)     -> admin signs the config; only this form is stored
6. Genesis entry signed and appended -> RepoCreated
```

The admin is now the sole escrow holder. Nobody else exists.

### 9.2 Onboarding a user

```
Bob                                  Admin
---                                  -----
generate identity
seal under his passphrase
publish public identity  ---------->  verify out of band (fingerprint)
                                      append UserEnrolled (signed)
                                      wrap folder keys Bob should see
                                        -> WrappedKey per folder
```

Bob's passphrase never leaves his machine. The admin only ever sees public keys.

**Out-of-band verification matters.** Nothing cryptographic stops an admin enrolling a key
that is not really Bob's. Compare fingerprints over a channel the store does not control.

### 9.3 Opening the app

```
passphrase -> Argon2id -> derived key -> unlock SealedIdentity
                                              |
                                              +-> signing key  (sign new entries)
                                              +-> wrapping key (unwrap folder keys)
                                                       |
                                    for each folder the user can see:
                                    ContentKey::unwrap_for(...)
                                                       |
                                              decrypt entries, render tree
```

Folders whose wraps are absent simply do not decrypt - they are invisible, not greyed out.

### 9.4 Granting access

```
Admin unwraps K for "Production" (they hold a wrap)
Admin wraps K to Bob's public key
Admin appends AclGranted { folder, grantee: Bob }  (signed)
Bob's next sync sees the new wrap and the folder appears
```

One wrap, one entry. No re-encryption.

### 9.5 Revoking access

```
Admin generates K'
Admin re-seals folder entries under K'
Admin wraps K' to remaining users (not Bob)
Admin appends AclRevoked + KeyRotated       (signed)

Bob loses access to everything from this point forward.
Bob keeps anything he already read.  <- say this in the UI
```

### 9.6 Lost passphrase, user still present

**No escrow needed.** The common case.

```
Admin appends UserRevoked for the old identity
Bob generates a new identity
Admin enrols it and re-wraps shared folder keys
Bob is back. Only his personal vault is lost.
```

### 9.7 Lost passphrase, user gone - escrow

```
Quorum of escrow holders (k of n) combine to recover ESCROW_PRIV
ESCROW_PRIV unwraps the escrow copy of the content keys
Data is recovered
EscrowRecoveryPerformed appended, naming the participating admins
```

Escrow use is always visible after the fact. That is the point of recording it.

### 9.8 Second admin joins

```
Enrol admin2 as a user with admin capability
Do NOT issue an escrow share

Result: admin2 can enrol users and manage ACLs,
        but cannot recover anyone else's data.
```

Exactly the behaviour asked for in `DESIGN.md` 9.4a, expressed as role separation rather
than as an ordering between admins - because key material has no notion of precedence.

### 9.9 Third admin joins - quorum rises

```
admin1 (sole holder) reconstructs ESCROW_PRIV
Shamir-splits it 2-of-3
Seals one share to each of admin1, admin2, admin3
Appends EscrowQuorumChanged { from: 1-of-1, to: 2-of-3 }

No content key is re-wrapped.  ESCROW_PUB is unchanged.
```

### 9.10 Tampering is detected

```
Attacker edits entry 2 in the store
        |
        v
Client verifies: H(entry 2) no longer matches entry 3's prev
        |
        v
Error::ChainIntegrity("broken hash link")   -> refuse to load, alert
```

And if the attacker instead deletes entries 3-4:

```
Chain verifies cleanly (see section 8)
        |
        v
But head is now (2, H2), while the client pinned (4, H4)
        |
        v
Head::check_not_rewound -> Error::ChainIntegrity("head moved backwards")
```

And if the attacker deletes entries 3-4 and appends their own entries 3'-5':

```
Head is (5, H5'), ahead of the pin (4, H4) - check_not_rewound passes by design
        |
        v
Client syncs: verify_chain(entries after seq 4, Some((4, H4)))
        |
        v
Entry 5' links to H4', not H4
        |
        v
Error::ChainIntegrity("broken hash link")   -> the fork is caught at sync
```

---

## 10. Implementation notes

- **No `unsafe`.** Forbidden crate-wide.
- **`unwrap`, `expect`, `panic`, indexing and arithmetic overflow are denied** in library
  code by workspace lints. This crate parses data written by other people; a panic there
  is a remote crash. Tests are exempt, where an unwrap *is* the assertion.
- **Secrets zeroize on drop** (`DerivedKey`, `ContentKey`, plaintext buffers).
- **`Debug` never prints key material** - there are tests asserting this, because a
  debug-print leak is the kind of bug that survives review.
- **Errors are deliberately coarse.** `Error::Decrypt` covers wrong passphrase, wrong key
  and tampering alike; distinguishing them hands an attacker an oracle.
- **One canonical encoding.** Everything hashed or signed goes through a single CBOR
  function. If signing and verification ever encoded differently, signatures would fail
  silently - or worse, verify something other than intended. And the encoding is
  enforced on the way *in*, not just produced on the way out: stored signed objects
  decode only through `from_bytes` constructors that reject non-canonical CBOR
  (section 8), so a digest determines the stored bytes, not merely the value.

### Not yet done

| Item | Status |
|---|---|
| Shamir `k > 1` | Returns `Unsupported` |
| ML-KEM-768 hybrid | Discriminant reserved, unimplemented |
| `EpochSealed` pruning | Designed, not implemented |
| **Independent review** | **Not done - required before anything is built on this** |

That last row is the important one. The construction here is conventional and the tests are
thorough, but "looks correct" is not a security property, and the author is not a
cryptographer. `DESIGN.md` 7 calls for review before Phase 2; that still stands.
