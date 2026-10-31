# Remotino — Design Draft v0.1

An open-source, cryptographically-enforced remote connection manager (RDP/SSH) with a
shared file backend, per-user credential vaults, and a tamper-evident audit log.

Goal: replace Remote Desktop Manager at ~100+ entries without the latency.

---

## 1. Technology stack

| Layer | Choice | Why |
|---|---|---|
| Shell | **Tauri v2** | ~10 MB binaries, native webview, Rust core. Ships macOS arm64 + Windows 11 from one codebase. |
| Core | **Rust** | The RDP, SSH, crypto and storage libraries we need are all best-in-class in Rust. |
| UI | **Svelte 5 + TypeScript** | Tab shell, connection tree, settings. Small and fast; no virtual-DOM overhead on the framebuffer path. |
| RDP | **IronRDP** (`ironrdp-client`) | Pure-Rust RDP. Sans-IO core, native client engine, embeddable. Same code on both OSes. |
| SSH | **russh** + **xterm.js** | Embedded terminal, so SSH lives in a tab like everything else. |
| Crypto | **RustCrypto** / `ring` / `age`-style envelopes | See §4. |
| Storage | Append-only encrypted segment log on SMB | See §3. |

### Why this solves the macOS RDP problem

The usual trap: on Windows you embed the `mstsc` ActiveX control, on macOS you can't
embed anything, so you shell out to Microsoft's *Windows App* — and your tab model dies
on the Mac.

IronRDP removes the fork entirely. It's a Rust RDP implementation with a sans-IO core:
the Rust side owns the TCP connection, decodes frames, and hands decoded bitmaps to the
UI, which blits them into a `<canvas>`. Identical behaviour and identical code on macOS
arm64 and Windows 11. One tab model, one input pipeline, one clipboard implementation.

**Bonus that matters for your threat model:** you asked for clipboard only — no drive
redirection, no printers. With `mstsc` that's a *configuration flag* the user can flip.
With IronRDP you simply do not compile the `rdpdr` (drive) or printer virtual channels
in. Only `cliprdr` exists. The restriction becomes structural rather than advisory —
there is no code path to redirect a drive.

**Risk to validate in week 1 (see §7):** IronRDP is younger than `mstsc`. Codec coverage
(RemoteFX, RLE, bitmap) is good; verify H.264/AVC444 and multi-monitor against your
actual server fleet before committing. This is the single biggest technical risk in the
plan, so it gets tested first.

### On SSH — a conflict in your spec

You asked to use the onboard clients (Windows OpenSSH / macOS Terminal). That conflicts
with your own requirement that everything lives in tabs in one maximised window — an
external `ssh.exe` or Terminal.app is a separate OS window you cannot tab.

Recommendation: embed `russh` + `xterm.js`. You get the tab model, and session
credentials flow from the vault into the connection without ever touching a command line
(no secrets in process args or shell history). Keep "open in external terminal" as a
per-entry escape hatch for edge cases like ProxyJump chains you'd rather hand to
OpenSSH's config.

---

## 2. Application shell / UX

```
┌──────────────────────────────────────────────────────────────┐
│ [Connections] [srv-db01 ×] [fw-edge ×] [build-vm ×]     ⚙ 🔒 │  ← 28px tab strip
├──────────────────────────────────────────────────────────────┤
│                                                              │
│                  full-bleed session surface                  │
│              (canvas for RDP / xterm for SSH)                │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

- Tab 0 is always the connection tree; it is never closable.
- Session tabs render edge-to-edge. No chrome, no toolbars, no status bar.
- Chrome auto-hides in fullscreen; reveal on a 3px top-edge hover zone.
- RDP resolution follows the surface; reconnect-on-resize via Display Update channel.
- `Ctrl/Cmd+1..9` jump to tab, `Ctrl/Cmd+W` closes, `Ctrl/Cmd+K` is a fuzzy connection
  launcher — at 100+ entries this becomes your primary navigation, not the tree.

**Performance budget** (the reason you're leaving RDM): cold start to interactive
< 500 ms, connection tree filter < 16 ms at 1000 entries. Achieved by §3's local cache —
the app must never block startup on an SMB round-trip.

---

## 3. Backend: the file format

The thing that makes RDM slow at 100 entries is near-certainly a monolithic
document that is fetched, decrypted, and parsed in full on every open and every write.
Do not repeat that.

### Backend: SQL Server only (revised 2026-07-21)

The original plan shipped a file backend first and added SQL later. **That is reversed:
SQL Server is now the only backend.** The file layout below is retained for reference but
is not being built.

Why the change:

1. **Append-only becomes enforced rather than requested.** `DENY UPDATE, DELETE` is
   applied by the server to each user's login. On a file share, append-only is a
   permission we ask for and a convention clients follow; in SQL it is a constraint they
   cannot violate. This converts the truncation defence (section 5, `CRYPTO.md` 8) from
   *detection* into *prevention*, which is the single strongest integrity improvement
   available to this design.
2. **It deletes a large amount of work.** No segment files, no snapshot files, no
   compaction of loose `.evt` records, no dependence on SMB byte-range locking, and
   Spike B (SMB concurrency) is no longer needed at all.
3. **Incremental sync becomes a query.** `WHERE seq > @cursor` against an index, rather
   than directory enumeration and partial-file reads.
4. **SMB proved fiddly in practice.** Phase 0 alone hit exec-bit differences, line-ending
   translation, hidden-attribute deletes and cross-platform path handling - none of them
   fatal, all of them time.

Confidentiality is **unchanged**: records are client-side encrypted before they reach the
server, so SQL sees ciphertext exactly as SMB did. This is an integrity and concurrency
change, not a secrecy one.

### Single-seat backend: embedded SQLite, not LocalDB (revised 2026-07-24)

The single-seat store was going to be SQL Server Express **LocalDB**. In practice it can't
be: our `SqlRepo` uses `tiberius`, which connects over **TCP**, and LocalDB is reachable
only over **named pipes** (`np:\\.\pipe\LOCALDB#...`). There is no TCP endpoint to point
tiberius at, and SQL Browser (which tiberius uses to resolve named instances) does not
serve LocalDB.

So single-seat uses **embedded SQLite** instead - the same engine the local cache already
bundles. A `SqliteRepo` implements the exact same `Repository` trait (`append`,
`read_from`, `head`) and answers the same `MemoryRepo` conformance contract as `SqlRepo`,
so nothing above the trait knows or cares which backend is in use.

This does not reopen the "no file backend" decision (section 3 top): that was about SMB
*file shares*, with their locking and cross-platform grief. An embedded local SQLite
database is the same category as LocalDB was - a local, single-process store - just one
our stack can actually talk to, and one already present.

The security properties are identical to what LocalDB would have given single-seat:
append-only is **evident, not enforced** (the user is sysadmin over their own file either
way), and the store is local-only. The chain still makes tampering evident. Shared
deployments are unaffected: they use `SqlRepo` against Express over TCP, where append-only
*is* server-enforced.

| | Single seat | Shared |
|---|---|---|
| Backend | **embedded SQLite** (`SqliteRepo`) | SQL Server Express (`SqlRepo`, TCP) |
| Ships with | the app - no external service | admin installs Express on the NAS |
| Append-only | evident | enforced (`DENY UPDATE, DELETE`) |

**The cost, stated plainly:** every deployment now requires a SQL Server instance
(Express is sufficient and free). For a personal or small-team tool sitting next to a NAS
that is a non-issue, but it does raise the barrier for anyone else adopting the project.
If a zero-dependency backend is ever wanted, the `Repository` trait is the seam - see
below.

### Legacy file layout (not implemented, kept for reference)

```
\\server\share\remotino\
  repo.json                  # format version, repo id, crypto suite (cleartext)
  users/<keyid>.pub          # public identities
  log/000001.seg             # append-only, signed, hash-chained segments
  snapshots/000002.snap      # materialised state at seq N
  vaults/<keyid>.vault       # per-user credential vault
```

### Event sourcing — the log *is* the database

Every mutation is an event appended to the log: `FolderCreated`, `EntryUpdated`,
`AclGranted`, `UserAdded`, `KeyRotated`. Current state is the fold of all events.

This is the design's central move, and it buys three things at once:

1. **Speed.** Clients keep a local encrypted cache (SQLite) plus the last-applied
   sequence number. On launch you render from cache *immediately*, then read only
   segments newer than your cursor. Steady-state sync is a few KB, not a full document.
   Startup does not block on the network.
2. **The audit log for free.** You asked for auditing of every settings change. In an
   event-sourced system there is no separate audit subsystem to fall out of sync —
   the audit log and the data are the same artefact. An unaudited change is not
   representable.
3. **Concurrency without locking.** Appending to a new file is far friendlier to SMB
   than read-modify-write on a shared document. Writers append
   `<seq>-<keyid>.evt` records; segments are compacted later. This sidesteps SMB
   byte-range locking, which you do not want to depend on.

Snapshots are a pure cache: signed, and always reconstructible by replaying the log.
Never treat a snapshot as authoritative.

### Schema

Deliberately narrow. The server stores opaque bytes and enforces append-only; it does not
understand the payloads, and must not need to.

```sql
CREATE TABLE dbo.Events (
    seq         BIGINT       NOT NULL PRIMARY KEY,   -- chain position, contiguous
    prev_hash   BINARY(32)   NOT NULL,               -- link to seq-1
    entry_hash  BINARY(32)   NOT NULL,               -- SHA-256 over the CBOR entry
    actor       BINARY(32)   NOT NULL,               -- KeyId of the signer
    signature   BINARY(64)   NOT NULL,               -- Ed25519 over CBOR(body)
    body        VARBINARY(MAX) NOT NULL,             -- CBOR(EntryBody), payload encrypted
    written_at  DATETIME2    NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE UNIQUE INDEX IX_Events_entry_hash ON dbo.Events(entry_hash);

-- Public identities. Readable by everyone; integrity comes from the chain, not the table.
CREATE TABLE dbo.Identities (
    key_id      BINARY(32)   NOT NULL PRIMARY KEY,
    public_blob VARBINARY(MAX) NOT NULL              -- CBOR(PublicIdentity)
);

-- Per-user sealed vaults. Only the owner can decrypt; the server cannot.
CREATE TABLE dbo.Vaults (
    key_id      BINARY(32)   NOT NULL PRIMARY KEY,
    sealed_blob VARBINARY(MAX) NOT NULL
);
```

`written_at` is the server's clock and is **advisory only** - ordering comes from `seq`
and `prev_hash`, exactly as in the file design. It exists for operational forensics, not
for the protocol.

### Permissions - the reason for the change

```sql
CREATE ROLE remotino_user;
GRANT  SELECT, INSERT ON dbo.Events     TO remotino_user;
DENY   UPDATE, DELETE ON dbo.Events     TO remotino_user;
GRANT  SELECT, INSERT ON dbo.Identities TO remotino_user;
DENY   UPDATE, DELETE ON dbo.Identities TO remotino_user;
GRANT  SELECT, INSERT, UPDATE ON dbo.Vaults TO remotino_user;  -- own row only, see below
```

A separate `remotino_admin` role holds the archival rights needed for `EpochSealed`
compaction (section 8.1). Everyday users cannot remove history even if their client is
compromised.

Vault row ownership should be enforced with a row-level security predicate tying `key_id`
to the connecting login, so one user cannot overwrite another's vault. Note this is an
*availability* control, not a confidentiality one - the blob is sealed to its owner
regardless.

### Authentication without a domain

Per-user **SQL Authentication** logins, created by an admin at enrolment. Not one shared
application login: a shared credential lands in every client's config, any user can
extract it, and they would then hold the DELETE-capable identity - discarding precisely
the guarantee SQL Server was adopted for.

The login password is **sealed to the user's X25519 public key** and stored in the repo,
so it travels with enrolment and needs no out-of-band delivery:

```
passphrase -> Argon2id -> unlock identity -> unwrap SQL password -> connect
```

One passphrase, as designed. The user never sees or types a SQL credential.

Because content is end-to-end encrypted, **a leaked SQL password is low-stakes**: it
yields ciphertext and an append-only grant. It is an access boundary, not a
confidentiality boundary, so rotation is routine rather than an incident.

Connections use `Encrypt=True` with the server certificate pinned.

### Two deployment modes

| | Single seat | Shared |
|---|---|---|
| Engine | **SQL Server Express LocalDB** | **SQL Server Express** (or higher) |
| Runs as | user-space process, on demand | Windows service |
| Network | **local only** - by design | TCP, certificate pinned |
| Install | bundled with the Remotino installer | installed once on the NAS/server |
| Logins | the local user | per-user SQL Auth (see above) |
| Append-only | **evident, not enforced** - see below | **enforced** by `DENY UPDATE, DELETE` |

LocalDB is included with Express (still current as of SQL Server 2025/17.x), needs no
service and no administration, and caps at 50 GB - irrelevant for a log of connection
metadata.

#### Express does support network connections

Worth stating explicitly, because the opposite is a widespread belief: **Express is a full
server edition and accepts remote connections.** What trips people up is that **TCP/IP
ships disabled**, so a fresh install refuses remote clients and looks like it is licensed
not to.

Only LocalDB is genuinely local-only.

Server-side setup for the shared deployment:

1. Enable **TCP/IP** in SQL Server Configuration Manager
2. **Restart the SQL Server service** - protocol changes are not honoured until it restarts
3. Add an inbound **firewall rule** for the chosen port
4. Either run **SQL Browser** (UDP 1434) so clients can resolve `HOST\SQLEXPRESS`, **or**
   pin a **static TCP port**

Prefer the static port and leave SQL Browser off: one firewall rule, no extra service, no
UDP name resolution, and the client config reduces to `host,port`. Fewer moving parts to
diagnose later.

Express limits - 10 GB per database, ~1.4 GB buffer pool, 1 socket / 4 cores - are nowhere
near binding for a log of connection metadata.

#### The caveat that must not be glossed

**LocalDB runs as the user, so the user is sysadmin on their own instance.** They can drop
the `DENY`, or detach the `.mdf` and edit it elsewhere. The server-side append-only
enforcement - the main argument for choosing SQL - **does not bind in single-seat mode.**

This is acceptable, for a specific reason: that enforcement protects users *from each
other*, and protects shared history from a compromised client. In a single-seat deployment
there is no one else; the user is the sole admin and the sole subject of the log.

What still holds: the hash chain and head pinning, so tampering remains **evident** even
though it is not **prevented**. The guarantee degrades from enforced to evident, and the
UI should not imply otherwise.

Consequence worth recording: entries written during the single-seat era were never
server-enforced, so after migration their integrity rests on the chain alone. Entries
written after the move get the stronger property.

#### Migration: replay, not backup/restore

Backup and restore from LocalDB to a full instance works and is documented, but the design
offers something better:

```
   LocalDB                                Shared Express
   -------                                --------------
   read_from(None) ────────────────────►  append(entries)
                                                 │
                                                 ▼
                                          verify_chain(...)
                                          - every prev link intact
                                          - every signature valid
                                          - head matches the pinned head
```

Because the log *is* the database, migration is a replay - and the hash chain **proves**
nothing was lost or altered in transit. A restore offers no such assurance; it asks you to
trust the copy. This also sidesteps `.mdf` version compatibility and avoids carrying
LocalDB-era logins into an instance where they would be wrong.

Both ends implement `Repository`, so the tool is: open two `SqlRepo`s, stream, verify.

#### The migration wizard

Migration and first-time shared setup are the same operation with a different starting
point, so they share one component. It is also what provisions a login when a new user is
enrolled.

##### Two credentials, two lifetimes

| | SQL admin (`sa` or equivalent) | Per-user login |
|---|---|---|
| Needed for | `CREATE DATABASE`, schema, `CREATE LOGIN`, `GRANT`/`DENY`, row-level security | `SELECT` + `INSERT` on `Events` |
| Used | **once**, during provisioning | every session |
| Stored | **never** | sealed to the user's X25519 key |

The admin credential is **transient**: held in memory, zeroized after use, never written to
config, never logged, never placed in a vault. This follows the same rule as section 8.5 -
if we will not hand a password to a process we do not control, we certainly will not
persist a sysadmin credential. The chain records *that* provisioning happened and by whom;
it never records the credential itself.

##### Wizard steps

```
 1. Target          host, port, instance            -> test connection
 2. Credential      SQL admin login                 -> transient, never stored
 3. Preflight       version, TCP enabled, database
                    absent or empty, admin rights   -> fail early, fail clearly
 4. Provision       database, schema, role,
                    per-user logins + sealed pwds   -> idempotent
 5. Replay          stream entries source -> target -> resumable, shows progress
 6. Verify          verify_chain on target,
                    compare head with source        -> must pass before step 7
 7. Cutover         write connection config
                    (host/port/db only - no creds)
 8. Discard         zeroize admin credential
```

Steps 1-6 are non-destructive. The source is only ever read, so a failure at any point
before step 7 leaves the single-seat deployment intact and the operation can simply be
retried.

##### Two properties that come free from the design

**Resumable.** Entries have contiguous `seq` and the target exposes `head()`, so resuming
is `read_from(target_head)`. Because `seq` is the primary key, a retried insert is
idempotent - a dropped connection mid-replay costs a restart of the copy, not a rebuild.

**Verifiable.** Step 6 is not a checksum over a file; it re-verifies every hash link and
every signature in the target, then compares the head to the source. If it passes, nothing
was lost or altered in transit. A backup/restore can only assert that bytes were copied.

##### Ordering: record the migration in the source, not the target

If a `RepositoryMigrated` event were appended to the source *after* copying, the target
would be missing it and the two logs would diverge immediately.

Instead append `RepositoryMigrated { from, to, at_seq }` to the **source first**, then
replay everything including it. The target's history then contains the record of its own
migration, and the source is marked archived and read-only. One log, one continuous
history, no divergence.

##### What the user sees

They type a SQL admin credential once, watch a progress bar, and get a result. Afterwards
their own passphrase unlocks everything as before - the per-user SQL password is sealed to
their key and they never see it. Nothing about day-to-day usage changes.

#### Licensing - verify before shipping

Express is redistributable *bundled with an application* (not standalone), and the
installer must present its licence terms for acceptance. Reports differ on whether 2019+
licence files still carry explicit distribution clauses. **Read the licence for the exact
version shipped**, and for wide distribution get a direct answer from Microsoft rather
than relying on secondary sources. Unresolved here.

### The Repository trait still earns its place

`Repository` (`append`, `read_from`, `head`) remains, with `SqlRepo` as the only
production implementation. It is not dead abstraction:

- `MemoryRepo` in the crate's tests is the executable contract every backend must satisfy
- it keeps the crypto core free of I/O and of any SQL dependency
- if a zero-dependency backend is ever wanted, this is where it attaches

What is *not* being built is a second production backend nobody asked for.

---

## 4. Cryptography — where I'd push back

### The 8192-bit RSA requirement

I'd advise against it, on your own stated grounds. Three reasons:

1. **It's slow in exactly the place you care about.** RSA-7680 keygen benchmarks at
   ~43 seconds; 8192 is in the same range and highly variable — a multi-minute first-run
   on some hardware. Worse, you want *every audit entry signed*. RSA-4096 signing is
   ~2000× slower than Ed25519, and each signature is ~1 KB. At thousands of audit
   entries, you're building the slowness you're trying to escape into the hot path.
2. **It buys no future-proofing.** 8192-bit RSA and 2048-bit RSA both fall to Shor's
   algorithm. If "MEGA encrypted" means resisting future attack, RSA key size is the
   wrong dial. The right one is hybrid post-quantum: **X25519 + ML-KEM-768**.
3. **Classically, 4096 is already beyond any projected attack.** The gap from 4096 to
   8192 is not a security improvement anyone can operationalise.

**Recommended suite:**

| Purpose | Algorithm |
|---|---|
| Identity / signing | **Ed25519** — 64-byte sigs, microsecond signing |
| Key wrapping | **X25519** (+ optional ML-KEM-768 hybrid) |
| Content encryption | **XChaCha20-Poly1305** |
| Passphrase KDF | **Argon2id** (256 MB, t=3, p=4) |

Your passphrase requirement is preserved exactly: the private keys are sealed with
Argon2id-derived keys, so the passphrase *is* the login to the tool. That property
comes from the KDF, not from RSA.

**If you still want RSA:** make the suite pluggable via `repo.json` from day one
(algorithm agility is good design regardless), and use RSA-4096. But please don't put
RSA signing on the audit-write path.

### Envelope encryption and what ACLs actually mean

This is the most important consequence in the document.

With a file backend, everyone with SMB read access can read every byte. Therefore
**permissions cannot be enforced by the application — only by key possession.** A
checkbox-based ACL over a file everyone can read is decorative.

So:

- Each folder has a random **content key**; entries in it are sealed with it.
- Granting user U access = wrapping that content key to U's X25519 public key.
- Revoking access = **rotating** the content key and re-wrapping for the remaining
  users. Anyone who cached the old key still holds what they already read — revocation
  is forward-only. That is inherent to shared-file storage, not a flaw in the plan, but
  it must be stated in the UI rather than implied away.
- Inheritance: child folder keys are wrapped by the parent's key, so a grant at the top
  cascades naturally.

The admin's role is therefore *key distribution*, not permission enforcement.

### Vault

`vaults/<keyid>.vault` is sealed to a single user's key. No sharing in v1 — shared
credentials are a genuinely harder problem (rotation, revocation) and belong in v2 as
"credential handed out via the folder key" rather than a special case.

---

## 5. Audit log integrity — hash chain, not blockchain

You want immutability. You do not want a blockchain: consensus solves *mutually
distrusting parties with no shared authority*, which is not your situation, and it
would cost you the speed you came for.

What you want is what Git and Certificate Transparency use — a **signed hash chain**:

```
Entry N = {
  seq:        N,
  prev_hash:  SHA-256(Entry N-1),
  timestamp:  RFC3339 UTC,
  actor:      <keyid>,
  action:     "EntryUpdated",
  payload:    <encrypted; secrets never logged>,
  payload_hash: SHA-256(plaintext payload),
  signature:  Ed25519(actor_sk, all of the above)
}
```

Properties: any edit to a historical entry breaks every subsequent hash; every entry is
attributable to a key holder; no entry can be forged without a private key. Verification
is a linear scan, and clients verify incrementally from their cursor.

**The honest limitation, which you should know before building:** a hash chain detects
*mutation*, but a file backend cannot prevent *truncation* or wholesale deletion.
Someone with write access to the share can delete the last N entries or the whole
directory, and the remaining chain is still internally valid. Mitigations, in order of
cost:

1. Each client persists the highest `(seq, head_hash)` it has seen. A head that moves
   backwards is a loud, unambiguous tamper alarm. Cheap, and catches the realistic case.
2. Clients co-sign checkpoints they've observed, so rollback requires colluding with
   every witness.
3. Anchor periodic head hashes somewhere append-only outside the share.
4. SMB share permissions: grant users write-new-file but deny delete/modify. Defence in
   depth — and the one control that actually prevents rather than detects.

Do (1) and (4) in v1; they're most of the value. Note that (4) fits the append-only
design perfectly — the format was already chosen to never rewrite existing files.

---

## 6. Threat model (state it explicitly, it drives everything)

**Defended:** an attacker with full read access to the SMB share learns nothing beyond
the folder graph shape; a user cannot read folders not granted to them; audit history
cannot be altered undetectably; a stolen laptop yields nothing without the passphrase.

**Not defended:** a compromised client while unlocked (keys are in RAM); a user
re-sharing data they were legitimately granted; revocation of already-cached secrets;
metadata (entry counts, timing, sizes) leaking to share readers.

---

## 7. Where to start — proposed phasing

The ordering here is deliberate: it front-loads the two things that could invalidate
the design, so a wrong assumption costs a week rather than three months.

**Phase 0 — de-risk (1–2 weeks). Do this before writing any product code.**
Two throwaway spikes:
- **Spike A:** IronRDP against *your* real servers. Connect, render to a canvas in
  Tauri, verify keyboard/mouse latency, clipboard, resize, and NLA/CredSSP auth. This is
  the plan's load-bearing assumption. If it fails, we fall back to a
  platform-split RDP layer and you need to know that now, not in month three.
- ~~**Spike B:** SMB concurrency.~~ **Dropped 2026-07-21.** The backend is SQL Server
  only (section 3), so there is no shared-file concurrency to de-risk. This is the
  clearest illustration of the point: choosing SQL removed an entire spike plus the
  segment-writing and compaction work behind it.

Neither spike ships. Their only job is to answer a question.

**Phase 1 — crypto core (2–3 weeks).** Pure Rust library, no UI. Identity generation,
Argon2id sealing, envelope encryption, the signed hash chain, and the `Repository`
trait. This is the part that must be *correct* rather than fast, so it gets built in
isolation with heavy property tests and known-answer vectors. Get it reviewed before
anything is built on top of it.

**Phase 2 — repository + sync (1–1.5 weeks, down from 2).** `SqlRepo`: schema and
migrations, per-user login provisioning, local SQLite cache, incremental replay from a
cached cursor. Target: cold start < 500 ms with 1000 entries, which the cache delivers -
startup must never block on the database.

Shorter than the original estimate because segment writing, snapshot files and compaction
of loose records all disappeared with the file backend.

**Phase 3 — shell + connection tree (2 weeks).** Tauri app, tab model, tree, search,
CRUD. No sessions yet — just prove the data layer feels instant.

**Phase 4 — RDP (2–3 weeks).** Promote Spike A into a real session tab: input, clipboard-
only, resize, reconnect, multi-session.

**Phase 5 — SSH (1–2 weeks).** `russh` + xterm.js, vault-fed auth, key and agent support.

**Phase 6 — multi-user (2 weeks).** Admin UI for enrolling public keys, ACL grant/revoke
with key rotation, audit viewer with chain verification, RDM import.

First commit should be Phase 0 Spike A. Everything else is contingent on its result.

---

## 8. Decisions log (v0.2)

### 8.1 Log pruning — epochs, not truncation

You proposed verifying the last X entries so that hiding an old event requires forging X
new ones. The instinct is right but the mechanism isn't needed, because **truncation only
ever removes the tail.** Deleting an event from the *middle* breaks `prev_hash` on the
very next entry — that's mutation, and it's already caught. So to hide event X by
truncating, an attacker must delete X *and everything after it*, destroying all
legitimate history since. Loud by construction.

That means a verification window doesn't need to be a security parameter at all. The real
requirement underneath your question is the operational one: **logs grow, and pruning is
legitimate.** Handle that directly.

**Pruning must not delete hashes — it archives entries and keeps a Merkle root.**

Sealing an epoch is itself a signed event in the chain:

```
EpochSealed {
  seq:          N,
  prev_hash:    <chains normally>,
  covers:       [first_seq .. N-1],
  merkle_root:  <root over every pruned entry>,
  entry_count:  <int>,
  archived_to:  "archive/epoch-0007.seg",
  actor:        <admin keyid>,
  signature:    Ed25519
}
```

The live log keeps full detail for the hot window (your 300 — now a *retention* setting,
not a security one) plus every `EpochSealed` record forever. Those are ~200 bytes each,
so the chain stays verifiable from genesis indefinitely at trivial cost. Archived
segments move to `archive/` and can go to cold storage or be deleted entirely — the root
still proves what they contained, and any archived entry can later be proven against it
with a Merkle inclusion proof.

Net effect: history is prunable, verification is still end-to-end from genesis, and
nothing about it depends on guessing how far back to look.

Tail truncation of the live head remains covered by the §5 mitigations — client-pinned
head hashes and append-only storage permissions.

### 8.2 SQL Server backend — a real upgrade, but not to confidentiality

Worth being precise, because "SQL = more secure" is the wrong summary.

**Confidentiality: unchanged.** Records are client-side encrypted before they ever reach
storage. SQL Server sees ciphertext, exactly as SMB does. This is a deliberate property —
it's also what makes §8.3 workable.

**Integrity and availability: genuinely better.** SQL can enforce append-only
*server-side and per-user*, which is the one thing a file share does weakly:

```sql
GRANT SELECT, INSERT ON dbo.Events TO [remotino_user];
DENY  UPDATE, DELETE ON dbo.Events TO [remotino_user];
```

That's the truncation defence from §5 as an enforced constraint rather than a detection
mechanism. Plus real concurrency, indexed incremental reads (`WHERE seq > @cursor`), and
transactional appends.

So: worth doing on the NAS, but for tamper-resistance and speed, not secrecy.

### 8.3 SQL login without a domain

Don't use one shared application login. A shared credential sits in every client's
config, any user can extract it, and they'd then hold the DELETE-capable identity — which
throws away precisely the guarantee you installed SQL Server to get.

**Per-user SQL Authentication logins**, created by the admin when enrolling a user:

1. Admin enrols user U (public key + SQL login) and generates a long random password
   for U's SQL login.
2. That password is **sealed to U's X25519 public key** and stored in the repo — so it
   travels with the user's enrolment and needs no out-of-band delivery.
3. U enters their passphrase → Argon2id unwraps their private key → which decrypts the
   SQL password → client connects. **One passphrase, as designed.** The user never sees
   or types a SQL credential.
4. Each login gets `SELECT` + `INSERT` only. Admins get an additional login with
   `EpochSealed` archival rights.

The pleasant consequence of end-to-end encryption: a leaked SQL password is low-stakes.
It yields ciphertext and an append-only grant. It's an access boundary, not a
confidentiality boundary — so rotation is routine rather than an incident.

Use `Encrypt=True` on the connection and pin the server certificate.

### 8.4 Key escrow

First, a distinction that removes most of the need for it. "Lost passphrase" is two
different problems:

- **(a) User is present and trusted, just locked out.** No escrow required. Admin enrols
  a fresh identity for them and re-wraps the shared folder keys. They're back in minutes.
  The only unrecoverable loss is their *personal vault*. This is the overwhelmingly
  common case.
- **(b) User is gone — left, incapacitated — and the org needs what they held.** Only
  this one needs escrow.

So escrow is a business-continuity control for case (b), and should be scoped as
narrowly as that implies.

**Two separately-decided scopes:**

| Scope | Recommendation |
|---|---|
| Shared folder keys | **Escrow by default.** This is org data; losing it to one person's forgotten passphrase is an availability failure, and it surprises nobody. |
| Personal vaults | **Off by default, opt-in per repo.** Enabling it means admins can read users' personal credentials. |

**Never make personal-vault escrow silent.** If it's on, the UI must say so on the vault
screen — and it should be a repo-creation policy in `repo.json`, covered by the audit
chain, so it can't be quietly switched on later without leaving a signed trace.

**No single admin should be able to use it.** Escrow with one key means one compromised
or malicious admin holds everything, which is a worse position than the problem it
solves. Use **Shamir secret sharing, k-of-n** (start 2-of-3):

- At repo init, generate an escrow keypair.
- Split the escrow *private* key into n shares; seal share i to admin i's public key.
- Every content key is additionally wrapped to the escrow *public* key.
- Recovery needs k admins to combine shares — a deliberate, quorum, auditable act.

Recovery must itself emit an `EscrowRecoveryPerformed` event naming the participating
admins and the target. Escrow use should be visible after the fact, always.

**Cost to accept:** escrow is a permanent second path to the data. It is only as strong
as the admins' key hygiene. That's the trade for business continuity — worth it for
shared folders, a real decision for personal vaults.

---

### 8.5 Embedded RDP vs launching an external client

Revisited after the Phase 0 spike, when the toolchain burden prompted the question of
whether to drop embedding and shell out to `mstsc` / Windows App / FreeRDP instead.

**Decision: keep embedding.** Not primarily for the tab UI - for credential custody.

#### The deciding constraint

A launcher design must hand the password to a process we do not control. Every available
mechanism leaks:

| Mechanism | Exposure |
|---|---|
| `mstsc` + `cmdkey` | password in argv, readable by any process; persists in Credential Manager until deleted |
| `.rdp` file with DPAPI blob | no argv exposure, but written to disk and cached by mstsc afterwards |
| FreeRDP `/p:` | upstream issue #3639 calls it "broken by design" |
| FreeRDP `/from-stdin` | correct in principle, but contends with the certificate-trust prompt - documented workaround is `/cert-ignore`, i.e. disabling certificate verification. Also an open crash regression on piped input in 3.18.0. |
| **Windows App (macOS)** | **no supported mechanism at all** |

The macOS row settles it. There is no sanctioned way to pass a credential to Microsoft's
macOS client, so a launcher build would ask users to type passwords by hand there -
negating the point of a per-user vault.

With embedding, the password is unwrapped from the vault in memory and fed straight into
the CredSSP handshake. It never touches argv, stdin, disk, or another process. That is a
direct consequence of the goals in section 1, not a nice-to-have.

A launcher's audit log would also degrade to "a session was launched", with the
credential's subsequent handling outside our control - weakening section 5's guarantees.

#### Why not FreeRDP even with embedding

Considered seriously; it has real advantages - working clipboard on all platforms, H.264,
multi-monitor, RD Gateway, and ~15 years of maturity against IronRDP's youth.

Rejected on build and packaging cost:

- C + CMake + OpenSSL with a large dependency tree, versus `cargo build`
- **MacFreeRDP ships no prebuilt binaries** - it must be built from their bundling script,
  and is reported as limited next to the Linux and Windows clients. Shipping macOS
  installers would mean compiling it ourselves, which is more toolchain burden than the
  Rust setup it was meant to avoid.
- We would still need an app shell, most naturally Tauri - so Rust *plus* a C toolchain
  and FFI, not instead of.

#### On the toolchain concern that prompted this

Worth stating plainly because it was the premise: **end users never install Rust.** Tauri
bundles `.msi`/`.exe` (WiX/NSIS), `.dmg` (signed and notarized) and Linux packages, and
`tauri-action` builds them in CI on tag push. The toolchain is a build-time dependency
for developers and CI only.

**Action:** set up the release pipeline early rather than at the end, so the "installer
with precompiled binaries" finish line is real and continuously verified rather than
deferred.

## 9. Open questions - proposed answers

Each carries a recommendation and, more importantly, **the cost of changing your mind
later**. That column is what decides which of these genuinely need settling before
Phase 1 and which can safely wait.

Marked **PROPOSED** until confirmed. Override any of them freely.

| # | Question | Proposal | Cost to reverse later |
|---|---|---|---|
| 1 | RD Gateway | **Out of v1** | Low |
| 2 | Multi-monitor | **Out of v1** | Medium |
| 3 | SSH jump hosts | **Defer implementation, reserve the field now** | Low if field reserved, high if not |
| 4 | Key escrow | **DECIDED** - see 9.4a. Admin and escrow-holder split; quorum grows 1-of-1 -> 2-of-3 | **Very high** |
| 5 | Concurrent users | **Design for <10, degrade safely** | Low |

### 9.1 RD Gateway - out of v1 (PROPOSED)

Everything tested so far is LAN, direct to port 3389. IronRDP already has an
`ironrdp-mstsgu` crate behind a `gateway` feature, so adding it later is enabling a
feature and adding config fields, not redesigning anything.

**Reverse cost: low.** Defer without concern.

**Assumption to confirm:** no remote access through an RD Gateway today. If you do reach
hosts through one, this flips to v1 and needs testing (checklist row 14).

### 9.2 Multi-monitor - out of v1 (PROPOSED)

Untested (row 10), materially raises Phase 4 cost, and sits awkwardly with the design in
section 2: a session is a *tab*, and a tab spanning two physical monitors is not a
coherent model. Single-monitor sessions that fill the window, with the window movable to
whichever display you like.

**Reverse cost: medium.** Multi-monitor touches the display-layout and resize paths, which
are the same paths the tab UI uses - so it is a rework of code you will have written,
though not a redesign of the data or crypto layers.

### 9.3 SSH jump hosts - defer, but reserve the field (PROPOSED)

ProxyJump is common for admins with bastion hosts, and `russh` can do it (session to the
jump host, then a `direct-tcpip` channel onward). But it is real work and not needed to
prove the product.

**Do now:** include `jump_host: Option<EntryRef>` in the connection entry schema from the
first version, even though nothing reads it.

**Reverse cost: low if the field exists, high if it does not.** Adding a field later means
migrating every existing record through the event log and re-encrypting affected entries.
Reserving it now costs nothing.

### 9.4a Key escrow - DECIDED (2026-07-21)

Deployment model: start as sole admin, onboard users, add admins over time. Escrow
strength grows with the admin count.

#### Admin and escrow holder are separate roles

The original framing was "the first admin takes precedence over the second". That is not
expressible in key material - a party can either decrypt or it cannot; there is no
ordering. What it actually describes is two distinct roles that were being conflated:

| Role | Capability | Cryptographic basis |
|---|---|---|
| **Admin** | enrol users, grant/revoke folder ACLs, seal log epochs | holds keys for folders they manage; permitted to append to the log |
| **Escrow holder** | recover data belonging to *others* | holds a share of the escrow private key |

Separating them is strictly more expressive than a quorum alone: a new admin can manage
users without gaining recovery power over everyone's vault. Escrow holder is then an
explicit, separately granted role - never implied by being an admin.

Note the boundary: an admin still sees any folder **granted** to them by the normal ACL
path (section 4). Escrow only governs access to what they were *not* granted.

#### Growth path

| Stage | Escrow config | Effect |
|---|---|---|
| 1 admin | 1-of-1, held by admin 1 | admin 1 can recover anything |
| 2 admins | **still 1-of-1**, admin 1 only | admin 2 administers but cannot recover others' data |
| 3+ admins | **2-of-3** | recovery requires a quorum; no single admin acts alone |

#### Why this is cheap - the escrow public key never changes

Content keys are wrapped to the escrow **public** key. Re-sharding changes only how the
escrow **private** key is protected.

So changing the quorum **re-wraps no content keys**. It reconstructs one private key,
re-splits it, and re-seals the shares to the new admin set - seconds of work, not a repo
migration. This is what makes incremental growth practical rather than a rebuild each time
an admin joins.

Implementation requirement: the on-disk format carries `k` and `n` **from day one**, even
at k=n=1, so every transition above is a policy change rather than a format migration.

Each re-shard emits an `EscrowQuorumChanged` event naming the old and new configuration
and the acting admins, so the history of who could recover what is auditable.

#### Limitations - state these in the UI, do not paper over them

1. **Re-sharding reconstructs the escrow private key in memory** on one machine at that
   moment. Inherent to Shamir; unavoidable.
2. **Raising the quorum is forward-looking only.** Moving 1-of-1 -> 2-of-3 does not
   retroactively remove the previous sole holder's ability if they retained a copy. The
   new quorum binds future cooperation and relies on trusting whoever performed the
   re-shard. In the intended model that is the founding admin, which is coherent - but it
   must be stated rather than implied.
3. Personal vault escrow remains **off by default** per the table below, independent of
   quorum. The quorum governs *who* can recover; the scope setting governs *what* is
   recoverable at all.

### 9.4b Key escrow - scope (PROPOSED)

Mechanism is in section 8.4. The remaining decision is *policy*:

| Scope | Proposal | Why |
|---|---|---|
| Shared folder keys | **Escrow by default** | Org data. Losing it to one forgotten passphrase is an availability failure, and it surprises nobody. |
| Personal vaults | **No escrow by default; opt-in per repo, disclosed in the UI** | Escrowing them means admins can read users' personal credentials. That should be a deliberate, visible choice - never a silent default. |

**On the quorum:** section 8.4 proposes Shamir k-of-n at 2-of-3. That assumes at least
three admins. **For a single-admin deployment, k-of-n is theatre** - the one admin holds
every share. So:

- Implement escrow as *wrapped to an escrow public key*, and treat protection of the
  escrow **private** key as a separate, configurable concern.
- Single admin: the escrow key is protected by that admin's own key. Honest and simple.
- Three or more admins: split 2-of-3 via Shamir.
- **Design the on-disk format to carry k-of-n from day one**, even when k=n=1, so raising
  the quorum later is a policy change rather than a format migration.

**Reverse cost: very high.** Escrow determines how every content key is wrapped. Adding it
later means re-wrapping every key in the repo and a migration event across the whole log;
removing it later cannot retroactively un-share anything already escrowed. This is the
question to answer before Phase 1 writes its first line.

**Needs your input:** how many admins will exist? That single number selects between the
two quorum paths above.

### 9.5 Concurrent users - design for under ten (PROPOSED)

The append-only segment design in section 3 already avoids the hard cases: writers append
new files rather than mutating shared ones, so there is no read-modify-write race to
coordinate.

Proposal: optimistic append with retry on collision, no locking, no coordination service.
Correct at low concurrency and degrades into occasional retries rather than corruption if
usage grows.

**Reverse cost: low.** The `Repository` trait (section 3) isolates this. Higher concurrency
is what the SQL Server backend in section 8.2 is for, and it is a backend swap rather than
a redesign.

**Assumption to confirm:** this is you plus a small team, not fifty people. If it is fifty,
skip `FileRepo` and start on SQL.

---

### What actually blocks Phase 1

**Nothing.** 9.4 is decided (9.4a) - escrow holder is a separate role from admin, and the
quorum grows with the admin count without re-wrapping content keys. Phase 1 can start.

Everything else is either low-cost to reverse or already handled by reserving a field.
9.2 is worth a deliberate answer before Phase 4, not before Phase 1.
