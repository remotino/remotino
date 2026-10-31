# Remotino

Open-source remote connection manager (RDP/SSH) with client-side encryption, a
SQL Server backend, per-user credential vaults, and a tamper-evident audit log.

Replacing Remote Desktop Manager, which is slow at ~100 entries.

**Status: Phases 0-5 substantially working in the Tauri app.** The single-seat app runs
end to end: create/unlock identity, a persistent SQLite event store, the connection tree
(folders + connections) with create / rename / delete / drag-move, live **SSH** terminals
(russh + xterm), embedded **RDP** (IronRDP sidecar: NLA, RemoteFX, input, dynamic
resolution) verified against a real Windows 11 host, and a **credential vault**
(passwords + SSH keys, each sealed under its own content key, shareable to other enrolled
users) that auto-fills on connect.
Offline backend tests pass: crypto 80, model 12, cache 9, store 6 (SQL suite needs a live
server). What is NOT done: multi-user / shared SQL Server backend + admin permissions UI
(Phase 6), TLS cert pinning + Kerberos + clipboard for RDP, and the independent
cryptographer review (a hard gate before commercialization). See `## Next steps`.

**The RDP engine is a separate process** (`rdp-host/`, its own workspace/lock): IronRDP's
CredSSP stack pins a pre-release RustCrypto snapshot that cannot share a binary with russh +
`remotino-crypto` (stable). Do not try to merge them - see `rdp-host/README.md`.

## Location and sync (read before running anything)

Build on a local disk, not a network share: the JS frontend toolchain fails to run from a
share (`npm install` EPERMs executing esbuild, and `node_modules` can't be junctioned there).

- Rust build output: `CARGO_TARGET_DIR=%LOCALAPPDATA%\Remotino\target` (set per shell).
- Cross-platform work syncs over `git`; see `README-OSX.md` for macOS setup.

## Read these first

| File | What it holds |
|---|---|
| `DESIGN.md` | Architecture, crypto, storage, decisions log, open questions |
| `spikes/rdp/RESULTS.md` | Live findings from the RDP viability spike |
| `spikes/rdp/README.md` | Spike protocol, 15-row checklist, GO/NO-GO bar |
| `CRYPTO.md` | How the crypto works, with diagrams and end-to-end use cases |
| `SQL-SETUP.md` | Standing up SQL Server Express for a shared repository |
| `README-OSX.md` | macOS setup: Rust, toolchain selection, troubleshooting |

## Where the project actually is

**Phase 0 answered its question: yes, IronRDP can be the single cross-platform RDP
engine.** Every check capable of overturning the architecture has passed, so the
platform-split fallback (mstsc + FreeRDP, ~3-4 extra weeks and two input/clipboard
implementations forever) is off the table.

Verified against a real Windows 11 host on LAN, and on macOS arm64:

- Connect, TLS, **CredSSP/NLA**, graphics decode: pass on both platforms
- Latency: acceptably fast on LAN
- **Dynamic resize** via Display Control channel: works, no reconnect, both platforms
- RemoteFX: supported and on by default. No H.264 - low impact on LAN
- **macOS arm64 (row 13): PASS** - built and rendered a correct desktop
- Clipboard-only is **structural** - virtual channels are compile-time features, so
  omitting `rdpdr` means no drive-redirection code exists at all

7 of 15 rows done. The two failures are **clipboard (rows 7-8), on both platforms**: no
macOS backend exists upstream, and on Windows the backend is never message-pumped. Neither
is architectural; budget ~1 week in Phase 4. See `spikes/rdp/RESULTS.md`.

Row 1 (Windows Server) is **assumed, not tested** - no Server host was available.

## Decisions that are settled

- **Embedded RDP, not a launcher** - decided on credential custody, not the tab UI. A
  launcher must hand passwords to a process we do not control, and macOS offers no
  supported way to do it at all. `DESIGN.md` 8.5
- **SQL Server only, no file backend** - makes append-only server-enforced rather than a
  convention, and deleted segment writing, snapshots and Spike B. `DESIGN.md` 3
- **LocalDB for single seat, Express for shared**, migration by log replay
- **Escrow: admin and escrow-holder are separate roles**, quorum grows 1-of-1 -> 2-of-3
  without re-wrapping content keys. `DESIGN.md` 9.4a
- **No RSA.** Ed25519 + X25519 + XChaCha20-Poly1305 + Argon2id. `CRYPTO.md` 2

## Phase 1: crates/remotino-crypto

I/O-free crypto core. 39 tests, clippy clean under lints that deny
unwrap/expect/panic/indexing/overflow in library code - it parses data written by other
people, so a panic there is a remote crash.

Modules: `kdf`, `identity`, `envelope`, `chain`, `escrow`, `repository`.

**Not independently reviewed.** `DESIGN.md` 7 asks for review before anything is built on
top; that still stands.

Build output must land on a local disk, not a network share:

```powershell
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Remotino\target"
```

## Two upstream bugs found and patched

Both in glue code, not the protocol stack. Kept in `spikes/rdp/patches/` because the
`.work/` clone is disposable.

1. `0001-screenshot-windows-timeout.patch` - the example matched only `WouldBlock`, but a
   Windows socket timeout is `WSAETIMEDOUT` -> `TimedOut`, so its intended exit path never
   fired and it errored instead of saving the image.
2. `0002-restore-bulk-decompressor-on-reactivation.patch` - the client dropped the bulk
   decompressor on every Deactivation-Reactivation Sequence while still advertising
   compression, so resizing a window crashed the session. **Builds clean but is not yet
   verified at runtime** - needs an interactive resize with compression left ON.

## Working agreements

- **Verify against real output, never source-reading or memory.** Run `--help`, check the
  docs, run the thing. Three flag/API mistakes were made this way early on.
- **`.ps1` files: ASCII-only, UTF-8 *with* BOM.** Windows PowerShell 5.1 reads BOM-less
  files as cp1252, and a UTF-8 em-dash decodes to a smart quote that PowerShell accepts as
  a string delimiter - the file then fails to parse with misleading errors.
- **`.sh` files: LF endings, *no* BOM.** A BOM breaks the shebang.
- Never write a file from a variable without checking it is non-empty first. An unchecked
  read-then-write truncated `run-spike.ps1` to 3 bytes.
- The spike is throwaway. Do not build product code on it.
- IronRDP is pinned to `079b48422b0b78d37beb76994950a2a07c442a94`. Keep it pinned so
  failures are attributable.

## Toolchain

Windows and macOS both need: Rust >= 1.89, git, cmake (the viewer pulls opus via a
dev-dependency). Windows additionally needs MSVC Build Tools; macOS needs Xcode CLT.

```powershell
.\spikes\rdp\run-spike.ps1 -Step setup          # Windows
.\spikes\rdp\test-rdp.ps1 -RdpHost <h> -Username <u>
```

```bash
./spikes/rdp/run-spike.sh setup                 # macOS - pins the same commit,
./spikes/rdp/run-spike.sh screenshot <h> <u>    # auto-applies both patches
```

## How to run it

`runtest.bat` (double-click) builds the RDP sidecar and starts the app; `runtest-debug.bat`
adds `RDP_HOST_LOG=debug`. Or: `cd remotino-app && npm run tauri dev` after building
`rdp-host` into `%LOCALAPPDATA%\Remotino\target-rdp` (see `rdp-host/README.md`).

## Next steps

1. **Get `remotino-crypto` reviewed** by someone who does crypto - still the hard gate
   before commercialization. The vault (seal-to-self content key, credential events) and the
   move/re-seal logic are new surface since the last review ask.
2. **Verify the credential auto-fill against a real host** - the login path (password and
   SSH publickey auth) mirrors the working manual path but has only been exercised through
   the manual flow; a linked connection connecting hands-free needs a live SSH/RDP target.
3. **Phase 6 - multi-user: working end to end.** The app points at a shared SQL Server
   (`SqlRepo` via `ThreadedRepo`), enrols users by public identity, and grants/revokes
   folders *and* credentials (per-credential content keys, `CredentialGranted`/`Revoked`,
   mirroring the folder ACL). SQL-login passwords are sealed to the identity (6c). Still
   open: key rotation on revoke (forward-only today), and the escrow/quorum admin UI.
4. **RDP polish (Phase 4 tail):** clipboard (~1 week, the spike's estimate), remote cursor
   rendering, TLS cert (TOFU) pinning - currently accept-all - and Kerberos (NTLM only now).
5. Decide whether `action` strings should move into the encrypted payload - currently
   cleartext, so a store compromise leaks the shape of activity (`SQL-SETUP.md` 8).
6. Remaining spike rows: reconnect, AltGr, concurrent sessions, and row 1 on a real Windows
   Server host when one exists.
