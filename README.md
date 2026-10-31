# Remotino

**An encrypted RDP & SSH connection manager where the server never holds your secrets in the clear.**

Remotino is a cross-platform remote-connection manager (Windows & macOS, plus an SSH-only
terminal client) built around client-side encryption. Credentials and connection details are
sealed on your machine before they ever reach storage — access is enforced by keys, not by
rules a database could be tricked into ignoring — and every change is recorded in a
tamper-evident, append-only audit log.

> **Status:** pre-1.0, in active development. The desktop app runs end to end — identity &
> vault, the connection tree, live **SSH** (russh) and embedded **RDP** (IronRDP), credential
> sharing, a shared multi-user **SQL Server** backend with in-app setup, and a tamper-evident
> audit view. The cryptographic core is designed for an independent review, which is a gate
> before a 1.0 — see [Security](#security).

---

## Why it's different

- **Zero-trust storage.** The backend only ever sees ciphertext. Sharing a folder or
  credential means wrapping its content key to a teammate's public key, so "who can read
  this" is a property of the keys, not an ACL the server enforces. A store compromise yields
  encrypted blobs, not passwords.
- **Embedded, not a launcher.** RDP and SSH render inside the app. The credential is unsealed
  in memory and used to authenticate — it is never handed to an external client you don't
  control.
- **Tamper-evident.** Every change is a signed link in an append-only hash chain, and (on the
  SQL backend) the database itself denies `UPDATE`/`DELETE` on the log. Rewriting history is
  cryptographically detectable — and blocked at the source.
- **Fast.** Built to stay responsive at thousands of entries.

## Features

- **RDP + SSH** in one tabbed window — dynamic resize, remote cursor, Ctrl+Alt+Del, clipboard.
- **Credential vault** — passwords and SSH keys, each under its own key; auto-fills on connect.
- **Sharing** — grant a folder or a single credential to an enrolled user, by public key; revoke it.
- **Multi-user over SQL Server** — a shared append-only repository with per-user
  least-privilege logins; database setup and login provisioning done from the GUI (no SSMS),
  and per-user passwords handed over as "setup codes" safe to send over chat.
- **Audit log** — who did what and when, with a live chain-integrity check.
- **Terminal client** — `remotino-tui`, an SSH-only TUI over the same encrypted vault.
- **Modern crypto only** — Ed25519, X25519, XChaCha20-Poly1305, Argon2id. No RSA, no shared
  application login.

## Repository layout

| Path | What it is |
|---|---|
| `crates/remotino-crypto` | I/O-free crypto core (identity, envelopes, hash chain, escrow) |
| `crates/remotino-model` | Event sourcing: events, structural fold, decrypted projection |
| `crates/remotino-sql`, `-store`, `-cache` | SQL Server + local SQLite backends |
| `remotino-app` | The desktop app (Tauri + SvelteKit) |
| `rdp-host` | The RDP engine, a separate process (its own pinned dependency stack) |
| `remotino-tui` | The terminal SSH client |

The RDP engine is a **separate process** on purpose: IronRDP's CredSSP stack pins a
pre-release crypto snapshot that cannot share a binary with the app's stable one. See
[`rdp-host/README.md`](rdp-host/README.md).

## Building & running

- **Windows** — build the sidecar into `%LOCALAPPDATA%\Remotino\target-rdp`, then
  `cd remotino-app && npm run tauri build`. `runtest.bat` runs a dev build. See
  [`DEPLOY.md`](DEPLOY.md).
- **macOS** — one command: [`./build-osx.sh`](build-osx.sh) builds the sidecar + app and
  bundles them. Needs Rust ≥ 1.89, Node, Xcode CLT, cmake. See [`README-OSX.md`](README-OSX.md).
- **Terminal client** — `cargo build --release -p remotino-tui`, then run `remotino`.

## Security

The design keeps the storage layer untrusted throughout:

- **Identity** — Ed25519 signing + X25519 wrapping, sealed at rest with Argon2id.
- **Content** — XChaCha20-Poly1305 under per-folder and per-credential keys.
- **Sharing** — content keys wrapped to a recipient's public key (ECIES).
- **Audit** — a signed hash chain; append-only is server-enforced.

The crypto lives in `crates/remotino-crypto` and is meant to be read. It has **not yet had an
independent cryptographer review** — that is a gate before 1.0, not a claim of certification.
Deeper detail is in [`CRYPTO.md`](CRYPTO.md) and [`DESIGN.md`](DESIGN.md).

**Reporting a vulnerability:** see [`SECURITY.md`](SECURITY.md) — please email
`security@remotino.app`, don't open a public issue.

## License

To be finalized before the first public release. Until then, all rights reserved.
