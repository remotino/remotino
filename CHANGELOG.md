# Changelog

Notable changes to Remotino, newest first.

From 0.1.0 the Windows build ships as an **MSI installer** and uses **semantic versioning**;
earlier builds (0001–0009) were portable zips numbered by build. The `dist/NNNN/` folder
numbering continues internally, each with its own detailed `CHANGELOG.md`. The macOS build is
produced by `./build-osx.sh` and stamped with its git commit.

## 0.1.0 (build 0010)
- **Windows MSI installer**, replacing the portable zip — per-machine install into
  `Program Files\Remotino`, a Start-menu entry, an uninstaller, and the `rdp-host.exe` sidecar
  bundled inside (no loose files). Unsigned for now (SmartScreen warns on first run).
- **Product identity** — product name **Remotino**, identifier **`sk.tibtech.remotino`**.
- **Semantic versioning** (starting 0.1.0) so MSI in-place upgrades work.

## 0009
- **Fix — provisioning from the Users panel used the wrong backend.** The "Setup code" button
  next to an enrolled user opened the database-admin dialog in **SQL Server** mode even when
  the shared backend was **Postgres**, so it spoke the wrong protocol at the server
  (`failed to fill whole buffer`) and dropped the TLS pin. The dialog now resolves the real
  backend, connection details and Postgres TLS pin from the saved profile from either entry
  point.

## 0008
- **Local → shared bookmark migration.** Switching from the local store to a shared
  MSSQL/Postgres backend offers to bring your folders, connections and vault credentials
  along. It's a re-encrypted *replay* onto the shared hash chain (fresh ids, hierarchy and
  credential links preserved); your local store is left untouched, and it refuses to migrate
  into a shared database that already has entries.
- **RDP resolution badge.** On resize, a brief `host · WIDTH×HEIGHT` readout flashes in the
  bottom-right corner, then fades.

## 0007
- **PostgreSQL backend**, at parity with SQL Server (initialize, per-user login provisioning,
  setup codes, reset). Append-only is enforced two ways: role grants *and* a trigger that
  rejects UPDATE/DELETE/TRUNCATE on the event log.
- **TLS with trust-on-first-use certificate pinning** for Postgres. Approve the server
  certificate once by its SHA-256 fingerprint; any later change is refused, and the pin
  travels inside setup codes.

## 0006
- **Audit log view** — who did what, when, newest first, re-walked against the signed hash
  chain with a *Chain intact* / *Tampering detected* verdict.
- **macOS build fixes** — builds on macOS (Windows-only integrated auth gated), macOS RDP
  text clipboard (NSPasteboard), a one-command `build-osx.sh`, and no console pop-up on RDP
  connect (Windows).

## 0005
- **Reset database keeps you signed in.** Dropping the database also dropped your login's
  database user, so a reset used to fail the next unlock with "cannot open database". Now a
  reset while unlocked with your own provisioned login re-provisions it into the recreated
  database and re-opens the session in place — no re-unlock, no re-setup.

## 0004
- **Reset database button.** Drop and recreate an empty shared schema from the app (admin
  sign-in required). Destructive, with a confirmation step — erases every user, folder,
  credential and audit event for everyone on that database.

## 0003
- **No console pop-up on RDP connect.** The RDP engine is launched with `CREATE_NO_WINDOW`.

## 0002
- **Larger default window** (1080×800) so all settings fit without resizing.

## 0001 — first packaged multi-user / shared-SQL build
- **Credential sharing** — share individual vault credentials, not just folders; each has its
  own key, and sharing wraps it to the recipient. Granted items show a **shared** tag.
- **SQL-login passwords sealed to your identity** (6c) — stored as an ECIES wrap, decrypted
  only at unlock.
- **In-app SQL setup** — initialize the database and provision per-user least-privilege logins
  from the GUI; no SSMS.
- **Setup codes** — hand a provisioned login to another user as one self-contained string,
  safe to send over chat (the password is sealed to the recipient's key).
- **Auto-publish** for bidirectional sharing; an **over-privileged-login warning** if a login
  could rewrite the audit log.
- **Reset app**, no demo data, and an RDP fix for the stuck Windows key on focus loss.

---

Earlier phases (the crypto core, the event-sourced signed chain, embedded RDP via IronRDP,
SSH via russh, the connection tree and credential vault) predate the packaged builds — see
`DESIGN.md` and the git history.
