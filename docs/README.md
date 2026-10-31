# Remotino — User Guide

Remotino is an encrypted RDP & SSH connection manager. Your connections and
secrets are sealed on your machine before they ever reach a server, so the
backend only ever holds ciphertext — access is enforced by keys, not by rules a
database could be tricked into ignoring.

These guides walk through the common tasks, in order.

| Guide | What it covers |
|---|---|
| [1 · First run](01-first-run.md) | Creating your identity, adding connections, the credential vault |
| [2 · Setting up a shared backend](02-shared-backend.md) | Moving your team onto a shared MSSQL Server or PostgreSQL repository |
| [3 · Bringing your local bookmarks along](03-migrating-to-shared.md) | Copying your existing connections into the shared database |
| [4 · Adding users](04-adding-users.md) | Enrolling teammates and handing out per-user logins |
| [5 · Sharing folders & credentials](05-sharing.md) | Granting and revoking access, cryptographically |

## Key ideas in one minute

- **Your identity** is a key pair unlocked by your passphrase. The passphrase is
  never stored or sent; losing it means losing access to what only you could read.
- **Local vs shared.** Solo, everything lives in an encrypted store on your
  machine. For a team, point Remotino at a shared **MSSQL Server** or
  **PostgreSQL** database — but that database only ever sees encrypted blobs.
- **Sharing is cryptographic.** Granting a folder or credential wraps its key to
  a teammate's public key. "Who can read this" isn't a server setting — it's who
  mathematically holds the key.
- **The log is append-only.** Every change is a signed link in a hash chain, and
  the database itself refuses to update or delete rows. Tampering is both blocked
  and detectable (see the Audit view).
