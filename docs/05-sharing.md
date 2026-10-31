# 5 · Sharing folders & credentials

Sharing in Remotino is cryptographic. Granting a folder or a credential **wraps
its content key to the recipient's public key**, so "who can read this" is who
mathematically holds the key — not a flag the server enforces and could be
tricked into ignoring.

You can share with anyone you've [enrolled](04-adding-users.md).

## Share a folder

Right-click a folder in the tree and choose **Share…**. In the dialog:

- Toggle a user **on** to grant them the folder — they can now read its
  connections.
- Toggle **off** to revoke.

Granting a folder wraps that folder's key to the user. They see the folder and its
connections; sub-folders are granted separately.

## Share a credential

Right-click a connection's credential (or the credential in the vault) and choose
**Share…**. Granting wraps that credential's key to the user, so they can **use it
to connect** — the secret is still only ever decrypted inside their app at connect
time, never shown.

This is how a teammate connects to a host "hands-free" without you ever telling
them the password: they get the credential's key, not the password text.

Shared items are marked with a small **shared** tag in the tree.

## Revoking

Revoke from the same **Share…** dialog by toggling the user off.

**Revocation is forward-only.** It stops the user from reading *future* changes,
but you should treat anything they already had access to as known to them — they
may have copied it. For a credential that must be truly retired, rotate the
secret (change the password / key on the host) after revoking.

## What a compromised server sees

Nothing useful. The shared database holds:

- encrypted folder names and connection details,
- content keys **wrapped to public keys** (unusable without the matching private
  half, which never leaves a user's machine),
- a signed, append-only audit chain.

Compromise the database and you get ciphertext and the *shape* of activity — never
a password or a readable connection.

## Auditing

The toolbar's **audit log** shows every change to the repository — when, who, and
a plain-English action — newest first. It re-walks the signed hash chain and shows
a **Chain intact** badge, flipping to **Tampering detected** if any row was
deleted, reordered, or edited.
