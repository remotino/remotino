# 2 · Setting up a shared backend

A shared backend lets a team work from one repository of connections and share
folders and credentials. Remotino supports **MSSQL Server** and **PostgreSQL**.
The database only ever holds encrypted blobs and a per-user, least-privilege
login — it is treated as untrusted storage, not a trusted authority.

You need this once, done by whoever administers the shared database.

## 1 · Point Remotino at the database

Open **Connection settings** and pick your backend:

- **This machine** — the local single-seat store (the default).
- **SQL Server** — a shared Microsoft SQL Server.
- **Postgres** — a shared PostgreSQL server.

Enter the **host**, **port**, and **database** name (for SQL Server, an optional
**instance**). The default port fills in for you (1433 for SQL Server, 5432 for
Postgres).

### TLS (Postgres)

For Postgres, tick **Require TLS**, then **Verify certificate**. Remotino reads
the server's certificate and shows its **SHA-256 fingerprint**, subject, issuer,
and validity. Compare the fingerprint with the server's out of band, then
**Trust this certificate**.

This is trust-on-first-use pinning (the SSH known-hosts model, not public
certificate authorities): you approve the exact certificate once, and any later
change to it is refused. The pin travels inside setup codes, so users you
provision automatically trust the same certificate.

## 2 · Initialize the database

Click **Set up / add users…** and sign in with admin rights **once** — nothing
here is stored:

- **SQL Server** — Windows (integrated) auth, or a `sa`-style SQL admin login.
- **Postgres** — a superuser (e.g. `postgres`) and its password.

Click **Initialize database**. Remotino creates the database if it's missing,
then the tables, a least-privilege `remotino_user` role, and its SELECT/INSERT
grants. Append-only is enforced by the database itself: any attempt to UPDATE,
DELETE or TRUNCATE the event log is rejected.

## 3 · Provision your own login

Still in the setup panel, under **Provision a login**, leave the target as
**Yourself** and click **Create login**. Remotino creates a least-privilege login
with a strong random password, **sealed to your identity** — no password is ever
shown or typed. It immediately switches your own connection to that login.

Click **Save**. The app locks and reopens on the shared backend.

> If you had connections in your local store, Remotino now asks whether to bring
> them along — see [3 · Bringing your local bookmarks along](03-migrating-to-shared.md).

## Next

- Give teammates access: [4 · Adding users](04-adding-users.md).
- Share folders and credentials: [5 · Sharing](05-sharing.md).

## Resetting

The setup panel also has **Reset database** — it drops and recreates the shared
repository (erasing everything, for everyone) and re-provisions your own login so
you stay signed in. Use it only to start a shared repository over from scratch.
