# SQL Server logins for Remotino

Remotino's shared backend is a single append-only table, `dbo.Events`, in a database
(default name `remotino`). There are two kinds of login it needs:

- an **admin** login that can create the database and its schema, and
- a **per-user** login that can only read and append the chain — which is how the append-only
  guarantee becomes *server-enforced*, not a client convention.

## The easy path: do it from the app (no SSMS)

**Settings → Shared SQL Server → Set up / add users…** does all of this from the GUI:

1. **Initialize database** — enter admin sign-in (Windows integrated, or the `sa`/dbcreator
   SQL login) once; it creates the database, tables, the `remotino_user` role and its grants.
   The admin credential is used for that call only and never stored.
2. **Provision a login** — pick **Yourself** or an enrolled user, and the app creates a
   least-privilege SQL login with a random strong password **sealed to that user's identity**.
   - For yourself, it switches your own connection to that login automatically.
   - For another user, it produces a **setup code** — one string you send them. They paste it
     under **Settings → SQL login → I have a setup code**, and connect with no password to
     type. The sealed password inside only opens for their identity, so the code is safe to
     send over any channel.

The manual SQL below is the equivalent, for anyone who prefers SSMS or needs to audit exactly
what the app runs. Everything runs in SQL Server Management Studio (or `sqlcmd`) as a sysadmin.
Adjust the database name if you didn't use `remotino`.

> **Password storage note.** When you pick "SQL login" in Settings, the password is **sealed
> to your identity** (ECIES under the `sql-password` context) before it touches disk, so the
> `connection.json` file reveals nothing without unlocking, and it is decrypted only at
> unlock. If you configure SQL *before* an identity exists on that machine, the password sits
> in the clear for that brief interim and is upgraded to the sealed form on your first unlock.
> Integrated (Windows) auth stores no password at all.

---

## 1. Admin login (database + schema setup)

This login runs `CREATE DATABASE` and the schema migration. Membership in the `dbcreator`
server role is enough (it can create databases and owns what it creates); `sysadmin` also
works and is simpler on a throwaway LAN box.

```sql
-- Create the login (SQL authentication).
CREATE LOGIN remotino_admin WITH PASSWORD = 'CHANGE-ME-strong-password';

-- Let it create databases (and thus own + set up the Remotino database).
ALTER SERVER ROLE dbcreator ADD MEMBER remotino_admin;
```

Then in the app: **Settings → Shared SQL Server → Authentication: SQL login**, enter
`remotino_admin` + its password, and click **Test & initialize**. That creates the `remotino`
database (if missing) and applies the schema.

---

## 2. Per-user login (everyday access)

Each real user gets their own login with **SELECT + INSERT on `dbo.Events`** and **SELECT on
`dbo.SchemaVersion`** — and nothing else. No `UPDATE`/`DELETE`, so the append-only chain
cannot be rewritten from the client; no DDL, so they can't touch the schema.

Run this **once per user** (after the admin has created the database in step 1):

```sql
-- 2a. Server-level login.
CREATE LOGIN remotino_alice WITH PASSWORD = 'CHANGE-ME-her-password';

-- 2b. A database user for that login, inside the Remotino database.
USE remotino;
CREATE USER remotino_alice FOR LOGIN remotino_alice;

-- 2c. Exactly the rights the app needs: read + append the chain, read the schema version.
GRANT SELECT, INSERT ON dbo.Events        TO remotino_alice;
GRANT SELECT          ON dbo.SchemaVersion TO remotino_alice;
```

That user then opens the app, picks **Shared SQL Server → SQL login**, enters
`remotino_alice` + password, and unlocks with their own Remotino identity. They see only the
folders that have been **shared** with them (Users → enrol, then a folder's **Share…**);
everything else shows as *Restricted*.

To simulate a second person on one machine, create `remotino_alice` as above, create a second
Remotino identity (a separate app data dir, or a second machine), enrol its identity string,
and share a folder to it.

---

## 3. Removing a user

```sql
USE remotino;
DROP USER remotino_alice;      -- revokes their database access
DROP LOGIN remotino_alice;     -- removes the server login
```

Dropping the SQL login stops them connecting. Their past appends remain in the chain (it's an
audit log). To also cut off their *read* access to shared folders, revoke the folder in the
app (Share…) and, for cached content, rotate the folder key — forward-only revocation, per
`CRYPTO.md` 6.

---

## Prerequisites recap

- SQL Server reachable over **TCP** (not just Shared Memory / named pipes). `SQL-SETUP.md`
  covers enabling TCP and a static port on SQL Server Express.
- **Mixed Mode** authentication enabled on the server (SQL logins need it; integrated-only
  installs must switch to "SQL Server and Windows Authentication mode" and restart).
- The app requests TLS; on a self-signed Express certificate over a LAN, tick "Trust the
  server certificate" in Settings.
