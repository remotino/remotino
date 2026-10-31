# SQL Server setup for the shared deployment

Standing up SQL Server Express for a shared Remotino repository, without a domain.

Single-seat installs need none of this - they use bundled LocalDB (`DESIGN.md` 3).

---

## 1. Install

Install **SQL Server Express** on the machine that will host the repository (a NAS or a
small always-on server).

During setup:

- **Authentication mode: Mixed Mode.** Required - without a domain there is no Windows
  identity for other machines to present, so per-user logins must be SQL Authentication.
- Set a strong `sa` password when prompted. You are about to disable the account, but it
  needs a password in the meantime and a weak one is a live risk in that window.
- Instance name: the default `SQLEXPRESS` is fine.

---

## 2. Replace `sa` with a named administrator

`sa` is the first account every scanner and brute-force tool tries, precisely because the
name is fixed and universal. Renaming and disabling it removes that free target.

Connect locally with SSMS or `sqlcmd`, then:

```sql
-- 1. A dedicated administrator under a non-obvious name.
CREATE LOGIN [remotino_dba]
    WITH PASSWORD    = N'<long random passphrase>',
         CHECK_POLICY = ON;

ALTER SERVER ROLE sysadmin ADD MEMBER [remotino_dba];
GO

-- 2. Verify it works BEFORE disabling sa. Open a new connection as remotino_dba and run:
--       SELECT IS_SRVROLEMEMBER('sysadmin');   -- must return 1
--    Do not proceed until this succeeds, or you can lock yourself out.

-- 3. Now retire sa.
ALTER LOGIN [sa] DISABLE;
GO

-- 4. Optional but worth doing - rename it so the well-known name is gone entirely.
ALTER LOGIN [sa] WITH NAME = [disabled_legacy_admin];
GO
```

> **Do step 2 properly.** Disabling `sa` without a verified replacement leaves an instance
> nobody can administer. Recovery means single-user mode and is unpleasant.

Store `remotino_dba`'s password in a password manager, **not** in Remotino - it is the
credential that could rebuild the repository, so it must not depend on the repository.

### Least privilege, if you want to go further

`sysadmin` is more than the migration wizard needs. After the database exists, a
provisioning account with `dbcreator` + `securityadmin` and `db_owner` on the Remotino
database is sufficient, and limits the damage if that credential leaks. Optional; use
`remotino_dba` for setup either way.

---

## 3. Enable network access

Express **does** accept remote connections - TCP/IP simply ships disabled, which makes a
fresh install look as though it is licensed not to.

1. Open **SQL Server Configuration Manager**
2. *SQL Server Network Configuration* -> *Protocols for SQLEXPRESS* -> enable **TCP/IP**
3. Open TCP/IP properties -> *IP Addresses* tab -> scroll to **IPAll**:
   - clear **TCP Dynamic Ports** (leave it empty)
   - set **TCP Port** to `1433`, or another fixed port
4. **Restart the SQL Server service** - protocol changes are ignored until it restarts
5. Leave **SQL Browser** disabled

A static port means one firewall rule, no extra service, no UDP name resolution, and a
client config that reduces to `host,port`. With SQL Browser you would instead need UDP
1434 open and the service running.

Firewall:

```powershell
New-NetFirewallRule -DisplayName "SQL Server (Remotino)" `
    -Direction Inbound -Protocol TCP -LocalPort 1433 `
    -Action Allow -Profile Domain,Private
```

Restrict `-RemoteAddress` to your LAN range if the host is exposed to anything wider.

Verify from a client machine:

```powershell
Test-NetConnection -ComputerName <host> -Port 1433
```

---

## 4. Create the database

```sql
CREATE DATABASE [Remotino];
GO

ALTER DATABASE [Remotino] SET RECOVERY FULL;
GO
```

`FULL` recovery so point-in-time restore is possible. The audit chain proves history was
not *altered*; it cannot recover a database that was deleted, so backups remain your
availability story.

The migration wizard (`DESIGN.md` 3) creates the schema, roles and per-user logins. The
statements below are what it runs, recorded here so the setup is auditable by hand.

```sql
USE [Remotino];
GO

CREATE TABLE dbo.Events (
    seq         BIGINT         NOT NULL PRIMARY KEY,
    prev_hash   BINARY(32)     NOT NULL,
    entry_hash  BINARY(32)     NOT NULL,
    actor       BINARY(32)     NOT NULL,
    signature   BINARY(64)     NOT NULL,
    body        VARBINARY(MAX) NOT NULL,
    written_at  DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
);
CREATE UNIQUE INDEX IX_Events_entry_hash ON dbo.Events(entry_hash);
GO

CREATE TABLE dbo.Identities (
    key_id      BINARY(32)     NOT NULL PRIMARY KEY,
    public_blob VARBINARY(MAX) NOT NULL
);
GO

CREATE TABLE dbo.Vaults (
    key_id      BINARY(32)     NOT NULL PRIMARY KEY,
    sealed_blob VARBINARY(MAX) NOT NULL
);
GO

CREATE ROLE remotino_user;
GRANT SELECT, INSERT ON dbo.Events     TO remotino_user;
DENY  UPDATE, DELETE ON dbo.Events     TO remotino_user;
GRANT SELECT, INSERT ON dbo.Identities TO remotino_user;
DENY  UPDATE, DELETE ON dbo.Identities TO remotino_user;
GRANT SELECT, INSERT, UPDATE ON dbo.Vaults TO remotino_user;
GO
```

**`DENY UPDATE, DELETE` on `dbo.Events` is the whole reason this project uses SQL Server.**
It turns append-only from a convention clients follow into a constraint they cannot
violate, which converts the truncation defence from detection into prevention
(`CRYPTO.md` 8). Do not grant it away for convenience.

### Verify the DENY actually binds

Do not assume it. `EXECUTE AS USER` tests the role's real permissions without needing a
login or mixed-mode authentication:

```sql
CREATE USER remotino_test WITHOUT LOGIN;
ALTER ROLE remotino_user ADD MEMBER remotino_test;

EXECUTE AS USER = 'remotino_test';
    INSERT INTO dbo.Events (...) VALUES (...);   -- expect: allowed
    UPDATE dbo.Events SET body = 0x99 ...;       -- expect: DENIED
    DELETE FROM dbo.Events ...;                  -- expect: DENIED
REVERT;

DROP USER remotino_test;
```

Verified on SQL Server 2022 Express (16.0.1190.2), 2026-07-21:

```
INSERT: ALLOWED
UPDATE: BLOCKED -> The UPDATE permission was denied on the object 'Events'
DELETE: BLOCKED -> The DELETE permission was denied on the object 'Events'
```

Worth re-running after any permission change, and on the production instance before it
holds anything real.

---

## 5. Per-user logins

One login per user. **Never a shared application login**: a shared credential sits in every
client's config, any user can extract it, and they would then hold whatever rights it
carries.

```sql
CREATE LOGIN [remotino_alice] WITH PASSWORD = N'<generated>', CHECK_POLICY = ON;

USE [Remotino];
CREATE USER [remotino_alice] FOR LOGIN [remotino_alice];
ALTER ROLE remotino_user ADD MEMBER [remotino_alice];
GO
```

The wizard generates the password randomly and **seals it to that user's X25519 public
key**, so it travels with enrolment and needs no out-of-band delivery. The user never sees
or types it - their passphrase unlocks the identity, which decrypts the SQL password,
which opens the connection.

Because content is end-to-end encrypted, a leaked SQL password is low-stakes: it yields
ciphertext and an append-only grant. It is an access boundary, not a confidentiality
boundary, so rotation is routine rather than an incident.

---

## 6. Connection security

Clients connect with `Encrypt=True` and the server certificate pinned.

Express installs with a self-signed certificate, which is fine for a LAN provided the
client **pins** it rather than blindly trusting it. Do not ship
`TrustServerCertificate=True` - that accepts any certificate and reintroduces the
man-in-the-middle risk TLS was there to remove.

---

## 7. Backups

The audit chain detects tampering; it does not restore a deleted database.

```sql
BACKUP DATABASE [Remotino]
    TO DISK = N'<path>\Remotino.bak'
    WITH INIT, CHECKSUM, COMPRESSION;
```

Schedule it, and **test a restore at least once** - an untested backup is a belief, not a
backup. Note that backups contain the same ciphertext as the live database, so they are no
more sensitive than it is; they still need protecting against deletion.

---

## 8. What an attacker with database access actually sees

Worth being precise, because "it is all encrypted" is not quite true.

**Encrypted - unreadable:**

- entry payloads: hostnames, usernames, credentials, folder contents
- vault contents

**Not encrypted - readable metadata:**

- `actor` on every entry: which identity made each change
- `written_at`: when, and therefore activity patterns and working hours
- entry counts, sizes, growth rate
- `Identities`: how many users exist, and their public keys
- `action` strings such as `AclGranted` or `EscrowRecoveryPerformed`

So a database compromise leaks **the shape of your activity, not its content**. An attacker
learns how many folders and users exist and when things changed; they do not learn a single
hostname, username or password.

They also cannot **alter** history: every entry is signed, and a modification breaks the
chain. Under `DENY UPDATE, DELETE` they cannot rewrite rows at all unless they have
compromised an administrator account rather than a user one.

See `DESIGN.md` 6 for the full threat model.

---

## 9. Future: domain authentication

Not required now - there is no domain. Recorded so the design does not preclude it.

If Remotino is later deployed into an Active Directory environment, Windows Authentication
becomes preferable to SQL Authentication:

- no per-user SQL password to generate, seal, or rotate
- account lifecycle follows AD, so a disabled AD account loses database access immediately
- Kerberos rather than passwords on the wire

The change would be contained: the connection layer switches to integrated authentication
and the sealed-SQL-password mechanism becomes unnecessary. **Everything above that layer is
unaffected** - identities, envelope encryption, the audit chain and escrow are independent
of how the database connection is authenticated.

Design implication to preserve: keep database authentication behind the `Repository`
implementation, never leaking a SQL credential concept into the crypto core or the UI.
Doing so now costs nothing and keeps that door open.
