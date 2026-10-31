# 4 · Adding users

Once a [shared backend](02-shared-backend.md) is set up, the admin gives each
teammate two things: an **enrolment** (so they can be granted access
cryptographically) and a **login** to the database (so they can connect to it).

## Step 1 — the teammate sends you their identity

The new user opens the **Users** panel (the people icon in the toolbar) and, under
**Your identity**, clicks **Copy**. They send that identity string to you (the
admin) — it's a public key, safe to send over any channel.

They should also set **Your display name** and it will be published automatically,
so you can share things *back* to them by name.

## Step 2 — enrol them

In your **Users** panel, under **Enrol a user**:

1. Type their **name** (e.g. `Bob`).
2. Paste their **identity string**.
3. Click **Enrol**.

They now appear under **Enrolled users**. Enrolling records who they are; it
doesn't yet give them a database login or any folders.

## Step 3 — give them a database login (a setup code)

Next to the enrolled user, click **Setup code**. Remotino:

- provisions a **least-privilege login** in the shared database for that user,
  with a strong random password **sealed to their identity**, and
- packages everything they need to connect — host, database, the sealed password,
  and (for Postgres) the TLS pin — into a single **setup code**.

Copy the code and send it to them. It's safe to send over chat: the sealed
password inside can only be opened by that user's identity.

## Step 4 — the teammate applies the code

The new user opens **Connection settings**, chooses the same backend
(**SQL Server** or **Postgres**), and on the login step clicks
**I have a setup code instead**, then pastes the code and clicks **Apply code**
→ **Save**.

They're now connected to the shared repository on their own least-privilege login.
At first they'll see only what's been shared with them — grant them folders and
credentials next: [5 · Sharing](05-sharing.md).

## Why two steps (enrol *and* a login)?

They're different layers, on purpose:

- **Enrolment** is about *cryptographic access* — it lets you wrap folder and
  credential keys to that person.
- **The database login** is about *reaching the store at all*, with least
  privilege (SELECT/INSERT only). Even with a login, a user can read only the
  ciphertext of folders they hold a key for.
