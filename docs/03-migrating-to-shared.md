# 3 · Bringing your local bookmarks along

If you've been using Remotino on **This machine** and then switch to a shared
MSSQL/Postgres backend, your existing folders, connections and vault credentials
are in the *local* store — the shared database starts empty.

So when you save a switch from local to a shared backend and you have local
entries, Remotino asks:

> **Bring your bookmarks along?**
> Your local store has *N connections, M credentials and K folders*. Copy them
> into the shared database so it isn't empty?
>
> **[ Start fresh ]  [ Bring them along ]**

- **Bring them along** copies everything into the shared repository, then reopens
  on it.
- **Start fresh** switches to the empty shared repository and leaves your local
  store as-is.

## What actually happens

The local store and the shared database are **two separate signed hash chains**,
so raw entries can't simply be transplanted (their positions and links belong to
the local chain). Instead Remotino **replays** them:

- It decrypts your local tree and vault with your unlocked identity.
- It re-creates each folder, connection and credential as **new events** on the
  shared chain, with fresh ids and freshly-sealed content.
- Folder hierarchy is preserved, and connections keep their link to the
  credential they used.

Your **local store is left untouched** — nothing is deleted. If you ever switch
back to *This machine*, it's all still there.

## Notes and limits

- **One-way, into an empty repository.** Migration refuses if the shared database
  already has entries (so it can never duplicate a tree). It's meant for the
  admin populating a fresh shared repository, not for merging.
- **Your vault comes too.** Your personal credentials are re-created in the shared
  repository, still sealed to you alone. Sharing them with others is a separate,
  explicit step — see [5 · Sharing](05-sharing.md).
- **Joining an existing shared team?** If a colleague already set up and populated
  the shared database, choose **Start fresh** — you'll get access to shared
  folders as they're granted to you. Trying to migrate into a populated database
  is refused.
