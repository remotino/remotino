# 1 · First run

## Install

Remotino is portable. Unzip the build and keep the two files together:

- `remotino-app.exe` — the app
- `rdp-host.exe` — the RDP engine (the app launches it; it must sit next to the app)

Double-click `remotino-app.exe`. On Windows 11 nothing else is needed; on Windows 10,
if the window is blank, install Microsoft's *Evergreen WebView2 Runtime*.

## Create your identity

On first launch you'll be asked to **create a new identity**. Choose a strong
passphrase.

- Your passphrase unlocks a key pair that seals everything you store. It is
  **never saved and never sent** — not to us, not to any server.
- If you forget it, there is no reset: no one else can decrypt what only your
  identity could read. Keep it somewhere safe (a password manager).

Each launch you unlock with that passphrase. The fingerprint shown on the unlock
screen is your identity's public fingerprint — teammates use it to grant you
access later.

By default Remotino stores everything **on this machine** (a local encrypted
store). No server is required to start.

## Add connections

- **New folder / new connection** from the tree or the toolbar. Folders nest;
  drag items to reorganise, even at thousands of entries.
- A connection has a **kind** (RDP or SSH), a **name**, a **host**, and a **port**.
- Press <kbd>Ctrl</kbd>+<kbd>K</kbd> (⌘K on macOS) for the **command palette** to
  jump to any host, and use the filter box to narrow the tree instantly.

Open a connection to get an embedded session in a tab:

- **RDP** — a real Windows desktop in the tab. Dynamic resize, remote cursor, and
  a **Ctrl+Alt+Del** button (the OS won't let that arrive as a keystroke). A small
  green badge flashes the desktop resolution when you resize.
- **SSH** — a live terminal.

## The credential vault

Rather than typing a password every time, store it once in the vault and link it
to connections:

1. Open the **credential** editor and add a password or an SSH private key. Give
   it a name, username, and (for RDP) an optional domain.
2. Link a connection to that credential. On connect, Remotino fills it in
   automatically.

Each credential is sealed under **its own key**. The secret is decrypted only
inside the app's backend at connect time — it never reaches the on-screen UI, and
it never sits inside a connection definition (only a reference to it does).

## Where to next

When you're ready to share with a team, move to a shared backend:
[2 · Setting up a shared backend](02-shared-backend.md).
