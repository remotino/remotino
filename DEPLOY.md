# Deploying a built Remotino

A finished Remotino install is **two files that live next to each other**:

- `remotino-app.exe` — the app (frontend is embedded; nothing else to ship).
- `rdp-host.exe` — the RDP engine the app spawns. The app looks for it *next to its own
  executable* first, so as long as they're in the same folder it just works.

No dev toolchain, Node, or Rust is needed on the target machine.

---

## Windows (x64)

### What's in the package

A `Remotino-win64` folder containing `remotino-app.exe` + `rdp-host.exe`. Copy the whole
folder to the target machine and run `remotino-app.exe`. That's it.

### Requirement: WebView2

The UI renders in Microsoft's WebView2 runtime.

- **Windows 11** — built in, nothing to do.
- **Windows 10** — usually already present (it ships with Edge). If the window comes up blank,
  install the "Evergreen WebView2 Runtime" from Microsoft (a small, free bootstrapper).

### First run on the target

1. Launch `remotino-app.exe`, click **Connection settings**, choose **Shared SQL Server**, and
   enter the server + database. For a second user, pick **SQL login** and enter that user's
   SQL credentials (see `SQL_USER_SETUP.md`).
2. Save (the app locks), then **create a new identity** — this is that user's own identity,
   separate from yours.
3. Give an admin your **Users → your identity** string so they can enrol you and share folders.

### Rebuilding the Windows package

```powershell
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Remotino\target-rdp"
cargo build --release --manifest-path rdp-host\Cargo.toml

$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Remotino\target"
cd remotino-app
npm run tauri build -- --no-bundle
```

Then put `…\target\release\remotino-app.exe` and `…\target-rdp\release\rdp-host.exe` in one
folder. (`--no-bundle` skips the MSI/NSIS installer; drop it, and add WiX/NSIS, if you want a
real installer instead of a portable folder.)

---

## macOS (Apple Silicon)

**This must be built on a Mac** — Tauri's macOS build needs the Apple toolchain and can't be
cross-compiled from Windows. The spike already proved IronRDP renders correctly on macOS
arm64, and the code is cfg-gated to compile there. **RDP text clipboard now works on macOS
too** (NSPasteboard via `arboard`), sharing one CLIPRDR backend with the Windows path.

On the Mac (Rust ≥ 1.89, Node, Xcode CLT, cmake):

```bash
git clone <the bare repo>            # see README-OSX.md
cd Remotino
./build-osx.sh                       # one command: sidecar + app + bundle it all together
```

`build-osx.sh` builds the RDP sidecar, builds the `.app`, and copies the sidecar inside the
bundle. It prints the path when done — typically:

```
target/release/bundle/macos/remotino-app.app
```

That `.app` is self-contained (the app finds `rdp-host` next to its own executable, which
inside a `.app` is `Contents/MacOS/`) — copy it wherever.

<details><summary>What the script does, if you prefer the manual steps</summary>

```bash
# 1. RDP sidecar (its own workspace)  -> rdp-host/target/release/rdp-host
cargo build --release --manifest-path rdp-host/Cargo.toml
# 2. App bundle (src-tauri is a workspace member, so the target is the repo-root target/)
(cd remotino-app && npm install && npm run tauri build)
# 3. Drop the sidecar inside the bundle
cp rdp-host/target/release/rdp-host \
   target/release/bundle/macos/remotino-app.app/Contents/MacOS/rdp-host
```
</details>

Unsigned app note: Gatekeeper will complain on first open. Right-click → **Open** once.
`build-osx.sh` already clears the bundle's quarantine flag; if you assembled the app by hand
(or moved/downloaded it), run `xattr -dr com.apple.quarantine remotino-app.app` yourself —
**this is required for RDP**, because a quarantined bundle silently *kills the spawned
`rdp-host` sidecar* (no prompt), which surfaces as an RDP tab that goes straight to red.
Proper signing/notarisation is a later step.

---

## What "finished deployment" still doesn't cover

- **No auto-update, no code signing.** Portable/unsigned for now.
- **RDP clipboard is text-only** on both platforms (no files/images).
- The independent **cryptographer review** is still the hard gate before real production use.
