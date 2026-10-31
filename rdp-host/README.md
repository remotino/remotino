# rdp-host — the RDP sidecar

A standalone binary that owns one RDP session. The Tauri app spawns it per RDP tab and talks
to it over stdio.

## Why it's a separate binary (and its own workspace)

IronRDP's CredSSP/NLA path (`sspi` → `picky`) exact-pins a **pre-release** RustCrypto
snapshot (`curve25519-dalek =5.0.0-rc.1`, `ecdsa =0.17.0-rc.22`, …). The main app's `russh`
+ `remotino-crypto` pin the **stable** releases of those same crates. Cargo unifies versions
across one lockfile, so the two stacks cannot share a binary.

Rather than vendor-fork the whole Devolutions crypto stack, the RDP engine lives here as its
own process with its own `Cargo.lock` — each stack pinned independently. This is the project
convention for engines with incompatible dependency stacks.

## Protocol (stdio)

- **stdin** — newline-delimited JSON. First line is the connect request
  (`{host, port, username, password, domain?, width, height}`); every line after is an input
  event (`m_move`, `m_btn`, `m_wheel`, `key`, `resize`).
- **stdout** — length-prefixed binary: `[u32 len][u8 kind][payload]`.
  `1` FRAME `[u16 x,y,w,h][rgba…]` · `2` SIZE `[u16 w,h]` · `3` STATUS (utf-8).
- **stderr** — logs (`RDP_HOST_LOG=debug` to raise the level).

The password is read from stdin, never logged, never echoed.

## Build

Its own workspace, so build it directly (keep the target dir on a local disk):

```powershell
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Remotino\target-rdp"
cargo build --manifest-path rdp-host/Cargo.toml
```

## Status / not done yet

- Host key / TLS cert is **accept-all** (`NoCertificateVerification`) — TOFU pinning is later
  hardening.
- CredSSP uses NTLM only; the `NetworkClient` is a stub, so **Kerberos** KDC round-trips are
  not supported yet.
- Bulk compression is intentionally **not advertised** (broken upstream on reactivation; the
  spike confirmed dynamic resize is stable with it off). RemoteFX is negotiated regardless.
- Clipboard (`cliprdr`) is not wired — the spike budgeted ~1 week for it in Phase 4.
- Not yet spawned/bundled by the app; that wiring + a canvas frontend are the next step.
