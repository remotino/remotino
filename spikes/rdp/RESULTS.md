# Spike A results

Fill this in **while testing**, not from memory afterwards.

## Already established (from the source + built binary, before any server test)

| Finding | Evidence | Consequence |
|---|---|---|
| Virtual channels are **compile-time features** (`sound`, `rdpdr`, `smartcard`, `clipboard`) | `crates/ironrdp-client/Cargo.toml` | Confirms DESIGN.md 1: clipboard-only is structural. Omitting `rdpdr` means no drive-redirection code exists to enable. |
| **RemoteFX supported and ON by default** | `client_codecs_capabilities()`, `bitmap_codecs/mod.rs:778` | Good - the low-latency path you wanted is the default, not an opt-in. |
| Codecs are **remotefx, qoi, qoiz only - no H.264/AVC444** | `ironrdp-viewer --codecs help` | Low impact here, see note below. |
| `qoi`/`qoiz` are Devolutions' own codecs, feature-gated off by default | same | Potentially interesting later; not enabled in this build. |
| Upstream examples need cmake via an `opus2` **dev-dependency** | `crates/ironrdp/Cargo.toml` | Build-time only. Does not force sound into the product, which depends on `ironrdp-client` directly. |

Built and ready: `ironrdp-viewer.exe`, `examples/screenshot.exe` (release, Rust 1.97.1).

### Note on the missing H.264 - scope is LAN/local clients

`mstsc` does support H.264/AVC 444, but it is **off by default**: it needs the server-side
policies *Prioritize H.264/AVC 444 Graphics mode for Remote Desktop connections* and
*Configure H.264/AVC hardware encoding* (Computer Configuration > Administrative Templates >
Windows Components > Remote Desktop Services > Remote Desktop Session Host > Remote Session
Environment). Without them the server uses RemoteFX Adaptive Graphics - the same thing
IronRDP negotiates.

So unless those GPOs were deliberately enabled, moving to IronRDP loses nothing that is
currently in use. **Worth verifying on one representative server rather than assuming.**

On a LAN the codec is rarely the bottleneck anyway - bandwidth is plentiful and latency
dominates. And AVC 4:2:0 chroma subsampling visibly blurs text (the reason AVC 444 exists
as a separate mode), so for console and log work RemoteFX often renders sharper.

Conclusion: **not a blocker for this use case.** Revisit only if WAN links or full-motion
video enter scope. Checklist row 5 should therefore be judged on RemoteFX behaviour, not on
H.264 absence.

- IronRDP commit: **079b48422b0b78d37beb76994950a2a07c442a94** (079b484, 2026-07-13)
  - Pin it: `./run-spike.ps1 -Step setup -IronRdpRef 079b48422b0b78d37beb76994950a2a07c442a94`
  - Local patch on top: `patches/0001-screenshot-windows-timeout.patch`
- Client machines: Windows 11 workstation / macOS arm64 (Apple Silicon) NOT YET TESTED
- Target tested: 192.0.2.202 (Windows 11), LAN

## Step 1 - PASSED (Windows 11, LAN)

Headless connect + decode against a real host succeeded end to end. `out.png` shows the
live desktop (signed in to a local account, Settings visible), correct colour, 1280x1024.

| Stage | Result |
|---|---|
| TCP 3389 | pass |
| TLS upgrade | pass |
| **CredSSP / NLA** | **pass** - the most likely failure mode, cleared |
| Connection finalize -> active stage | pass |
| Graphics decode -> PNG | pass |

**Row 3 (NLA) is the single most design-threatening check, and it works.**

### Bug found in upstream's example (not in the library)

The first run failed with `read frame ... (os error 10060)`. Cause: `screenshot.rs`
sets a 3s socket read timeout to break out of the active-stage loop, but matched only
`ErrorKind::WouldBlock`. On Unix a `SO_RCVTIMEO` expiry is `EAGAIN` -> `WouldBlock`; on
**Windows it is `WSAETIMEDOUT` (10060) -> `TimedOut`**, so the intended exit path never
fires and the example errors instead of saving the image.

One-line fix, saved as `patches/0001-screenshot-windows-timeout.patch` (the `.work/`
clone is disposable, the patch is not). Worth sending upstream - it makes the example
unusable on Windows.

**Important: this is a defect in the example harness, not in IronRDP itself.** The
protocol stack completed the whole connection sequence correctly before this triggered.
It says nothing negative about the library.

## Step 2 - interactive: fast, but crashes on resize (root cause found)

User verdict on speed: **"absolutely acceptably fast"** over LAN. Row 6 effectively passes.

Crash on window resize:

```
WARN  ironrdp_session::fast_path: Received compressed FastPath data but no decompressor is configured
ERROR ColorPointerAttribute decode: NotEnoughBytes { received: 336, expected: 50255 }
```

### Root cause - compression state lost across reactivation (NOT a resize defect)

| Path | Decompressor |
|---|---|
| Initial connect - `ironrdp-session/src/active_stage.rs:79` | built from negotiated `compression_type` - correct |
| After resize - `ironrdp-client/src/rdp.rs:988` | hardcoded `bulk_decompressor: None` - **bug** |

Resize triggers the Deactivation-Reactivation Sequence, which rebuilds the FastPath
processor and discards the negotiated decompressor. `fast_path.rs:124` then passes the
still-compressed bytes through unchanged, so the decoder reads a bogus length and dies.

The client advertises bulk compression by default but cannot decode it after
reactivation. `ironrdp-bulk` implements MPPC/NCrush/XCrush in full - it is simply not
wired into that code path.

**Workaround:** `--no-compression` (`test-rdp.ps1 -NoCompression`). Nothing is compressed,
so nothing is mis-parsed. Costs bandwidth, irrelevant on LAN.

**CONFIRMED:** with `-NoCompression` the crash is gone and **dynamic resize
works**. The diagnosis is verified end to end, not merely plausible.

**Bulk compression is BROKEN upstream. Remotino will not advertise it.** (2026-07-21)

Three fixes were attempted. The evidence now says the fault is in the decompression path
itself, not in how the decompressor is managed:

| Attempt | Result |
|---|---|
| `bulk_decompressor: None` (original) | crash - "no decompressor is configured", NotEnoughBytes |
| build a **fresh** decompressor on reactivation | garbage - `bytes per pixel: 64`, `xorMask Expected 8192 actual 4096`, `invalid update type` |
| **carry the live decompressor over** (preserves MPPC/NCRUSH history) | still garbage - `not supported pointer bpp: 0`, and one `ConnectionReset` |

Both configurations where decompression actually *runs* produce corrupt output. Moving the
instance around cannot fix that; the defect is in `ironrdp-bulk` or in how `fast_path.rs`
maps compression flags into it. Diagnosing further needs packet captures and is out of
scope for a viability spike.

**Decision: do not advertise bulk compression.** Remotino controls its own client, so this
is a configuration choice rather than a workaround, and on a LAN compression buys nothing.
`test-rdp.ps1` now disables it by default; `-Compression` re-enables it for re-testing
against a newer upstream.

The carry-over patch is kept in `patches/` because it is the *correct* lifecycle handling
and will be needed if upstream fixes decompression. It is not sufficient on its own.

**CONFIRMED 2026-07-21:** with compression off (now the default) the session is stable
and **dynamic resize works**. Row 9 stands on the shipping configuration, not on a
special flag.

Worth reporting upstream with a capture. Not a blocker: RemoteFX is the codec that
matters, and it works.

<details><summary>Superseded: the original diagnosis (correct as far as it went)</summary>

`patches/0002-carry-bulk-decompressor-across-reactivation.patch`

- `ironrdp-session/src/active_stage.rs` - extracted the decompressor construction into a
  public `make_bulk_decompressor()` (the builder now calls it too, so there is one code
  path rather than two that can drift).
- `ironrdp-session/src/lib.rs` - export it.
- `ironrdp-client/src/rdp.rs` - retain `connection_result.compression_type` as
  `negotiated_compression`, and rebuild the decompressor on reactivation instead of
  passing `None`.

Builds clean. **NOT yet verified at runtime** - that needs an interactive resize with
compression left ON:

```powershell
.\test-rdp.ps1 -RdpHost 192.0.2.202 -Username Administrator     # note: NO -NoCompression
```

Expected: resize works, and the log shows `Bulk decompressor initialized for FastPath`
after reactivation instead of the `no decompressor is configured` warning.

**Outcome: it did not.** See above.

</details>

### Dynamic resize itself is fully implemented - good news for the design

`ironrdp-client/src/rdp.rs:776-793`: on a resize event it calls
`MonitorLayoutEntry::adjust_display_size` then `active_stage.encode_resize(...)`, sending
a new monitor layout over the **Display Control** dynamic channel - live resize, no
reconnect. If the channel is unavailable it falls back to `ReconnectWithNewSize`.

That is exactly the behaviour Remotino's full-bleed tab UI needs (DESIGN.md 2).
Checklist row 9 is therefore a **capability pass, blocked only by the compression bug**.

## Checklist

Status: PASS / FAIL / PARTIAL / N-A

| # | Check | Status | Notes |
|---|---|---|---|
| 1 | Windows Server 2019/2022/2025 | **ASSUMED** | no Server host available; assumed to work, NOT tested. See risk note below. |
| 2 | Windows 11 workstation | PASS | 192.0.2.202 |
| 3 | **NLA / CredSSP** | PASS | the big risk, cleared |
| 4 | TLS-only fallback | TODO | |
| 5 | **Codecs - RemoteFX / bitmap / H.264** | PASS* | RemoteFX default-on; no H.264, low impact on LAN (see note above) |
| 6 | **Input latency vs mstsc, same link** | PASS | acceptably fast on LAN. Direct mstsc A/B still worth doing |
| 7 | Clipboard text both ways | **FAIL both platforms** | different causes: no macOS backend; Windows likely unpumped message loop |
| 8 | Clipboard images | **FAIL both platforms** | same causes as row 7 |
| 9 | Dynamic resize | PASS | compression off (now the default). Display Control live resize, no reconnect |
| 10 | Multi-monitor | TODO | droppable for v1? (DESIGN.md 9 Q2) |
| 11 | 4+ concurrent sessions | TODO | MB and %CPU per session |
| 12 | Reconnect after drop | TODO | |
| 13 | **macOS arm64** | **PASS** | Apple Silicon Mac, Darwin arm64, rustc 1.97.1. Built and rendered a correct desktop. |
| 14 | RD Gateway | N-A? | only if DESIGN.md 9 Q1 says yes |
| 15 | Ctrl+Alt+Del, F-keys, AltGr, layout | TODO | AltGr breaks many clients |

Interim read: 6 of 15 done, **no failures**. **Every check capable of overturning the
architecture has now passed** - NLA, latency, and macOS arm64. What remains
(clipboard, reconnect, AltGr, concurrency) affects polish and effort, not the choice of
engine.

## Row 13 - macOS arm64: PASS

- Host: Apple Silicon Mac, `arch: arm64`, `os: Darwin`, rustc 1.97.1 (same version as Windows)
- Built the pinned commit cleanly on arm64
- `out-macos.png` shows a correct Windows 11 desktop - accurate colour, crisp text,
  taskbar and icons intact. Equivalent to the Windows `out.png`.
- Build correctly redirected to local disk
  (`~/Library/Caches/Remotino/spike-work`) rather than a network share

**This is the result the whole spike existed to obtain.** One Rust codebase drives RDP on
both macOS arm64 and Windows 11, so the platform-split fallback (mstsc ActiveX + FreeRDP,
~3-4 extra weeks and two input/clipboard implementations maintained forever) is not
needed.

Incidental confirmation: this run happened *without* patch 0001, which had failed to
apply. That is exactly what the analysis predicted - on Unix the socket timeout is
`EAGAIN` -> `WouldBlock`, which upstream already handles, so the bug really was
Windows-only.

Still untested on macOS: interactive latency, retina/HiDPI sharpness, keyboard layout.
Those are usability questions, not architectural ones.

### macOS interactive session

- Viewer runs, **window resize works cleanly** - dynamic resize confirmed on macOS as
  well as Windows
- **Clipboard does not work at all**: Cmd+C/V, Ctrl+C/V and right-click copy/paste all
  fail

## Rows 7-8 - clipboard is UNIMPLEMENTED on macOS upstream (not a bug)

`ironrdp-cliprdr-native` ships exactly two backends:

```rust
#[cfg(windows)]
mod windows;                     // real implementation
mod stub;                        // everything else -> StubClipboard, a no-op
```

Its `Cargo.toml` declares only `[target.'cfg(windows)'.dependencies]`. On macOS the
viewer binds the stub, so every copy/paste route fails identically. **No keyboard mapping
change would fix this** - Cmd-vs-Ctrl was a red herring; there is simply nothing behind
the channel.

Note the shape of this finding: it is *missing platform code*, not a protocol or design
flaw. The CLIPRDR protocol layer (`ironrdp-cliprdr`) is platform-independent and already
works - only the OS glue is absent.

### What it costs

Remotino needs a macOS `CliprdrBackend` backed by `NSPasteboard`. Tractable:

- `CliprdrBackend` is a well-defined trait, and `crates/ironrdp-cliprdr-native/src/windows/`
  is a complete reference implementation to mirror
- Scope for v1 is narrow - text is required; images are nice-to-have; file transfer is
  explicitly out of scope per DESIGN.md
- Estimate: a few days, not weeks. Budget it into **Phase 4**.

This is the first real cost found in choosing IronRDP, and it is worth stating plainly
alongside the win: it is still far cheaper than the platform-split fallback, which would
have required *two* clipboard implementations plus two input layers, permanently.

### Windows ALSO fails - and the cause is different

Ctrl+C/V and right-click copy/paste all fail on Windows too, so this is not simply
"macOS backend missing".

Established facts:

- The `clipboard` feature **is** compiled in (`cargo tree -e features` shows
  `ironrdp-client feature "clipboard"`, and `ironrdp-cliprdr-native` is in the graph).
- `WinClipboard::new()` **succeeded**. If it had failed, the client emits
  `ConnectionFailure` and aborts the session (`ironrdp-client/src/rdp.rs:159-168`), and
  the session connected normally.

**Hypothesis (NOT yet verified):** `WinClipboard::new()` creates a hidden `WS_POPUP`
window, calls `AddClipboardFormatListener`, and subclasses it via `SetWindowSubclass`.
Its own source says:

> "We need to receive winapi messages in the main thread, so we need to add a subclass
> to the window."

That design needs a **Win32 message pump on the thread that owns the window**. The object
is built inside `ironrdp-client`'s async task rather than on winit's main thread, and
nothing pumps messages for it - so `WM_CLIPBOARDUPDATE` is never dispatched and the
listener never fires. The struct even carries `_thread_marker: PhantomData<*const ()>`,
making it `!Send`, which is consistent with it being intended to live on the UI thread.

Confirm by re-running with the wider log filter now in `test-rdp.ps1` and checking
whether any `cliprdr` traffic appears. Silence on the channel supports this; errors would
point elsewhere.

### What this means for Remotino - smaller than it looks

**Remotino will not use `ironrdp-viewer`.** We build our own Tauri frontend and own the
event loop, so this specific wiring defect does not carry over. What does carry over:

- **Windows:** `WinClipboard` is reusable, but only if we create it on the UI thread and
  pump its messages. That is a wiring requirement to design for, not new code to write.
- **macOS:** no backend exists; we implement `CliprdrBackend` over `NSPasteboard`.

Revised Phase 4 estimate for clipboard: **about a week**, versus the few days assumed when
only macOS looked affected. Still far below the platform-split fallback, which needed two
clipboard *and* two input implementations maintained permanently.

Worth stating plainly: this is the second upstream integration gap found (after the
decompressor), and both were in glue code rather than the protocol stack. The protocol
work - the genuinely hard part - keeps holding up.

### Row 1 is an assumption, not a result

No Server 2022/2025 host was available, so we are proceeding on the assumption that it
works. That is a reasonable bet - Server and Windows 11 client share the RDP stack, and
NLA/CredSSP (the usual differentiator) already passed - but it is a bet, and it should not
quietly harden into "tested" later.

What could still differ on a real Server host:

- **RDS licensing / per-user CAL handling** - absent entirely on a workstation
- **Multi-session (RDSH)** rather than single-session, so session brokering is in play
- Session Host GPOs that constrain codecs or redirection
- Older TLS or CredSSP policy on 2019
- RD Gateway, if it turns out to be in scope (DESIGN.md 9 Q1)

Cost to close: one 30-second `-Step screenshot` run once a Server host exists. Worth doing
before Phase 4 (RDP implementation) commits, not before Phase 1.

## Verdict

> Bar was set in README.md *before* testing. Hold to it.

**GO / GO-REDUCED / NO-GO:** ____

Reasoning:

Limitations accepted into the design:

## Step 3 — Tauri embedding (only if steps 1–2 passed)

- Frames Rust -> webview canvas: transport used ____ , measured FPS ____
- Input webview -> Rust: latency feel ____
- Blocker(s):

## Surprises

Anything that changes DESIGN.md — note it here and open a question in §8.
