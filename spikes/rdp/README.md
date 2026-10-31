# Spike A — IronRDP viability

**Question this spike answers:** can IronRDP drive our real RDP servers well enough to be
the single cross-platform RDP engine for Remotino?

**This code is throwaway.** Its only output is a decision recorded in `RESULTS.md`.
Do not build product code on it.

If the answer is no, the fallback is a platform-split RDP layer (mstsc ActiveX on
Windows, FreeRDP embedded on macOS) — roughly 3–4 extra weeks and two input/clipboard
implementations to maintain forever. That is why this runs before anything else.

---

## Order of work — cheapest question first

Each step is only worth doing if the previous one passed.

### Step 1 — headless connect (30 min, zero code)

IronRDP ships a `screenshot` example: it connects, authenticates, decodes graphics, and
writes a BMP. That single command answers the riskiest question — *does it speak
protocol to our servers at all* — before we write a line.

```powershell
./run-spike.ps1 -Step screenshot -RdpHost srv-test01 -Username you
```

Passing = a BMP that looks like the desktop. If this fails, stop and read the error;
it's almost always NLA/CredSSP or TLS, and that's decisive information.

### Step 2 — interactive viewer (1–2 h, zero code)

`ironrdp-viewer` is a full async GUI client. This is where subjective quality lives:
latency, keyboard, clipboard, resize.

```powershell
./run-spike.ps1 -Step viewer -RdpHost srv-test01 -Username you
```

Run this against the *worst* link you actually use — a VPN or WAN hop, not the LAN.
LAN results tell you nothing about how it will feel in practice.

### Step 3 — Tauri embedding (2–3 days, real code)

Only if steps 1 and 2 pass. Prove decoded frames can be pushed from Rust into a webview
canvas at acceptable framerate, and input routed back. This is the one genuinely novel
piece; everything before it is running someone else's binary.

---

## The checklist that matters

Record every row in `RESULTS.md`. Test against **real** servers, not a lab VM.

| # | Check | Why it's on the list |
|---|---|---|
| 1 | Connects to Windows Server 2019/2022/2025 | Baseline |
| 2 | Windows 11 workstation target | Different stack than Server |
| 3 | **NLA / CredSSP auth** | Most likely single point of failure |
| 4 | TLS-only / RDP Security fallback | Older or non-domain hosts |
| 5 | Codec negotiation (RemoteFX / bitmap / **H.264 AVC444**) | Perf on modern hosts; known IronRDP soft spot |
| 6 | Subjective input latency over WAN/VPN | The whole point of leaving RDM |
| 7 | Clipboard text both directions (`cliprdr`) | Your one required redirection |
| 8 | Clipboard **images** | Often quietly missing |
| 9 | Dynamic resize (Display Update channel) | Required by the full-bleed tab UI |
| 10 | Multi-monitor | Confirm scope — may be droppable for v1 |
| 11 | 4+ concurrent sessions, CPU/RAM per session | Tab model implies many at once |
| 12 | Reconnect after network drop | Laptop lid / VPN flap |
| 13 | **Runs on macOS arm64** | Load-bearing for the whole plan |
| 14 | RD Gateway | Only if §8 Q1 says yes |
| 15 | Special keys: Ctrl+Alt+Del, F-keys, AltGr, non-US layout | AltGr breaks a lot of clients |

Rows 3, 5, 6 and 13 are the ones that would actually kill the design. Do those first
within each step.

---

## Verdict rule — decide this before you see the results

Agreeing the bar in advance stops the sunk-cost argument later.

- **GO** — rows 1–9, 11–13, 15 pass; latency comparable to `mstsc` over the same link.
- **GO (reduced)** — above holds but H.264 or multi-monitor missing, *and* §8 Q2 says
  multi-monitor is out of scope. Note the limitation and continue.
- **NO-GO** — NLA fails, macOS arm64 fails, or latency is visibly worse than `mstsc`.
  Switch to the platform-split fallback and re-plan.

## Row 13 - macOS arm64 (the remaining load-bearing check)

Use `run-spike.sh` on an Apple Silicon Mac. It pins the same commit verified on Windows and applies
both patches from `patches/`, so a failure there means "macOS problem" rather than
"different code" - which is the whole point of testing it.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # NOT 'brew install rustup'
source "$HOME/.cargo/env"                                       # - that formula no longer
brew install cmake                                              #   ships rustup-init
xcode-select --install                                          # linker
cd spikes/rdp
chmod +x run-spike.sh
./run-spike.sh setup                          # compiling at all is half the answer
./run-spike.sh screenshot <host> <user>
./run-spike.sh viewer <host> <user>
```

Compare `out-macos.png` against the Windows `out.png` - they should look equivalent.

macOS-specific risks worth attention, none of which the Windows run exercised:

- **Retina / HiDPI scaling** - `softbuffer` blits a raw framebuffer. Crisp or blurry?
- **Cmd vs Ctrl mapping** - remote Windows expects Ctrl; does the viewer translate?
- **Keyboard layout**, especially non-US and AltGr equivalents
- **Latency vs Microsoft's Windows App** on the same link
- Whether `winit` window behaviour (resize, fullscreen) matches Windows

## Prerequisites

- Rust ≥ 1.89 (`winget install Rustlang.Rustup`)
- A test RDP host you are authorised to connect to
- macOS arm64 machine for row 13
