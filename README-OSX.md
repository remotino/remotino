# macOS setup (Apple Silicon)

Everything needed to get the RDP spike running on the Apple Silicon Mac from a clean machine.
Written down because two of these steps are non-obvious and cost time on the first run.

---

## 1. Rust

**Use the official installer, not Homebrew.**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

> **Why not `brew install rustup-init`?** That formula was renamed to `rustup`, and it
> **no longer ships a `rustup-init` binary** - the command fails with `command not found`.
> There is also a known Homebrew PATH issue on Apple Silicon where the rustup binary does
> not land in `/opt/homebrew/bin`. The official installer avoids both.

### If you installed rustup some other way: select a toolchain

`rustup` is only the *installer*. Until a toolchain is selected there is **no `cargo`**,
which shows up confusingly as "cargo not found" even though rustup is clearly installed.

```bash
rustup default stable
```

That downloads the stable toolchain and creates the `cargo` / `rustc` shims in
`~/.cargo/bin`. This is the single most likely thing to have gone wrong.

If `rustup` itself is not found despite being installed, it came from Homebrew and its
prefix is not on your PATH:

```bash
export PATH="$(brew --prefix rustup)/bin:$PATH"
```

### Verify

```bash
rustc --version     # must be >= 1.89 (IronRDP's MSRV)
cargo --version
```

## 2. Build tools

```bash
xcode-select --install      # linker and system headers
brew install cmake          # the RDP viewer pulls opus, which builds via cmake
```

`cmake` is only needed for the interactive **viewer**. The headless **screenshot** step
builds without it, so a missing cmake is not a blocker for the first result.

## 3. Run the spike

```bash
cd /path/to/remotino
./spikes/rdp/run-spike.sh setup                     # 5-10 min on first run
./spikes/rdp/run-spike.sh screenshot <host> <user>
./spikes/rdp/run-spike.sh viewer <host> <user>
```

Look for the toolchain line in the `setup` output:

```
[ok] rustc 1.9x.x  (IronRDP needs >= 1.89)
```

Cargo does thousands of small file operations and relies on file locking, so build to a
**local disk**, not a network share. If the repo is on a share, point the build at a local
path:

```bash
export REMOTINO_WORK_DIR="$HOME/Library/Caches/Remotino/spike-work"
```

## 4. What this is actually testing

Checklist **row 13** in `spikes/rdp/RESULTS.md` - the last remaining check that could
overturn the architecture. If IronRDP does not work on macOS arm64, the single-codebase
plan collapses and we need a platform-split RDP layer instead.

`run-spike.sh setup` completing already answers half of it: **it compiles on arm64.**

The script pins the same IronRDP commit verified on Windows
(`079b48422b0b78d37beb76994950a2a07c442a94`) and auto-applies both patches from
`patches/`, so a failure here means "macOS problem" rather than "different code".

macOS-specific risks the Windows run could not exercise:

- **Retina / HiDPI** - `softbuffer` blits a raw framebuffer. Crisp, or blurry?
- **Cmd vs Ctrl** - the remote Windows host expects Ctrl. Does the viewer translate?
- **Keyboard layout**, especially non-US and AltGr equivalents
- **Latency vs Microsoft's Windows App** on the same link

Record what you find in `spikes/rdp/RESULTS.md` row 13.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `rustup-init: command not found` | Homebrew renamed the formula; it no longer ships that binary | Use the `curl` installer above |
| `cargo not found` but rustup is installed | No default toolchain selected | `rustup default stable` |
| `cargo not found` in a shell where it worked before | New shell has not re-read the rc files | `source "$HOME/.cargo/env"` |
| `permission denied` running `./run-spike.sh` | Execute bit missing | `bash ./spikes/rdp/run-spike.sh` (or `chmod +x`) |
| Build is extremely slow | Building on a network share | Set `REMOTINO_WORK_DIR` to a local path |
| `failed to execute command: cmake` | opus needs cmake | `brew install cmake` |

The `setup` step prints exactly which directories it searched when it cannot find cargo -
read that output before trying anything else.
