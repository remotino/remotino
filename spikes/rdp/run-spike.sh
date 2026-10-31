#!/usr/bin/env bash
# Spike A harness - macOS / Linux counterpart of run-spike.ps1.
#
# Purpose: checklist row 13 - does IronRDP work on macOS arm64 (M4)? The whole
# single-codebase premise in DESIGN.md rests on this answering yes.
#
# Throwaway. Clones IronRDP into .work/ and runs its stock example clients.
#
# Usage:
#   ./run-spike.sh setup
#   ./run-spike.sh screenshot <host> <user> [domain]
#   ./run-spike.sh viewer     <host> <user> [domain]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_DIR="$SCRIPT_DIR/patches"

# The IronRDP clone and its multi-GB target/ must live on LOCAL disk. Cargo does
# thousands of small file operations and depends on file locking; over a network share that
# is slow and the locking is not dependable. If this repo is on a network share, build
# locally instead.
# Override with REMOTINO_WORK_DIR.
if [ -n "${REMOTINO_WORK_DIR:-}" ]; then
    WORK_DIR="$REMOTINO_WORK_DIR"
elif [ "$(uname -s)" = 'Darwin' ] && [ "${SCRIPT_DIR#/Volumes/}" != "$SCRIPT_DIR" ]; then
    WORK_DIR="$HOME/Library/Caches/Remotino/spike-work"
    printf '  \033[90m[i] repo is on a network share - building in %s\033[0m\n' "$WORK_DIR"
elif df -P "$SCRIPT_DIR" 2>/dev/null | tail -1 | grep -qE '^(//|.*:/)'; then
    WORK_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/remotino/spike-work"
    printf '  \033[90m[i] repo is on a network mount - building in %s\033[0m\n' "$WORK_DIR"
else
    WORK_DIR="$SCRIPT_DIR/.work"
fi

REPO_DIR="$WORK_DIR/IronRDP"

# Pin to the commit that passed on Windows, so a Mac failure means "macOS problem"
# and not "different code". Override with IRONRDP_REF=... to test something else.
IRONRDP_REF="${IRONRDP_REF:-079b48422b0b78d37beb76994950a2a07c442a94}"

step() { printf '\n\033[36m=== %s ===\033[0m\n' "$1"; }
ok()   { printf '  \033[32m[ok]\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m[!!]\033[0m %s\n' "$1"; }
die()  { printf '  \033[31m[xx]\033[0m %s\n' "$1" >&2; exit 1; }

usage() {
    cat <<'EOF'

Spike A - IronRDP viability harness (macOS / Linux)

  ./run-spike.sh setup
      Clone + pin IronRDP, apply local patches, build. First build 5-10 min.

  ./run-spike.sh screenshot <host> <user> [domain]
      Headless connect + decode to out.png. Answers the core question.
      NOTE: the example takes the password on argv - use a throwaway.

  ./run-spike.sh viewer <host> <user> [domain]
      Interactive session; prompts for the password.

  What row 13 is really asking:
    1. Does it build at all on arm64?
    2. Does it connect and decode (compare out.png against the Windows run)?
    3. Does the winit/softbuffer window behave - resize, keyboard, retina scaling?
    4. Is latency comparable to Microsoft's Windows App on the same link?

  Record findings in RESULTS.md row 13.

EOF
}

STEP="${1:-}"
[ -z "$STEP" ] && { usage; exit 0; }

# --- prerequisites -----------------------------------------------------------
step 'Checking prerequisites'

# Rust may be installed but absent from this shell's PATH - a new login shell only picks
# it up after the installer edits the rc files. Add every plausible location before
# giving up, so "cargo not found" means genuinely absent rather than merely unexported.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi
for d in "$HOME/.cargo/bin" /opt/homebrew/bin /usr/local/bin; do
    [ -d "$d" ] && case ":$PATH:" in *":$d:"*) ;; *) PATH="$d:$PATH" ;; esac
done
if command -v brew >/dev/null 2>&1; then
    brew_rustup="$(brew --prefix rustup 2>/dev/null || true)"
    [ -n "$brew_rustup" ] && [ -d "$brew_rustup/bin" ] && PATH="$brew_rustup/bin:$PATH"
fi
export PATH

if ! command -v cargo >/dev/null 2>&1; then
    warn 'cargo not found. Checked:'
    for d in "$HOME/.cargo/bin" /opt/homebrew/bin /usr/local/bin; do
        if [ -d "$d" ]; then
            printf '    %-24s exists, cargo present: %s\n' "$d" \
                "$([ -x "$d/cargo" ] && echo yes || echo no)"
        else
            printf '    %-24s does not exist\n' "$d"
        fi
    done
    printf '    %-24s %s\n' 'rustup on PATH:' "$(command -v rustup 2>/dev/null || echo no)"
    printf '    %-24s %s\n' 'rustc on PATH:'  "$(command -v rustc  2>/dev/null || echo no)"
    cat <<'EOF'

  If nothing above shows cargo, Rust is not installed. Install it with:

      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
      source "$HOME/.cargo/env"

  Do NOT use `brew install rustup-init` - that formula was renamed and no longer
  ships a rustup-init binary.

  If `rustup` IS present above but cargo is not, the toolchain was never selected:

      rustup default stable

EOF
    exit 1
fi

command -v git   >/dev/null 2>&1 || die 'git not found - run: xcode-select --install'
command -v cmake >/dev/null 2>&1 || warn 'cmake not found - needed by the viewer (opus). brew install cmake'

ok "$(rustc --version)  (IronRDP needs >= 1.89)"
ok "arch: $(uname -m)   os: $(uname -s)"

# --- source ------------------------------------------------------------------
step 'Fetching IronRDP'

if [ ! -d "$REPO_DIR" ]; then
    mkdir -p "$WORK_DIR"
    git clone https://github.com/Devolutions/IronRDP.git "$REPO_DIR"
else
    ok 'already cloned (delete .work/ to refresh)'
fi

git -C "$REPO_DIR" fetch --depth 1 origin "$IRONRDP_REF" 2>/dev/null || true
git -C "$REPO_DIR" checkout --quiet "$IRONRDP_REF"
ok "pinned to ${IRONRDP_REF:0:7} (same commit verified on Windows)"

# --- patches -----------------------------------------------------------------
# Both were found during the Windows run. Neither is macOS-specific, but without
# them you will hit the same two bugs and waste time rediscovering them.
if [ -d "$PATCH_DIR" ]; then
    step 'Applying local patches'
    for p in "$PATCH_DIR"/*.patch; do
        [ -e "$p" ] || continue
        name="$(basename "$p")"
        if git -C "$REPO_DIR" apply --check "$p" 2>/dev/null; then
            git -C "$REPO_DIR" apply "$p"
            ok "applied $name"
        elif git -C "$REPO_DIR" apply --reverse --check "$p" 2>/dev/null; then
            ok "$name already applied"
        else
            warn "$name did not apply - upstream may have fixed or moved it"
        fi
    done
fi

# --- build -------------------------------------------------------------------
SHOT_FEATURES='session,connector,graphics'   # on top of defaults (core + pdu)

if [ "$STEP" = 'setup' ]; then
    step 'Warming the build cache (first build is slow - 5-10 min)'

    echo '  Building screenshot example...'
    # Do NOT add --no-default-features: it strips `pdu`, which the example imports.
    cargo build --manifest-path "$REPO_DIR/Cargo.toml" -p ironrdp --example screenshot \
        --release --features "$SHOT_FEATURES"
    ok 'screenshot example built'

    echo
    echo '  Building ironrdp-viewer (needs cmake via the opus dependency)...'
    if cargo build --manifest-path "$REPO_DIR/Cargo.toml" --release --bin ironrdp-viewer; then
        ok 'viewer built'
    else
        warn 'viewer build failed - screenshot step still works. Try: brew install cmake'
    fi

    ok 'setup complete'
    echo
    echo '  This alone answers half of row 13: it compiles on arm64.'
    exit 0
fi

# --- connection steps --------------------------------------------------------
RDP_HOST="${2:-}"
RDP_USER="${3:-}"
RDP_DOMAIN="${4:-}"

[ -z "$RDP_HOST" ] && die 'host is required:  ./run-spike.sh '"$STEP"' <host> <user> [domain]'
[ -z "$RDP_USER" ] && die 'user is required:  ./run-spike.sh '"$STEP"' <host> <user> [domain]'

OUT_FILE="$SCRIPT_DIR/out-macos.png"

case "$STEP" in
    screenshot)
        # The example only accepts the password on argv - there is no env-var path.
        printf '  RDP password (will be passed on argv): '
        stty -echo; read -r RDP_PASS; stty echo; printf '\n'

        SHOT_EXE="$REPO_DIR/target/release/examples/screenshot"
        [ -x "$SHOT_EXE" ] || die "screenshot binary missing - run: ./run-spike.sh setup"

        step "Step 1: headless connect + decode -> $OUT_FILE"
        args=(--host "$RDP_HOST" -u "$RDP_USER" -p "$RDP_PASS" -o "$OUT_FILE")
        [ -n "$RDP_DOMAIN" ] && args+=(-d "$RDP_DOMAIN")

        if "$SHOT_EXE" "${args[@]}"; then
            ok "wrote $OUT_FILE"
            echo '  Compare it against the Windows out.png - they should look equivalent.'
        else
            die 'screenshot failed - record the exact error in RESULTS.md row 13'
        fi
        ;;

    viewer)
        VIEWER_EXE="$REPO_DIR/target/release/ironrdp-viewer"
        [ -x "$VIEWER_EXE" ] || die "viewer binary missing - run: ./run-spike.sh setup"

        step 'Step 2: interactive session'
        cat <<'EOF'
  Work these while connected (the macOS-specific risks):
    - resize the window; dynamic resize should work without a reconnect
    - retina / HiDPI scaling: is the image crisp or blurry?
    - Cmd vs Ctrl mapping, and your keyboard layout
    - clipboard text both directions
    - latency vs Microsoft's Windows App on the SAME link

  Compression is disabled below: without it, resize crashes on the unpatched
  client (see RESULTS.md). Patch 0002 fixes that - drop the flag to verify.
EOF
        args=("$RDP_HOST" --username "$RDP_USER" --no-compression)
        [ -n "$RDP_DOMAIN" ] && args+=(--domain "$RDP_DOMAIN")
        "$VIEWER_EXE" "${args[@]}"
        ;;

    *)
        die "unknown step '$STEP' (expected: setup | screenshot | viewer)"
        ;;
esac

printf '\n\033[36mRecord what you saw in RESULTS.md row 13 while it is fresh.\033[0m\n'
