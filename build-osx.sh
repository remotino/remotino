#!/bin/sh
# One command to build a self-contained macOS Remotino: the RDP sidecar (its own workspace)
# plus the .app bundle, with the sidecar copied inside the bundle so it ships as one app.
#
#   ./build-osx.sh          # or: sh build-osx.sh
#
# Run from the repo root on a Mac. Prereqs: Rust >= 1.89, Node, Xcode CLT, cmake.
set -eu

cd "$(dirname "$0")"

# Strip the build machine's home and source paths from the compiled binaries (rustc otherwise
# bakes /Users/<name>/.cargo/... and the project path into debug info and panic locations).
export RUSTFLAGS="--remap-path-prefix=$HOME=/home/dev --remap-path-prefix=$PWD=/src"

# Build identifier, derived from git so it always reflects the checked-out source without any
# manual bumping: short commit + commit date, plus "-dirty" if the working tree has uncommitted
# changes. Falls back gracefully outside a git checkout.
BUILD="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_DATE="$(git show -s --format=%cs HEAD 2>/dev/null || date +%F)"
if ! git diff --quiet HEAD 2>/dev/null; then BUILD="$BUILD-dirty"; fi
BUILD_STR="$BUILD ($BUILD_DATE)"

echo "==> Building Remotino for macOS - build $BUILD_STR"
echo "==> [1/3] Building the RDP sidecar (rdp-host, release)..."
cargo build --release --manifest-path rdp-host/Cargo.toml
RDP_BIN="rdp-host/target/release/rdp-host"
[ -f "$RDP_BIN" ] || { echo "error: rdp-host binary not found at $RDP_BIN" >&2; exit 1; }

# Stage the sidecar where Tauri's externalBin expects it: named with the target triple. The
# tauri build then bundles it into the .app's Contents/MacOS automatically (the same mechanism
# the Windows MSI uses). It MUST exist before the build, or tauri errors with
# "resource path binaries/rdp-host-<triple> doesn't exist".
TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
BINDIR="remotino-app/src-tauri/binaries"
mkdir -p "$BINDIR"
cp "$RDP_BIN" "$BINDIR/rdp-host-$TRIPLE"

echo "==> [2/3] Building the app bundle (npm + tauri; sidecar bundled via externalBin)..."
[ -d remotino-app/node_modules ] || ( cd remotino-app && npm install )
( cd remotino-app && npm run tauri build -- --bundles app )

echo "==> [3/3] Finalising the .app bundle..."
APP=$(find . -type d -path '*/release/bundle/macos/*.app' -not -path '*/node_modules/*' 2>/dev/null | head -n1)
[ -n "${APP:-}" ] || { echo "error: could not find the built .app bundle" >&2; exit 1; }

# Clear the quarantine flag on the whole bundle. Gatekeeper silently kills the *spawned*
# rdp-host sidecar if it's quarantined (no "click to open" prompt like the main app gets),
# which shows up as an RDP tab that goes straight to red. Safe: this is a locally-built app.
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

# Verify the sidecar actually landed next to the app binary.
[ -f "$APP/Contents/MacOS/rdp-host" ] || { echo "error: rdp-host is not in the bundle" >&2; exit 1; }

# Stamp the build id into the bundle so the artifact records which source it came from.
mkdir -p "$APP/Contents/Resources"
printf '%s\n' "$BUILD_STR" > "$APP/Contents/Resources/BUILD.txt"

echo ""
echo "Done - build $BUILD_STR. Self-contained app (both binaries bundled):"
ls -1 "$APP/Contents/MacOS/"
echo ""

# Offer to install into /Applications, replacing any existing copy. Only when stdin is a
# terminal, so a non-interactive run (pipe/CI) just skips it rather than hanging.
INSTALLED=""
if [ -t 0 ]; then
    printf "Install to /Applications, replacing the current Remotino.app? [y/N] "
    read -r reply
    case "$reply" in
        [Yy]*)
            rm -rf "/Applications/Remotino.app"
            cp -R "$APP" "/Applications/Remotino.app"
            INSTALLED="yes"
            echo "Installed -> /Applications/Remotino.app"
            ;;
    esac
fi

echo ""
if [ -n "$INSTALLED" ]; then
    echo "Launch it:  open -a Remotino"
else
    echo "A .app is a folder, not an executable - launch it with 'open', not ./:"
    echo "    open \"$APP\""
    echo "Or install later:  mv \"$APP\" /Applications/"
fi
echo "Built locally, so Gatekeeper won't block it."
