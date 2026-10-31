# Patches

Local fixes against the pinned IronRDP commit
`079b48422b0b78d37beb76994950a2a07c442a94`.

They live here rather than in the clone because `.work/` (and its macOS equivalent under
`~/Library/Caches`) is disposable and rebuilt from scratch by `run-spike`.

**Apply all of them on every platform.** None are platform-conditional - see the table.
`run-spike.sh` applies them automatically; the Windows harness currently expects the
clone to be patched by hand or by a prior `run-spike.sh` run.

## Index

| Patch | Fixes | Affects | Needed on |
|---|---|---|---|
| `0001-screenshot-windows-timeout.patch` | `screenshot` example treated a socket read timeout as fatal | example only, not the library | **Windows only in practice**, but harmless and correct everywhere |
| `0002-carry-bulk-decompressor-across-reactivation.patch` | bulk decompressor dropped on every Deactivation-Reactivation Sequence | `ironrdp-session`, `ironrdp-client` | **All platforms** |

## 0001 - screenshot Windows timeout

The example sets a 3s socket read timeout to break out of the active-stage loop once
updates stop, but matched only `ErrorKind::WouldBlock`:

```rust
Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break 'outer,
```

A `SO_RCVTIMEO` expiry is `EAGAIN` -> `WouldBlock` on Unix but `WSAETIMEDOUT` (10060) ->
`TimedOut` on Windows, so on Windows the intended exit path never fired and the example
errored instead of writing the image. The fix accepts both.

**Why apply it on macOS too:** the patch *adds* `TimedOut` and keeps `WouldBlock`, so
behaviour on Unix is unchanged. Verified empirically - the macOS screenshot run succeeded
*without* this patch, which is exactly what the analysis predicted. Applying it costs
nothing and keeps one code path across platforms.

Scope: the example harness only. Says nothing about the library's quality.

## 0002 - restore bulk decompressor on reactivation

`ironrdp-client` rebuilt the FastPath processor after a Deactivation-Reactivation
Sequence with `bulk_decompressor: None`, discarding the decompressor negotiated at
connect time. The client still advertises bulk compression, so the server keeps sending
compressed PDUs; `fast_path.rs` then passes them through unchanged and the decoder reads
a bogus length.

Resizing a window triggers that sequence, so **resize crashed the session** with:

```
WARN  Received compressed FastPath data but no decompressor is configured
ERROR ColorPointerAttribute decode: NotEnoughBytes { received: 336, expected: 50255 }
```

### Two wrong fixes preceded the right one

**Attempt 1** set `bulk_decompressor: None` -> obviously wrong, that *was* the bug.

**Attempt 2** built a *fresh* decompressor from the negotiated compression type. It
compiled, and it was still wrong: `BulkCompressor` holds MPPC/NCRUSH/XCRUSH **history
windows** that must track the server's compressor. A fresh instance starts with an empty
history while the server continues with its own, so every subsequent update decodes to
garbage:

```
invalid pointer xorMask size. Expected: 8192, actual: 4096
Invalid RLE-compressed bitmap: invalid bytes per pixel: 64
Received invalid Fast-Path update field="updateType" reason="invalid update type"
```

The symptom changed from a clean crash to silent corruption, which is worse.

**Attempt 3, current:** `take_bulk_decompressor()` moves the *live* instance out of the
old processor and into the rebuilt one, preserving history. Compression state is
inherently stateful across a reactivation; it must be carried, never reconstructed.

**Not platform-specific.** macOS would hit the identical crash; it simply has not been
exercised there yet, because `run-spike.sh` passes `--no-compression` for the viewer.

Status: builds clean, **not yet verified at runtime**. Needs an interactive resize with
compression left ON - the log should then show `Bulk decompressor initialized for
FastPath` after reactivation.

## Conventions

- **LF line endings, always.** These were originally generated through PowerShell
  redirection, which wrote CRLF; `git apply` is whitespace-sensitive and silently
  refused them on macOS. `.gitattributes` marks `*.patch` as `-text` so git stores them
  byte-exact and never rewrites the endings.
- Name platform-specific patches accordingly (`0003-macos-*.patch`) **if** one ever
  arises, and note it in the table above. Do not split this directory by OS - the
  patches so far are shared, and duplicating them invites drift where a fix lands on one
  platform only.
- Regenerate with `git -C <clone> diff -- <paths> > patches/000N-name.patch` from a
  shell that writes LF.

## Upstream

Neither has been submitted to Devolutions yet. Both are worth sending: 0001 makes the
example unusable on Windows, and 0002 crashes any session on resize with default
settings.
