# Security Policy

Remotino is a security tool, and its cryptographic core is meant to be read and scrutinised.
Responsible reports are genuinely welcome.

## Reporting a vulnerability

**Email `security@remotino.app`.** Please do **not** open a public issue for anything
security-sensitive.

Helpful things to include:
- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected component (`remotino-crypto`, the app, the RDP sidecar, the SQL backend, …)
  and version / commit.

We aim to acknowledge reports promptly and to work with you on a coordinated disclosure —
a fix and an advisory before public details. We won't take legal action against good-faith
research that respects users' data and this process.

## Scope

Most valuable are issues in the **cryptographic and access-control model**, since that is
what the whole product rests on — for example:
- A way to read content (folder names, connections, credentials) without holding the key.
- A way to forge, reorder, or silently rewrite the append-only audit log.
- A flaw in identity sealing, key wrapping, sharing, or revocation.
- A way for a per-user SQL login to exceed its least-privilege (`SELECT`/`INSERT`) rights.

## Current status

Remotino is **pre-1.0**. Notably:
- The cryptographic core has **not yet had an independent cryptographer review** — that
  review is a gate before 1.0, not something already completed.
- RDP TLS is trust-on-first-use (TOFU); Kerberos and clipboard/file redirection are limited
  or absent by design.
- Revocation is currently forward-only (it stops new reads; key rotation to cut off cached
  access is planned).

These are documented tradeoffs, not surprises — but please factor them in when assessing
risk. See [`CRYPTO.md`](CRYPTO.md) and [`DESIGN.md`](DESIGN.md) for the details.
