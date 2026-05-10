---
title: Clients
layout: default
parent: User Guide
nav_order: 0
---

# Clients
{: .no_toc }

DMP has three first-party client implementations. Pick whichever fits
how you want to use the protocol; all three speak the same wire format
and interoperate over DNS.

1. TOC
{:toc}

{: .warning }
The desktop, Android, and Rust-SDK clients are **alpha**. The Python
CLI is the most mature surface and the one the protocol spec is
exercised against in CI. Wire format, on-disk layout, and SDK API
can still move between alpha tags — see each repo's `CHANGELOG.md`
before pinning.

## At a glance

| Client | Surface | Platforms | Status | Repo |
|---|---|---|---|---|
| `dnsmesh` (Python CLI) | Terminal | macOS, Linux, Windows (via Python or single-file binary) | Shipping | [DNSMeshProtocol](https://github.com/oscarvalenzuelab/DNSMeshProtocol) |
| `dnsmesh-app` | Desktop + mobile GUI | macOS, Linux, Windows, Android | Alpha | [dnsmesh-app](https://github.com/oscarvalenzuelab/dnsmesh-app) |
| `dnsmesh-rs` | Rust SDK + standalone CLI | macOS, Linux, Windows | Alpha | [dnsmesh-rs](https://github.com/oscarvalenzuelab/dnsmesh-rs) |

The Python CLI and the Rust CLI both target the terminal. The Tauri
GUI is the one to point non-technical users at; it embeds the Rust
SDK behind a Svelte UI and ships installers for every desktop OS
plus a sideloadable Android APK.

## Python CLI — `dnsmesh`

The reference implementation. Installs via `pip` / `pipx`, or as a
single-file binary if you don't want a Python runtime. This is the
client the [Getting Started]({{ site.baseurl }}/getting-started)
walkthrough uses end-to-end.

```bash
pipx install dnsmesh
dnsmesh --help
```

Standalone binaries (no Python required) are attached to every
[release on GitHub](https://github.com/oscarvalenzuelab/DNSMeshProtocol/releases).

Day-to-day flags and subcommands are in the
[CLI reference]({{ site.baseurl }}/guide/cli).

## Desktop + Android GUI — `dnsmesh-app`

A [Tauri 2](https://tauri.app) app — SvelteKit frontend, Rust host —
that wraps the `dnsmesh-rs` SDK behind a chat UI. The same codebase
builds across all four supported platforms.

Pre-built installers are published on every `v*` tag at
[github.com/oscarvalenzuelab/dnsmesh-app/releases](https://github.com/oscarvalenzuelab/dnsmesh-app/releases/latest).

| Platform | Asset |
|---|---|
| macOS, Apple Silicon (and Intel via Rosetta) | `.dmg`, `.app.tar.gz` |
| macOS, Intel | `.dmg`, `.app.tar.gz` |
| Linux x86_64 | `.deb`, `.rpm`, `.AppImage` |
| Linux aarch64 | `.deb`, `.rpm`, `.AppImage` |
| Windows x86_64 | `.msi`, `.exe` |
| Android, universal (experimental) | `.apk` (debug-signed) |

{: .warning }
Alpha builds are **unsigned** on macOS and Windows. Code-signing is
wired in CI but gated on signing-cert availability; until that lands,
Gatekeeper and SmartScreen will warn on first launch. The
[dnsmesh-app README](https://github.com/oscarvalenzuelab/dnsmesh-app#download)
documents the one-time bypass per platform.

### macOS

Download the `.dmg`, mount it, and drag **DNSMesh** into Applications.
First launch: right-click the app and pick **Open**, then confirm the
Gatekeeper dialog. macOS remembers the decision after that.

### Windows

Download the `.msi` (preferred) or the `.exe` installer. SmartScreen
will flag the unsigned publisher — click **More info → Run anyway**.

### Linux

Pick the format that matches your distro:

- `.deb` — Debian, Ubuntu, derivatives: `sudo apt install ./DNSMesh_*.deb`
- `.rpm` — Fedora, RHEL, derivatives: `sudo dnf install ./DNSMesh-*.rpm`
- `.AppImage` — universal: `chmod +x DNSMesh-*.AppImage && ./DNSMesh-*.AppImage`

### Android

Sideload the `.apk` from the releases page. Alpha builds are signed
with the Android debug keystore — installable via sideload, **not via
the Play Store**. Grant "install unknown apps" to your file manager
or browser, then open the APK and tap **Install**.

{: .note }
The Android client is **experimental**. The build pipeline proves
the APK compiles; whether DMP's DNS UPDATE traffic on port 53 fully
works inside Android's network sandbox is still being validated.
Expect rough edges and please file bugs.

### What ships in the GUI

The alpha covers the core day-to-day flow:

- **Multi-identity** with per-identity Argon2id salt and on-disk
  directory; switching is one click in the header.
- **Inbox** with read / unread, single + bulk delete, and a
  persistent JSONL log per identity so messages survive restarts.
- **Compose** with reply context. Replies quote the original sender,
  timestamp, and plaintext.
- **Contacts** with avatars, fetch-by-address (one-shot identity
  lookup + pin), manual add, and delete.
- **TSIG-authenticated DNS UPDATE publish** (RFC 2136 + RFC 8945)
  for identity records, prekey RRsets, and mailbox slots.
- **Identity backup / restore** as a single `.dmp-backup.tar.gz`
  archive (config + keystore + sqlite + persistent inbox).
- **Import from CLI** — pulls an existing identity out of the
  `dnsmesh-rs` CLI's `~/.dmp/` layout in one click.

## Rust SDK + CLI — `dnsmesh-rs`

The Rust port of the client side of the protocol. Two surfaces:

- A **client SDK** for embedding DMP into other Rust applications,
  iOS / Android apps (via UniFFI bindings), or server backends —
  no Python runtime required.
- A **standalone CLI** (`dnsmesh`) that ships as a single static
  binary and doubles as a sendmail-compatible MTA stub for `mutt`,
  `neomutt`, and other Maildir-aware clients.

Pre-built CLI binaries are published on every `cli-v*` tag at
[github.com/oscarvalenzuelab/dnsmesh-rs/releases](https://github.com/oscarvalenzuelab/dnsmesh-rs/releases).
Seven targets ship per release covering macOS (Intel + Apple Silicon),
Linux (x86_64 glibc + musl, aarch64), and Windows (x86_64 + aarch64).

```sh
# macOS Apple Silicon, latest release:
curl -fsSL -o dnsmesh.tar.gz \
  https://github.com/oscarvalenzuelab/dnsmesh-rs/releases/latest/download/dnsmesh-cli-aarch64-apple-darwin.tar.gz
tar -xzf dnsmesh.tar.gz
sudo install -m 0755 dnsmesh /usr/local/bin/
```

If you have a Rust toolchain, `cargo install` from source works the
same way it does for any other Rust CLI — see the
[`dnsmesh-rs` README](https://github.com/oscarvalenzuelab/dnsmesh-rs#install)
for the one-liner.

The node implementation stays in the Python reference — the Rust port
is intentionally **client-only**.

## Which client should I use?

- **Trying DMP for the first time, comfortable in a terminal** —
  start with the Python CLI and the
  [Getting Started]({{ site.baseurl }}/getting-started) walkthrough.
- **Want a GUI** — grab a `dnsmesh-app` installer for your platform.
  Same identity files work alongside the CLI; the **Import from CLI**
  button copies an existing `~/.dmp/` identity in one click.
- **Building DMP into another app** — link the `dnsmesh-rs` crate or
  use its UniFFI bindings. The Python reference and the Rust SDK
  share the wire format and are exercised against each other in CI.
- **Want a faster, dependency-free terminal client** — install the
  Rust CLI binary from `dnsmesh-rs` releases. No Python runtime,
  single static binary.

## Reporting issues

Each client tracks its own bugs:

- Protocol / Python CLI / node — [DNSMeshProtocol/issues](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues)
- Desktop + Android GUI — [dnsmesh-app/issues](https://github.com/oscarvalenzuelab/dnsmesh-app/issues)
- Rust SDK + CLI — [dnsmesh-rs/issues](https://github.com/oscarvalenzuelab/dnsmesh-rs/issues)

Security-sensitive reports — anything that could leak plaintext,
private keys, or undermine the trust model — go to the addresses
in each repo's `SECURITY.md`, **not** to a public issue.
