---
title: User Guide
layout: default
nav_order: 4
has_children: true
permalink: /guide
---

# User Guide

Day-to-day use of the `dnsmesh` CLI and the `dmp` Python library.

- [CLI reference]({{ site.baseurl }}/guide/cli) — every subcommand,
  flag, and env var. Includes the `dnsmesh tsig register` flow that
  mints the per-user DNS UPDATE credential after M9.
- [Identity and contacts]({{ site.baseurl }}/guide/identity) — how
  identities are published, how contacts are pinned, how the
  zone-anchored `user@host` addressing works.
- [Forward secrecy and prekeys]({{ site.baseurl }}/guide/forward-secrecy)
  — how the X3DH-style one-time prekeys keep past messages safe from
  long-term key compromise.
- [Legacy HTTP-token registration]({{ site.baseurl }}/guide/registration)
  — `dnsmesh register` and per-node bearer tokens. **Pre-M9 path,
  preserved for back-compat.** New deployments use
  `dnsmesh tsig register` (see CLI reference above).
