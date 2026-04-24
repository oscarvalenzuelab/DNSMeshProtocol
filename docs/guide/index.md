---
title: User Guide
layout: default
nav_order: 4
has_children: true
permalink: /guide
---

# User Guide

Day-to-day use of the `dnsmesh` CLI and the `dmp` Python library.

- [CLI reference]({{ site.baseurl }}/guide/cli) — every subcommand, flag,
  and env var the CLI understands.
- [Identity and contacts]({{ site.baseurl }}/guide/identity) — how
  identities are published, how contacts are pinned, how the zone-anchored
  `user@host` addressing works.
- [Forward secrecy and prekeys]({{ site.baseurl }}/guide/forward-secrecy) —
  how the X3DH-style one-time prekeys keep past messages safe from
  long-term key compromise.
- [Registering on a multi-tenant node]({{ site.baseurl }}/guide/registration) —
  `dnsmesh register`, per-node bearer tokens, what happens when you
  hit 401 / 403 / 409 / 429.
