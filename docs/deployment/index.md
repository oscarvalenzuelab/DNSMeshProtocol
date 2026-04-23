---
title: Deployment
layout: default
nav_order: 5
has_children: true
permalink: /deployment
---

# Deployment

Running a DMP node that other people publish to.

{: .warning }
**Must-read before production:** [Hardening]({{ site.baseurl }}/deployment/hardening)
— TLS, token hygiene, operator signing-key handling, DNS zone
hardening, file permissions, network exposure, upgrade cadence. Missing
an item here is the most common way a DMP node gets owned.

- [Docker]({{ site.baseurl }}/deployment/docker) — build, run, healthcheck,
  volumes, ports. The default path.
- [Production]({{ site.baseurl }}/deployment/production) — TLS via Caddy,
  rate limiting, per-name RRset caps, metrics scraping, env-var reference.
- [Clustered deployment]({{ site.baseurl }}/deployment/cluster) — 3-node
  federation with anti-entropy sync, for operators who need survival
  across individual node failure.
- [Hardening]({{ site.baseurl }}/deployment/hardening) — mandatory
  operator checklist before production.

{: .note }
You only need to run a node if you want other people to publish to *your*
zone. Using the `dmp` CLI against someone else's node does not require you
to run one yourself — just point `--endpoint` at theirs.
