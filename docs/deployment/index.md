---
title: Deployment
layout: default
nav_order: 4
has_children: true
permalink: /deployment
---

# Deployment

Running a DMP node that other people publish to.

- [Docker]({{ site.baseurl }}/deployment/docker) — build, run, healthcheck,
  volumes, ports. The default path.
- [Production]({{ site.baseurl }}/deployment/production) — TLS via Caddy,
  rate limiting, per-name RRset caps, metrics scraping, env-var reference.

{: .note }
You only need to run a node if you want other people to publish to *your*
zone. Using the `dmp` CLI against someone else's node does not require you
to run one yourself — just point `--endpoint` at theirs.
