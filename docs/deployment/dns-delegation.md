---
title: DNS subdomain delegation
layout: default
parent: Deployment
nav_order: 7
---

# DNS subdomain delegation
{: .no_toc }

Without this step a DMP node serves records that nobody can find. Reading
through it once is required for every operator who wants their node
reachable from clients on the public internet.

1. TOC
{:toc}

## The problem

DMP nodes ship two things on different ports:

- An **HTTP API** (TCP 443 behind Caddy, or 8053 directly) — used
  for registration only: clients hit `/v1/registration/tsig-confirm`
  once to mint a per-user TSIG key. Every record write after that
  is DNS UPDATE, not HTTP. (M5.5-era HTTP record routes existed at
  `/v1/records/...` and `/v1/claim/publish` but were removed in M9.)
- A **DNS authoritative server** (UDP 53) that accepts TSIG-signed
  RFC 2136 UPDATE messages from registered users and returns the
  resulting records as TXT responses to anyone who queries the right
  name.

A typical operator buys `example.com` from a registrar (Namecheap,
Google Domains, DigitalOcean, etc.), points an A record at their VPS,
adds Caddy in front, and runs `install.sh`. The HTTP side works
immediately. **The DNS side does not.**

Why: the registrar sets `example.com`'s `NS` records to its own
nameservers (e.g. `ns1.digitalocean.com`). Those nameservers serve
the website's records — but they don't know anything about the DMP
node's TXT records. So when a client asks `1.1.1.1` for
`id-XXX.example.com TXT`, the recursive chain ends at the registrar's
nameservers, which return `NXDOMAIN` (or an empty answer). The DMP
node has the data, but the public chain never asks for it.

`dig @<your-node-IP> id-XXX.example.com TXT` returns the record fine
(direct query). `dig @1.1.1.1 ...` does not. That asymmetry is the
symptom.

## The fix in one sentence

**Delegate a subdomain to your DMP node.** Add a single `NS` record at
your registrar that says "for any name under `mesh.example.com`,
ask the DMP node directly." The website at `example.com` keeps
working untouched; DMP traffic flows through the standard public
recursive chain.

```
At your registrar's DNS panel:
  mesh.example.com.   IN NS   example.com.

On the DMP node:
  DMP_DOMAIN=mesh.example.com
```

That's the whole change. The rest of this page walks through the
mechanics, registrar-specific UI, and verification.

## How a delegated query resolves

Walk through what `dig @1.1.1.1 id-XXX.mesh.example.com TXT` does after
the delegation is in place:

```
1.1.1.1                                     →   the recursive resolver the user picked
  ?  id-XXX.mesh.example.com TXT
  ↓
  asks ROOT     (.)
  ↓ root says: ".com is run by Verisign"
  asks .com    (Verisign)
  ↓ Verisign says: "example.com is at ns1.digitalocean.com"
  asks ns1.digitalocean.com
  ↓ DigitalOcean nameserver looks up the zone, sees:
  ↓   mesh.example.com  NS  example.com.
  ↓ replies: "ask example.com itself for that subdomain"
  asks example.com  (recursive resolver looks up its A record)
  ↓ resolves example.com → 24.199.107.165 (your node IP)
  asks 24.199.107.165 :53  for the TXT
  ↓ DMP node serves the record
  returns the signed identity TXT to the client
```

The website keeps working because `example.com`'s own records (A,
MX, web TXT, etc.) stay on DigitalOcean's nameservers. Only the
`mesh.example.com` subtree gets routed to your DMP node.

## Step-by-step on DigitalOcean

The dnsmesh.io reference deployment runs this exact configuration.
Adapt the names to your domain.

### 1. Confirm the node's A record exists

```
dig +short A example.com @1.1.1.1
# expected: <your-VPS-IP>
```

If empty, add the A record at the registrar before going further.
DMP delegation depends on the parent A record resolving to the node.

### 2. Add the NS record at DigitalOcean

DigitalOcean panel → Networking → Domains → `example.com` → "Add record":

- **Type:** `NS`
- **Hostname:** `mesh`         (the subdomain you're delegating)
- **Will direct to:** `example.com.`   (where the DMP node already lives)
- **TTL:** 3600 (default fine)

Click "Create record". DigitalOcean's authoritative servers pick the
change up within seconds; recursive resolvers around the world cache
the old NXDOMAIN for up to ~5 minutes before they retry.

### 3. Reconfigure the DMP node

```bash
# /etc/dnsmesh/node.env
DMP_DOMAIN=mesh.example.com
```

If you previously had `DMP_DOMAIN=example.com` (because pre-0.4.1
install.sh defaulted to the bare hostname), remove it. The
M8 claim-provider zone tracks `DMP_DOMAIN`, so this also moves
the `claim_provider_zone` advertisement to `mesh.example.com`.

```bash
sudo systemctl restart dnsmesh-node

# Verify the node is up and serving the new zone (the M5.5
# `/v1/info` HTTP route was removed in M9 — these checks replace
# it):
sudo systemctl status dnsmesh-node --no-pager | head -10
# expected: active (running)

# Confirm UDP 53 is bound:
sudo ss -ulnp | grep ':53 '
# expected: 0.0.0.0:53 ... users:(("python",...))

# (Optional, requires DMP_HEARTBEAT_ENABLED=1) Decode the
# advertised served-zone from the heartbeat wire:
dig +short @127.0.0.1 _dnsmesh-heartbeat.mesh.example.com TXT
# expected on a heartbeat-enabled node: "v=dmp1;t=heartbeat;..."
# Empty on heartbeat-disabled nodes; that's fine — heartbeat is
# opt-in and the rest of step 4 below verifies delegation
# end-to-end without it.
```

### 4. Verify the public DNS chain

```bash
# Pick any record the node is serving — easiest to publish a fresh
# identity and dig the resulting name.
dnsmesh init alice --domain mesh.example.com --endpoint https://example.com
dnsmesh tsig register --node example.com
dnsmesh identity publish
# → published identity to id-XXX.mesh.example.com

dig +short @1.1.1.1 id-XXX.mesh.example.com TXT
# expected: "v=dmp1;t=identity;d=..."
```

If `@1.1.1.1` returns the record, delegation is working. Other
recursive resolvers (`8.8.8.8`, your ISP's, etc.) pick it up within
a minute or two as their NXDOMAIN caches expire.

If `@1.1.1.1` returns empty but `dig @<your-node-IP>
id-XXX.mesh.example.com TXT` returns the record, the NS record at
the registrar didn't propagate — wait a few minutes and re-check, or
verify the panel saved it correctly.

## Step-by-step on a generic registrar

The DigitalOcean instructions translate one-for-one to any DNS
provider that exposes raw record types. The pattern is always:

```
At the parent zone (example.com):
  Type:     NS
  Name:     mesh                 (the subdomain label)
  Value:    example.com.         (FQDN trailing dot, where the DMP node lives)
  TTL:      3600
```

Some hosted DNS panels hide raw `NS` record entry behind "subdomain
delegation" or "vanity DNS". Look for that wording. If your panel
*only* exposes `A`/`AAAA`/`CNAME`/`MX`/`TXT`, the registrar doesn't
support per-subdomain delegation — switch the parent zone's
nameservers to a provider that does (Cloudflare, DigitalOcean,
Route 53, etc.) and re-add the NS there.

## Why not delegate the whole zone?

You could change `example.com`'s NS records at the registrar to
point directly at the DMP node:

```
At registrar:
  example.com.   IN NS   example.com.
```

That works for DMP records. It also makes your DMP node the single
authoritative DNS server for *the entire domain* — including the A
record for `example.com` itself, your MX records, any other web
services on the same domain. Any DMP node downtime takes the whole
domain offline.

Subdomain delegation isolates DMP from the rest of your DNS surface.
A node restart, OS reboot, or operator key rotation only affects
records under `mesh.example.com`. The website at `example.com`
keeps resolving through DigitalOcean's redundant nameservers.

The only situation where full-zone delegation is worth it: you're
running DMP on a domain reserved purely for DMP (no website, no
mail), AND you've put a redundant DNS deployment in front of the
DMP node (anycast, multiple nodes serving the same zone).
For most operators, **subdomain delegation is the answer**.

## Glue-record edge case

`mesh.example.com NS example.com.` only works because `example.com`
already resolves to a public IP through the parent zone. If you'd
rather delegate to a host *under* the same subdomain
(`mesh.example.com NS dns.mesh.example.com.`), you'll hit a
chicken-and-egg loop — the resolver needs to know `dns.mesh.example.com`'s
A record to ask it about `mesh.example.com`, but that A record is
itself under `mesh.example.com`.

Registrars solve this with **glue records** — an A record published
in the *parent* zone for the child nameserver. DigitalOcean and
most modern panels add this automatically when you create an NS
record pointing at a name under the delegated zone. If your panel
doesn't, delegate to `example.com.` instead (no glue needed).

## DNS server settings on the node

The DMP node needs to:

- Bind UDP 53 on the public interface so resolvers can reach it. The
  systemd unit installed by `deploy/native-ubuntu/install.sh` grants
  `CAP_NET_BIND_SERVICE` so the process can bind the privileged port
  without running as root. Verify:

  ```bash
  sudo ss -ulnp | grep ':53 '
  # expected: 0.0.0.0:53 ... users:(("python",...))
  ```

- Have the firewall pass UDP 53 inbound. On a DigitalOcean Cloud
  Firewall, add an allow rule for UDP 53 from `0.0.0.0/0`.

- Serve responses for the delegated zone (`DMP_DOMAIN`). The DMP
  node's DNS server is authoritative for whatever zone you set
  there — it doesn't recurse, it doesn't proxy, it just serves the
  records it has.

## Heartbeat + cross-zone interaction

After delegation, claims gossiped between providers still flow
correctly — peer nodes harvest the advertised provider zone from
the heartbeat wire's `claim_provider_zone` field
(at `_dnsmesh-heartbeat.<served-zone>` TXT) on the next tick.
No further reconfiguration on peer nodes is required; the new
zone propagates automatically through the seen-graph at
`_dnsmesh-seen.<each-peer's-zone>`.

## Multiple zones on one node

A single DMP node can serve multiple subdomains as long as it's
the authoritative DNS for each. To do this:

1. Delegate each subdomain at the registrar:
   ```
   mesh.example.com.   IN NS   example.com.
   alt.example.com.    IN NS   example.com.
   ```
2. Configure the node to serve both. The current implementation
   uses a single `DMP_DOMAIN` env var; multi-zone support is
   tracked under future-work and not yet wired into the
   `dmp/server/dns_server.py` resolver. For now: one delegated
   subdomain per node, OR run multiple node processes each bound
   to a different DNS port and fronted by a single recursive layer.

## Troubleshooting

| Symptom | Diagnose | Fix |
|---|---|---|
| `dig @1.1.1.1 id-XXX.mesh.example.com TXT` returns empty | Delegation not propagated | Wait 5 min; re-check the registrar panel |
| `dig @<node-IP>:53 ...` ALSO returns empty | Node isn't serving the zone | Check `DMP_DOMAIN` matches the delegated subdomain; restart `dnsmesh-node` |
| Records resolve fine but `_dnsmesh-heartbeat.<zone>` decodes the OLD `claim_provider_zone` | Service didn't restart, OR stale wire hasn't expired yet | `sudo systemctl restart dnsmesh-node` (orphan-sweep clears stale wires from 0.5.2 onward) |
| Public DNS reaches the node but TXT is empty | Wrong zone in DMP_DOMAIN | Match `DMP_DOMAIN=mesh.example.com` exactly to the delegated subdomain (no trailing dot) |
| `dig @1.1.1.1` returns SERVFAIL | Node DNS server isn't responding to UDP 53 | Check firewall, `ss -ulnp`, and `journalctl -u dnsmesh-node` |

## Reference: dnsmesh.io vs dnsmesh.pro

The two reference deployments illustrate both patterns:

| | dnsmesh.io | dnsmesh.pro |
|---|---|---|
| Parent zone | `dnsmesh.io` (DigitalOcean DNS) | `dnsmesh.pro` (DigitalOcean DNS) |
| Website | yes (Jekyll site under same hostname) | yes |
| DMP delegation | not yet — pending subdomain delegation | not yet — same |
| Recommended fix | `mesh.dnsmesh.io NS dnsmesh.io.` + `DMP_DOMAIN=mesh.dnsmesh.io` | `mesh.dnsmesh.pro NS dnsmesh.pro.` + `DMP_DOMAIN=mesh.dnsmesh.pro` |

Without the delegation, both nodes serve their records correctly
under direct query (`dig @<node-IP>`) but are invisible to the
public recursive chain. Cross-server messaging in those
conditions still works as long as both client CLIs include the
node IPs explicitly via `--dns-resolvers` — the live io ↔ pro
e2e validation that exercised this path is documented in the
[CHANGELOG]({{ site.baseurl }}/CHANGELOG/) under 0.4.x.

After both nodes apply the subdomain delegation, no `--dns-resolvers`
override is needed; clients on any network reach DMP records through
their normal resolver and `dnsmesh init alice@mesh.dnsmesh.io
--endpoint dnsmesh.io` Just Works.
