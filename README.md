# DNS Mesh Protocol

**End-to-end encrypted messaging delivered over DNS. No central server,
no app store, no gatekeeper — runs on the same infrastructure the
internet already runs on.**

[**Documentation**](https://oscarvalenzuelab.github.io/DNSMeshProtocol/) ·
[**Getting started**](https://oscarvalenzuelab.github.io/DNSMeshProtocol/getting-started) ·
[**Protocol spec**](https://oscarvalenzuelab.github.io/DNSMeshProtocol/protocol) ·
[**5-min training deck**](https://oscarvalenzuelab.github.io/DNSMeshProtocol/how-resolution-works.html)

> **Status: alpha, pre-external-audit.** Wire format, federation,
> identity / key rotation, multi-tenant auth, and the formal protocol
> spec are shipped. Don't route confidentiality-critical traffic
> through DMP until the cryptographic audit lands. See
> [SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md).

## What it is

DMP is an **open protocol** for moving end-to-end encrypted messages
between two people, using DNS as the transport. The recipient looks
your records up the same way any computer looks up `google.com`.

Instead of trusting one company to relay your messages, you trust the
DNS recursive chain — which is already what every device on the
internet does for every other lookup, all day, every day. That chain
has no single owner.

If DNS works on your network, DMP works on your network.

## Try it (5 min, against the public node)

```bash
pipx install dnsmesh

dnsmesh init alice --domain dmp.dnsmesh.io --endpoint https://dnsmesh.io
dnsmesh tsig register --node dnsmesh.io     # one HTTPS hop, mints a TSIG key
dnsmesh identity publish                     # DNS UPDATE + TSIG, no more HTTPS
dnsmesh identity refresh-prekeys             # forward-secret first messages

# Add a contact you know (someone who's already published):
dnsmesh identity fetch bob@dmp.dnsmesh.io --add

# Send + receive
dnsmesh send bob@dmp.dnsmesh.io "hi bob"
dnsmesh recv
```

Curious what a node currently publishes:

```bash
dig _dnsmesh-heartbeat.dmp.dnsmesh.io TXT +short
```

Full walkthrough with troubleshooting in
[Getting Started](https://oscarvalenzuelab.github.io/DNSMeshProtocol/getting-started).

## Self-host (one VPS)

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/install.sh \
    | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
```

After install you need to **delegate a DNS subzone to the node** so
public resolvers can find the records it serves. One `NS` record at
your registrar, one env var on the node. Full walkthrough:
[Deployment → DNS subdomain delegation](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/dns-delegation).

For a clustered HA deployment (3+ nodes with anti-entropy):
[Deployment → Cluster](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/cluster).

## How the trust model works

After M9 (0.5.x), the protocol speaks DNS in both directions:

- **Reads** — plain DNS TXT queries. Anyone can resolve any user's
  identity, mailbox slots, or chunks via the public recursive chain.
- **Writes** — RFC 2136 DNS UPDATE signed with RFC 8945 TSIG. Each
  user holds a per-user TSIG key (minted via one HTTPS call to
  `/v1/registration/tsig-confirm`) scoped to their own DNS owner
  patterns. Two users sharing a node can't overwrite each other.

The only HTTPS the protocol uses for normal operation is that one
TSIG-key registration step. Everything else is DNS. Cluster
anti-entropy between same-operator nodes stays HTTPS as a documented
HA-only exception ([design note](https://oscarvalenzuelab.github.io/DNSMeshProtocol/design/cluster-anti-entropy-http-boundary)).

End-to-end encryption is X25519 ECDH + ChaCha20-Poly1305, with Ed25519
sender authentication and one-time prekeys for forward secrecy. Wire
format and crypto details: [Protocol → Wire format](https://oscarvalenzuelab.github.io/DNSMeshProtocol/protocol/wire-format).

## Not a good fit for

- Real-time chat (DNS caching gives propagation in seconds-to-minutes)
- File transfer or media payloads
- Anonymity from traffic analysis (DMP hides content, not metadata)

## Contributing

See [CONTRIBUTING.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/CONTRIBUTING.md).
1357+ tests; security-sensitive changes get an extra review round.

## License

[AGPL-3.0](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/LICENSE) — if you host DMP as a service you must publish your changes.
