"""
DNS Publisher backends for writing TXT records to authoritative DNS.

Backends:
1. DNSUpdatePublisher    - RFC 2136 DNS UPDATE (BIND9, PowerDNS)
2. CloudflarePublisher   - Cloudflare API
3. Route53Publisher      - AWS Route53
4. LocalDNSPublisher     - local dnsmasq / BIND config file
5. MultiProviderPublisher - fan-out to multiple backends for redundancy

All inherit from dmp.network.base.DNSRecordWriter. publish_txt_record and
delete_txt_record take fully-qualified domain names. Backends that need the
TXT value for deletion (Route53) use it when provided; others ignore it.

Optional third-party deps (requests, boto3) are imported lazily inside the
backends that need them so the core library stays usable without them.
"""

from typing import Optional, List

import dns.update
import dns.query
import dns.tsigkeyring
import dns.rcode

from dmp.network.base import DNSRecordWriter

# Per RFC 1035 a DNS TXT record's RDATA is a sequence of
# <character-string>s, each prefixed by a single length byte, capping
# the per-string payload at 255 bytes. A single value longer than 255
# bytes MUST be emitted as multiple character-strings within the same
# RR — not as a single over-long string (many authoritative servers and
# client libs either reject or truncate that). The M2.1 cluster
# manifest runs up to 1200 bytes post-base64, so every publisher has to
# split before handing the value to its backend.
_TXT_CHUNK_BYTES = 255


def _split_txt_value(value: str, chunk_bytes: int = _TXT_CHUNK_BYTES) -> List[str]:
    """Split a TXT value into <=chunk_bytes byte chunks for multi-string RDATA.

    DNS TXT records can carry multiple character-strings per RR. Each
    character-string has a 1-byte length prefix, so the maximum payload
    per string is 255 bytes. Values under the cap return a single-element
    list; longer values are split on byte boundaries.

    The DMP wire format (``v=dmp1;...`` prefix + base64 body) is
    all-ASCII, so splitting on byte boundaries is safe for any value
    this project publishes today. For non-ASCII values that exceed one
    chunk, a naive byte split can land mid-codepoint and break UTF-8
    decoding — rather than silently corrupt the record or emit
    provider-specific failures, we reject such inputs explicitly so
    the caller can decide (typically: base64-encode first, or use a
    binary publisher path).
    """
    raw = value.encode("utf-8")
    if len(raw) <= chunk_bytes:
        return [value]
    if not value.isascii():
        raise ValueError(
            "multi-string TXT splitting requires ASCII-safe input; "
            f"values exceeding {chunk_bytes} bytes must be ASCII "
            "(base64-encode non-ASCII payloads first)"
        )
    return [
        raw[i : i + chunk_bytes].decode("ascii")
        for i in range(0, len(raw), chunk_bytes)
    ]


class DNSUpdatePublisher(DNSRecordWriter):
    """Publish DNS records via RFC 2136 DNS UPDATE.

    Works with BIND9, PowerDNS, and other RFC 2136 compliant servers.
    """

    def __init__(
        self,
        zone: str,
        nameserver: str,
        keyname: Optional[str] = None,
        secret: Optional[str] = None,
        keyalgorithm: str = "hmac-sha256",
    ):
        self.zone = zone.rstrip(".")
        self.nameserver = nameserver
        self.keyring = None
        if keyname and secret:
            self.keyring = dns.tsigkeyring.from_text({keyname: secret})

    def _relative_name(self, name: str) -> str:
        """Strip the zone suffix from a FQDN to get the relative label."""
        name = name.rstrip(".")
        if name == self.zone:
            return "@"
        if name.endswith("." + self.zone):
            return name[: -(len(self.zone) + 1)]
        return name  # caller passed a relative label already

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        try:
            update = dns.update.Update(self.zone, keyring=self.keyring)
            rel = self._relative_name(name)
            update.delete(rel, "TXT")
            # A TXT RDATA can carry multiple quoted character-strings
            # within a single RR; dnspython parses space-separated
            # quoted strings as such. Values under 255 bytes come back
            # as a single quoted string (identical to the prior
            # behavior); longer values split across multiple strings.
            chunks = _split_txt_value(value)
            rdata_text = " ".join(f'"{c}"' for c in chunks)
            update.add(rel, ttl, "TXT", rdata_text)
            response = dns.query.tcp(update, self.nameserver, timeout=10)
            return response.rcode() == dns.rcode.NOERROR
        except Exception as e:
            print(f"DNS UPDATE failed: {e}")
            return False

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        try:
            update = dns.update.Update(self.zone, keyring=self.keyring)
            update.delete(self._relative_name(name), "TXT")
            response = dns.query.tcp(update, self.nameserver, timeout=10)
            return response.rcode() == dns.rcode.NOERROR
        except Exception as e:
            print(f"DNS DELETE failed: {e}")
            return False


class CloudflarePublisher(DNSRecordWriter):
    """Publish DNS records via the Cloudflare API.

    Free tier supports up to 1000 DNS records per zone.
    """

    def __init__(self, zone_id: str, api_token: str):
        self.zone_id = zone_id
        self.api_token = api_token
        self.base_url = (
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        )
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

    def _requests(self):
        import requests

        return requests

    def publish_txt_record(
        self, name: str, value: str, ttl: int = 300, proxied: bool = False
    ) -> bool:
        try:
            ttl = max(60, ttl)  # Cloudflare minimum TTL
            existing = self._find_record(name, "TXT")
            # Cloudflare's v4 API stores ``content`` as a literal string
            # and handles DNS wire-format string splitting internally,
            # up to their ~2048-character content cap. Passing a
            # quoted-chunk form like `"a" "b"` would be stored with
            # the literal quotes and break resolution. Pass raw.
            # Values that exceed Cloudflare's cap will get an API error
            # response (surfaced via `response.json().get("success", False)`)
            # rather than silent corruption.
            content = value
            payload = {
                "type": "TXT",
                "name": name,
                "content": content,
                "ttl": ttl,
                "proxied": proxied,
            }
            requests = self._requests()
            if existing:
                url = f"{self.base_url}/{existing['id']}"
                response = requests.put(url, headers=self.headers, json=payload)
            else:
                response = requests.post(
                    self.base_url, headers=self.headers, json=payload
                )
            return response.json().get("success", False)
        except Exception as e:
            print(f"Cloudflare API error: {e}")
            return False

    def _find_record(self, name: str, record_type: str):
        try:
            response = self._requests().get(
                self.base_url,
                headers=self.headers,
                params={"name": name, "type": record_type},
            )
            result = response.json()
            if result["success"] and result["result"]:
                return result["result"][0]
            return None
        except Exception:
            return None

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        try:
            record = self._find_record(name, "TXT")
            if not record:
                return True
            url = f"{self.base_url}/{record['id']}"
            response = self._requests().delete(url, headers=self.headers)
            return response.json().get("success", False)
        except Exception as e:
            print(f"Cloudflare delete error: {e}")
            return False


class Route53Publisher(DNSRecordWriter):
    """Publish DNS records via AWS Route53.

    Route53 DELETE requires the exact record value. If `value` is not provided
    to `delete_txt_record`, the caller gets False.
    """

    def __init__(self, hosted_zone_id: str, aws_access_key: str, aws_secret_key: str):
        import boto3

        self.hosted_zone_id = hosted_zone_id
        self.client = boto3.client(
            "route53",
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
        )

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        try:
            # Route53 represents multi-string TXT RDATA as a single
            # ``Value`` field containing space-separated quoted chunks:
            #     "chunk1" "chunk2" "chunk3"
            # Each quoted chunk must be <= 255 bytes (the RFC 1035 TXT
            # character-string cap). Values at or below the cap round-
            # trip as a single quoted string, matching the prior
            # behavior.
            chunks = _split_txt_value(value)
            record_value = " ".join(f'"{c}"' for c in chunks)
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": name,
                                "Type": "TXT",
                                "TTL": ttl,
                                "ResourceRecords": [{"Value": record_value}],
                            },
                        }
                    ]
                },
            )
            return response["ResponseMetadata"]["HTTPStatusCode"] == 200
        except Exception as e:
            print(f"Route53 error: {e}")
            return False

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        if value is None:
            # Route53 delete requires the exact record value
            return False
        try:
            # Must match the exact wire form we wrote — multi-string
            # quoted chunks for long values, single quoted string for
            # short ones. See publish_txt_record.
            chunks = _split_txt_value(value)
            record_value = " ".join(f'"{c}"' for c in chunks)
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": name,
                                "Type": "TXT",
                                "TTL": 300,
                                "ResourceRecords": [{"Value": record_value}],
                            },
                        }
                    ]
                },
            )
            return response["ResponseMetadata"]["HTTPStatusCode"] == 200
        except Exception as e:
            print(f"Route53 delete error: {e}")
            return False


class LocalDNSPublisher(DNSRecordWriter):
    """Publish DNS records to a local DNS server (dnsmasq).

    Useful for testing and private networks. Writes a dnsmasq config file and
    reloads the service via `systemctl reload dnsmasq`.
    """

    def __init__(self, config_file: str = "/etc/dnsmasq.d/dmp.conf"):
        self.config_file = config_file
        self.records: dict = {}

    def _write_and_reload(self) -> bool:
        try:
            with open(self.config_file, "w") as f:
                for d, v in self.records.items():
                    # dnsmasq's ``txt-record=name,str1,str2,...``
                    # directive takes a comma-separated list of
                    # character-strings, each of which becomes one TXT
                    # character-string on the wire. Split long values
                    # so dnsmasq emits a valid multi-string TXT RR
                    # instead of rejecting / truncating at the 255-byte
                    # cap.
                    chunks = _split_txt_value(v)
                    quoted = ",".join(f'"{c}"' for c in chunks)
                    f.write(f"txt-record={d},{quoted}\n")
            import subprocess

            subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=False)
            return True
        except Exception as e:
            print(f"Local DNS error: {e}")
            return False

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        self.records[name] = value
        return self._write_and_reload()

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        if name not in self.records:
            return False
        del self.records[name]
        return self._write_and_reload()


class MultiProviderPublisher(DNSRecordWriter):
    """Publish to multiple backends for redundancy. Succeeds if any backend does."""

    def __init__(self) -> None:
        self.providers: List[DNSRecordWriter] = []

    def add_provider(self, provider: DNSRecordWriter) -> None:
        self.providers.append(provider)

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        any_ok = False
        for provider in self.providers:
            try:
                if provider.publish_txt_record(name, value, ttl):
                    any_ok = True
            except Exception:
                continue
        return any_ok

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        any_ok = False
        for provider in self.providers:
            try:
                if provider.delete_txt_record(name, value):
                    any_ok = True
            except Exception:
                continue
        return any_ok
