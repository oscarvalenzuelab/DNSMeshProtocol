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
        keyalgorithm: str = 'hmac-sha256',
    ):
        self.zone = zone.rstrip('.')
        self.nameserver = nameserver
        self.keyring = None
        if keyname and secret:
            self.keyring = dns.tsigkeyring.from_text({keyname: secret})

    def _relative_name(self, name: str) -> str:
        """Strip the zone suffix from a FQDN to get the relative label."""
        name = name.rstrip('.')
        if name == self.zone:
            return '@'
        if name.endswith('.' + self.zone):
            return name[: -(len(self.zone) + 1)]
        return name  # caller passed a relative label already

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        try:
            update = dns.update.Update(self.zone, keyring=self.keyring)
            rel = self._relative_name(name)
            update.delete(rel, 'TXT')
            update.add(rel, ttl, 'TXT', f'"{value}"')
            response = dns.query.tcp(update, self.nameserver, timeout=10)
            return response.rcode() == dns.rcode.NOERROR
        except Exception as e:
            print(f"DNS UPDATE failed: {e}")
            return False

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        try:
            update = dns.update.Update(self.zone, keyring=self.keyring)
            update.delete(self._relative_name(name), 'TXT')
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
            existing = self._find_record(name, 'TXT')
            payload = {
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": ttl,
                "proxied": proxied,
            }
            requests = self._requests()
            if existing:
                url = f"{self.base_url}/{existing['id']}"
                response = requests.put(url, headers=self.headers, json=payload)
            else:
                response = requests.post(self.base_url, headers=self.headers, json=payload)
            return response.json().get('success', False)
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
            if result['success'] and result['result']:
                return result['result'][0]
            return None
        except Exception:
            return None

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        try:
            record = self._find_record(name, 'TXT')
            if not record:
                return True
            url = f"{self.base_url}/{record['id']}"
            response = self._requests().delete(url, headers=self.headers)
            return response.json().get('success', False)
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
            'route53',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
        )

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        try:
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    'Changes': [{
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': 'TXT',
                            'TTL': ttl,
                            'ResourceRecords': [{'Value': f'"{value}"'}],
                        },
                    }]
                },
            )
            return response['ResponseMetadata']['HTTPStatusCode'] == 200
        except Exception as e:
            print(f"Route53 error: {e}")
            return False

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        if value is None:
            # Route53 delete requires the exact record value
            return False
        try:
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    'Changes': [{
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': f'"{value}"'}],
                        },
                    }]
                },
            )
            return response['ResponseMetadata']['HTTPStatusCode'] == 200
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
            with open(self.config_file, 'w') as f:
                for d, v in self.records.items():
                    f.write(f'txt-record={d},"{v}"\n')
            import subprocess
            subprocess.run(['sudo', 'systemctl', 'reload', 'dnsmasq'], check=False)
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
