"""
DNS Publisher - Methods to dynamically publish TXT records

This module provides multiple methods to publish DNS TXT records:
1. DNS UPDATE (RFC 2136) - Direct DNS server updates
2. Cloudflare API - Using Cloudflare's DNS service
3. Route53 API - Using AWS Route53
4. Local DNS Server - Using dnsmasq or BIND9
"""

import dns.update
import dns.query
import dns.tsigkeyring
import dns.resolver
import requests
import json
import time
from typing import Optional, Dict, Any
import boto3


class DNSUpdatePublisher:
    """
    Publish DNS records using DNS UPDATE protocol (RFC 2136)
    Works with BIND9, PowerDNS, and other RFC 2136 compliant servers
    """
    
    def __init__(self, 
                 zone: str,
                 nameserver: str,
                 keyname: Optional[str] = None,
                 secret: Optional[str] = None,
                 keyalgorithm: str = 'hmac-sha256'):
        """
        Initialize DNS UPDATE publisher
        
        Args:
            zone: DNS zone to update (e.g., 'mesh.example.com')
            nameserver: DNS server IP that accepts updates
            keyname: TSIG key name for authentication (optional)
            secret: TSIG secret key in base64 (optional)
            keyalgorithm: TSIG algorithm (default: hmac-sha256)
        """
        self.zone = zone
        self.nameserver = nameserver
        self.keyring = None
        
        if keyname and secret:
            # Create TSIG keyring for authenticated updates
            self.keyring = dns.tsigkeyring.from_text({
                keyname: secret
            })
        
    def publish_txt_record(self, 
                          subdomain: str, 
                          txt_data: str, 
                          ttl: int = 300) -> bool:
        """
        Publish a TXT record using DNS UPDATE
        
        Args:
            subdomain: Subdomain to create (e.g., 'chunk-001')
            txt_data: TXT record data
            ttl: Time to live in seconds
            
        Returns:
            bool: True if successful
        """
        try:
            # Create update message
            update = dns.update.Update(self.zone, keyring=self.keyring)
            
            # Delete any existing record and add new one
            fqdn = f"{subdomain}.{self.zone}"
            update.delete(subdomain, 'TXT')
            update.add(subdomain, ttl, 'TXT', f'"{txt_data}"')
            
            # Send update to server
            response = dns.query.tcp(update, self.nameserver, timeout=10)
            
            # Check response code
            return response.rcode() == dns.rcode.NOERROR
            
        except Exception as e:
            print(f"DNS UPDATE failed: {e}")
            return False
    
    def delete_txt_record(self, subdomain: str) -> bool:
        """Delete a TXT record"""
        try:
            update = dns.update.Update(self.zone, keyring=self.keyring)
            update.delete(subdomain, 'TXT')
            response = dns.query.tcp(update, self.nameserver, timeout=10)
            return response.rcode() == dns.rcode.NOERROR
        except Exception as e:
            print(f"DNS DELETE failed: {e}")
            return False


class CloudflarePublisher:
    """
    Publish DNS records using Cloudflare API
    Free tier supports up to 1000 DNS records
    """
    
    def __init__(self, zone_id: str, api_token: str):
        """
        Initialize Cloudflare publisher
        
        Args:
            zone_id: Cloudflare zone ID
            api_token: Cloudflare API token with DNS edit permissions
        """
        self.zone_id = zone_id
        self.api_token = api_token
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
    def publish_txt_record(self, 
                          name: str, 
                          content: str, 
                          ttl: int = 300,
                          proxied: bool = False) -> bool:
        """
        Publish TXT record to Cloudflare
        
        Args:
            name: Full domain name (e.g., 'chunk-001.mesh.example.com')
            content: TXT record content
            ttl: TTL in seconds (min 60 for Cloudflare)
            proxied: Whether to proxy through Cloudflare (usually False for TXT)
        """
        try:
            # Cloudflare minimum TTL is 60 seconds
            ttl = max(60, ttl)
            
            # Check if record exists
            existing = self._find_record(name, 'TXT')
            
            if existing:
                # Update existing record
                url = f"{self.base_url}/{existing['id']}"
                response = requests.put(url, headers=self.headers, json={
                    "type": "TXT",
                    "name": name,
                    "content": content,
                    "ttl": ttl,
                    "proxied": proxied
                })
            else:
                # Create new record
                response = requests.post(self.base_url, headers=self.headers, json={
                    "type": "TXT",
                    "name": name,
                    "content": content,
                    "ttl": ttl,
                    "proxied": proxied
                })
            
            result = response.json()
            return result.get('success', False)
            
        except Exception as e:
            print(f"Cloudflare API error: {e}")
            return False
    
    def _find_record(self, name: str, record_type: str) -> Optional[Dict]:
        """Find existing DNS record"""
        try:
            response = requests.get(
                self.base_url,
                headers=self.headers,
                params={"name": name, "type": record_type}
            )
            result = response.json()
            if result['success'] and result['result']:
                return result['result'][0]
            return None
        except:
            return None
    
    def delete_txt_record(self, name: str) -> bool:
        """Delete TXT record from Cloudflare"""
        try:
            record = self._find_record(name, 'TXT')
            if record:
                url = f"{self.base_url}/{record['id']}"
                response = requests.delete(url, headers=self.headers)
                return response.json().get('success', False)
            return True
        except Exception as e:
            print(f"Cloudflare delete error: {e}")
            return False


class Route53Publisher:
    """
    Publish DNS records using AWS Route53
    Costs ~$0.50 per hosted zone per month + $0.40 per million queries
    """
    
    def __init__(self, hosted_zone_id: str, aws_access_key: str, aws_secret_key: str):
        """
        Initialize Route53 publisher
        
        Args:
            hosted_zone_id: Route53 hosted zone ID
            aws_access_key: AWS access key
            aws_secret_key: AWS secret key
        """
        self.hosted_zone_id = hosted_zone_id
        self.client = boto3.client(
            'route53',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )
    
    def publish_txt_record(self, 
                          name: str, 
                          value: str, 
                          ttl: int = 300) -> bool:
        """
        Publish TXT record to Route53
        
        Args:
            name: Full domain name
            value: TXT record value
            ttl: TTL in seconds
        """
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
                            'ResourceRecords': [{'Value': f'"{value}"'}]
                        }
                    }]
                }
            )
            return response['ResponseMetadata']['HTTPStatusCode'] == 200
        except Exception as e:
            print(f"Route53 error: {e}")
            return False
    
    def delete_txt_record(self, name: str, value: str) -> bool:
        """Delete TXT record from Route53"""
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
                            'ResourceRecords': [{'Value': f'"{value}"'}]
                        }
                    }]
                }
            )
            return response['ResponseMetadata']['HTTPStatusCode'] == 200
        except Exception as e:
            print(f"Route53 delete error: {e}")
            return False


class LocalDNSPublisher:
    """
    Publish DNS records to a local DNS server (dnsmasq or BIND9)
    Useful for testing and private networks
    """
    
    def __init__(self, config_file: str = "/etc/dnsmasq.d/dmp.conf"):
        """
        Initialize local DNS publisher
        
        Args:
            config_file: Path to DNS configuration file
        """
        self.config_file = config_file
        self.records = {}
        
    def publish_txt_record(self, 
                          domain: str, 
                          value: str, 
                          ttl: int = 300) -> bool:
        """
        Add TXT record to local DNS configuration
        
        For dnsmasq: txt-record=domain,"value"
        For BIND9: domain IN TXT "value"
        """
        try:
            self.records[domain] = value
            
            # Write dnsmasq config
            with open(self.config_file, 'w') as f:
                for d, v in self.records.items():
                    f.write(f'txt-record={d},"{v}"\n')
            
            # Reload dnsmasq
            import subprocess
            subprocess.run(['sudo', 'systemctl', 'reload', 'dnsmasq'], check=False)
            return True
            
        except Exception as e:
            print(f"Local DNS error: {e}")
            return False


class MultiProviderPublisher:
    """
    Publish to multiple DNS providers for redundancy
    """
    
    def __init__(self):
        self.providers = []
    
    def add_provider(self, provider):
        """Add a DNS provider"""
        self.providers.append(provider)
    
    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Publish to all providers"""
        success_count = 0
        for provider in self.providers:
            try:
                if provider.publish_txt_record(name, value, ttl):
                    success_count += 1
            except:
                pass
        return success_count > 0
    
    def delete_txt_record(self, name: str) -> bool:
        """Delete from all providers"""
        success_count = 0
        for provider in self.providers:
            try:
                if hasattr(provider, 'delete_txt_record'):
                    if provider.delete_txt_record(name):
                        success_count += 1
            except:
                pass
        return success_count > 0