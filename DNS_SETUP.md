# DNS Setup Guide for DMP

This guide shows how to set up real DNS infrastructure for the DNS Mesh Protocol.

## Option 1: DNS UPDATE Protocol (RFC 2136)

### Using BIND9

1. **Install BIND9**:
```bash
# Ubuntu/Debian
sudo apt-get install bind9 bind9utils

# macOS
brew install bind

# CentOS/RHEL
sudo yum install bind bind-utils
```

2. **Generate TSIG Key for Authentication**:
```bash
# Generate a key for dynamic updates
dnssec-keygen -a HMAC-SHA256 -b 256 -n HOST dmp-update

# Or use tsig-keygen (BIND 9.10+)
tsig-keygen -a HMAC-SHA256 dmp-update > /etc/bind/dmp-update.key
```

3. **Configure BIND9** (`/etc/bind/named.conf.local`):
```
// Include the TSIG key
include "/etc/bind/dmp-update.key";

// Define the zone
zone "mesh.yourdomain.com" {
    type master;
    file "/var/cache/bind/mesh.yourdomain.com.zone";
    
    // Allow dynamic updates with the key
    update-policy {
        grant dmp-update wildcard *.mesh.yourdomain.com TXT;
    };
};
```

4. **Create Initial Zone File** (`/var/cache/bind/mesh.yourdomain.com.zone`):
```
$ORIGIN mesh.yourdomain.com.
$TTL 300
@       IN      SOA     ns1.yourdomain.com. admin.yourdomain.com. (
                        2024010101      ; Serial
                        3600           ; Refresh
                        1800           ; Retry
                        604800         ; Expire
                        300 )          ; Negative Cache TTL

        IN      NS      ns1.yourdomain.com.

; DMP records will be added dynamically here
```

5. **Use in Python**:
```python
from dmp.network.dns_publisher import DNSUpdatePublisher

# Read the TSIG key
with open('/etc/bind/dmp-update.key') as f:
    key_data = f.read()
    # Parse key name and secret from file

publisher = DNSUpdatePublisher(
    zone='mesh.yourdomain.com',
    nameserver='127.0.0.1',  # or your DNS server IP
    keyname='dmp-update',
    secret='your-base64-key-here'
)

# Publish a chunk
success = publisher.publish_txt_record(
    subdomain='chunk-0001-abc123',
    txt_data='v=dmp1;t=chunk;d=base64data',
    ttl=300
)
```

### Using PowerDNS

1. **Install PowerDNS**:
```bash
# Ubuntu/Debian
sudo apt-get install pdns-server pdns-backend-mysql

# CentOS/RHEL
sudo yum install pdns pdns-backend-mysql
```

2. **Configure PowerDNS** (`/etc/powerdns/pdns.conf`):
```
# Enable DNS UPDATE
dnsupdate=yes
allow-dnsupdate-from=127.0.0.0/8,::1

# For TSIG authentication
tsig-algo=hmac-sha256
```

3. **Create Zone**:
```bash
pdnsutil create-zone mesh.yourdomain.com
pdnsutil set-kind mesh.yourdomain.com master
pdnsutil generate-tsig-key dmp-update hmac-sha256
pdnsutil set-meta mesh.yourdomain.com TSIG-ALLOW-DNSUPDATE dmp-update
```

## Option 2: Cloudflare (Free Tier)

1. **Sign up for Cloudflare** (free at cloudflare.com)

2. **Add your domain** and update nameservers

3. **Get API Token**:
   - Go to My Profile → API Tokens
   - Create Token → Edit zone DNS template
   - Select your zone
   - Copy the token

4. **Get Zone ID**:
   - Go to your domain dashboard
   - Copy Zone ID from the right sidebar

5. **Use in Python**:
```python
from dmp.network.dns_publisher import CloudflarePublisher

publisher = CloudflarePublisher(
    zone_id='your-zone-id-here',
    api_token='your-api-token-here'
)

# Publish a record
success = publisher.publish_txt_record(
    name='chunk-0001.mesh.yourdomain.com',
    content='v=dmp1;t=chunk;d=base64data',
    ttl=300
)
```

## Option 3: AWS Route53

1. **Create Hosted Zone** in AWS Console:
```bash
aws route53 create-hosted-zone --name mesh.yourdomain.com --caller-reference dmp-$(date +%s)
```

2. **Get Hosted Zone ID** from response

3. **Create IAM User** with Route53 permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:GetHostedZone",
                "route53:ListResourceRecordSets"
            ],
            "Resource": "arn:aws:route53:::hostedzone/YOUR-ZONE-ID"
        }
    ]
}
```

4. **Use in Python**:
```python
from dmp.network.dns_publisher import Route53Publisher

publisher = Route53Publisher(
    hosted_zone_id='Z1234567890ABC',
    aws_access_key='AKIAIOSFODNN7EXAMPLE',
    aws_secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)

success = publisher.publish_txt_record(
    name='chunk-0001.mesh.yourdomain.com',
    value='v=dmp1;t=chunk;d=base64data',
    ttl=300
)
```

## Option 4: Local Testing with dnsmasq

1. **Install dnsmasq**:
```bash
# Ubuntu/Debian
sudo apt-get install dnsmasq

# macOS
brew install dnsmasq

# CentOS/RHEL
sudo yum install dnsmasq
```

2. **Configure dnsmasq** (`/etc/dnsmasq.conf`):
```
# Listen on all interfaces
interface=*
bind-interfaces

# Define local domain
local=/mesh.local/
domain=mesh.local

# Enable DNS UPDATE
enable-ra
dhcp-authoritative

# Include DMP records
conf-dir=/etc/dnsmasq.d/,*.conf
```

3. **Create DMP config** (`/etc/dnsmasq.d/dmp.conf`):
```
# DMP TXT records (will be updated dynamically)
txt-record=test.mesh.local,"v=dmp1;t=test;d=SGVsbG8="
```

4. **Use in Python**:
```python
from dmp.network.dns_publisher import LocalDNSPublisher

publisher = LocalDNSPublisher(
    config_file='/etc/dnsmasq.d/dmp.conf'
)

success = publisher.publish_txt_record(
    domain='chunk-0001.mesh.local',
    value='v=dmp1;t=chunk;d=base64data'
)
```

## Option 5: Free Dynamic DNS Services

### Using FreeDNS (freedns.afraid.org)

1. **Sign up** for free account
2. **Create subdomain** under their domains
3. **Use their API**:

```python
import requests

def publish_to_freedns(subdomain, txt_value, api_key):
    url = f"https://freedns.afraid.org/dynamic/update.php"
    params = {
        'key': api_key,
        'hostname': f'{subdomain}.mooo.com',  # or other FreeDNS domain
        'txt': txt_value
    }
    response = requests.get(url, params=params)
    return 'Updated' in response.text
```

### Using No-IP (noip.com)

1. **Sign up** for free account (requires monthly confirmation)
2. **Create hostname**
3. **Use their API** with dynamic DNS client

## Testing Your Setup

### 1. Test DNS UPDATE:
```bash
# Test with nsupdate
nsupdate -k /etc/bind/dmp-update.key <<EOF
server 127.0.0.1
zone mesh.yourdomain.com
update add test.mesh.yourdomain.com 300 TXT "v=dmp1;t=test"
send
EOF

# Verify
dig TXT test.mesh.yourdomain.com
```

### 2. Test with Python:
```python
# Simple test script
from dmp.network.dns_publisher import DNSUpdatePublisher

publisher = DNSUpdatePublisher(
    zone='mesh.yourdomain.com',
    nameserver='127.0.0.1',
    keyname='dmp-update',
    secret='your-key'
)

# Publish test record
if publisher.publish_txt_record('test', 'Hello DMP!', ttl=60):
    print("✓ Published successfully")
    
    # Query it back
    import dns.resolver
    answers = dns.resolver.resolve('test.mesh.yourdomain.com', 'TXT')
    for rdata in answers:
        print(f"✓ Retrieved: {rdata}")
    
    # Clean up
    publisher.delete_txt_record('test')
    print("✓ Deleted test record")
else:
    print("✗ Publishing failed")
```

### 3. Full Integration Test:
```python
from dmp.client import DMPClient
from dmp.network.dns_publisher import CloudflarePublisher

# Configure client with real DNS
client = DMPClient("alice", "password")
client.dns_publisher = CloudflarePublisher(
    zone_id='your-zone-id',
    api_token='your-token'
)

# Now messages will be published to real DNS!
client.send_message("bob", "Hello via real DNS!")
```

## Security Considerations

### For BIND9/PowerDNS:
- Restrict UPDATE access by IP and TSIG key
- Use firewall rules to limit DNS access
- Rotate TSIG keys periodically
- Monitor DNS logs for abuse

### For Cloud Services:
- Use API tokens with minimal permissions
- Enable 2FA on accounts
- Rotate API keys regularly
- Set up usage alerts

### General:
- Use short TTLs (300-600 seconds) for DMP records
- Implement rate limiting in your application
- Clean up old records regularly
- Monitor DNS query volume

## Cost Comparison

| Provider | Cost | Pros | Cons |
|----------|------|------|------|
| BIND9 (self-hosted) | $5-20/mo VPS | Full control, private | Requires maintenance |
| Cloudflare | Free (1000 records) | Global CDN, DDoS protection | API rate limits |
| Route53 | $0.50/zone + $0.40/million queries | Highly reliable, AWS integration | Costs add up |
| FreeDNS | Free | No setup required | Limited features, ads |
| dnsmasq (local) | Free | Perfect for testing | Local network only |

## Recommended Setup for Production

1. **Primary**: Cloudflare (free tier) for public records
2. **Backup**: Self-hosted BIND9 for fallback
3. **Testing**: Local dnsmasq for development

```python
from dmp.network.dns_publisher import MultiProviderPublisher, CloudflarePublisher, DNSUpdatePublisher

# Set up multi-provider redundancy
publisher = MultiProviderPublisher()

# Add Cloudflare as primary
publisher.add_provider(CloudflarePublisher(
    zone_id='cloudflare-zone',
    api_token='cloudflare-token'
))

# Add BIND9 as backup
publisher.add_provider(DNSUpdatePublisher(
    zone='mesh.backup.com',
    nameserver='backup.server.ip',
    keyname='backup-key',
    secret='backup-secret'
))

# Publish to both
success = publisher.publish_txt_record(
    name='chunk-001.mesh.yourdomain.com',
    value='v=dmp1;t=chunk;d=data',
    ttl=300
)
```

## Next Steps

1. Choose your DNS provider based on your needs
2. Set up authentication (TSIG keys or API tokens)
3. Test with simple TXT record publishing
4. Integrate with DMP client
5. Monitor and optimize performance

Remember: Start with local testing (dnsmasq) or free tier (Cloudflare) before moving to production!