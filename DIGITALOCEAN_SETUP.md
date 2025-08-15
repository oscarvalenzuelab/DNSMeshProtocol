# Complete DigitalOcean Setup for DNS Mesh Protocol

This guide will help you set up a complete DMP testing environment on DigitalOcean with your own DNS server.

## Part 1: Create DigitalOcean Droplet

### Step 1: Sign Up and Create Droplet

1. **Sign up** at [DigitalOcean](https://www.digitalocean.com/) (get $200 free credit with GitHub Student Pack or $100 with referral)

2. **Create a Droplet**:
   - Click "Create" → "Droplets"
   - Choose **Ubuntu 22.04 LTS**
   - Select cheapest plan: **$6/month** (1GB RAM, 1 CPU)
   - Choose datacenter closest to you
   - Authentication: Select **SSH keys** (more secure) or password
   - Hostname: `dmp-server`
   - Click "Create Droplet"

3. **Note your IP**: You'll get an IP like `165.232.177.123`

### Step 2: Point a Domain to Your Droplet

#### Option A: Use DigitalOcean's Free Domain (Easiest)
```bash
# DigitalOcean provides free subdomains
# Your domain will be: dmp-server-xxxxx.ondigitalocean.app
```

#### Option B: Use Your Own Domain
1. Go to "Networking" → "Domains"
2. Add your domain (e.g., `yourdomain.com`)
3. Create DNS records:
```
Type    Name    Value              TTL
A       @       165.232.177.123    3600
A       mesh    165.232.177.123    3600
NS      mesh    ns1.yourdomain.com 3600
```

#### Option C: Use a Free Domain
1. Get a free domain from [Freenom](https://www.freenom.com/) (.tk, .ml, .ga)
2. Or use [DuckDNS](https://www.duckdns.org/) for free subdomain
3. Point it to your droplet IP

## Part 2: Initial Server Setup

### Step 1: Connect to Your Droplet
```bash
# From your local machine
ssh root@165.232.177.123

# If using SSH key
ssh -i ~/.ssh/your_key root@165.232.177.123
```

### Step 2: Basic Security Setup
```bash
# Update system
apt update && apt upgrade -y

# Create non-root user
adduser dmpuser
usermod -aG sudo dmpuser

# Set up firewall
ufw allow OpenSSH
ufw allow 53/tcp
ufw allow 53/udp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# Install essential tools
apt install -y python3 python3-pip git vim curl wget net-tools dnsutils
```

### Step 3: Install Python Dependencies
```bash
# Switch to dmpuser
su - dmpuser

# Install Python packages
pip3 install cryptography dnspython reedsolo pyyaml flask

# Clone the DMP repository
git clone https://github.com/yourusername/DNSMeshProtocol.git
cd DNSMeshProtocol
pip3 install -e .
```

## Part 3: Install and Configure BIND9 DNS Server

### Step 1: Install BIND9
```bash
# As root or with sudo
sudo apt install -y bind9 bind9utils bind9-doc

# Check if running
sudo systemctl status bind9
```

### Step 2: Configure BIND9 for DMP

```bash
# Create TSIG key for dynamic updates
sudo tsig-keygen -a hmac-sha256 dmp-key | sudo tee /etc/bind/dmp-key.key

# Save the secret key that appears!
# It will look like:
# key "dmp-key" {
#     algorithm hmac-sha256;
#     secret "GJ1qPEgfNOhBmL3QLKfcIbVP8h47MwY7+WMgzZGqX8s=";
# };
```

### Step 3: Configure BIND9 Zones
```bash
# Edit named.conf.local
sudo vim /etc/bind/named.conf.local
```

Add this configuration:
```bind
// Include the TSIG key
include "/etc/bind/dmp-key.key";

// ACL for local updates
acl local-update {
    127.0.0.1;
    ::1;
};

// Main zone for your domain
zone "mesh.yourdomain.com" {
    type master;
    file "/var/lib/bind/mesh.yourdomain.com.zone";
    allow-update { key "dmp-key"; };
    allow-query { any; };
};

// Reverse zone (optional)
zone "177.232.165.in-addr.arpa" {
    type master;
    file "/var/lib/bind/165.232.177.rev";
    allow-update { key "dmp-key"; };
};
```

### Step 4: Create Initial Zone File
```bash
# Create zone file
sudo vim /var/lib/bind/mesh.yourdomain.com.zone
```

Add this content (replace with your domain and IP):
```bind
$ORIGIN mesh.yourdomain.com.
$TTL 300
@       IN      SOA     ns1.mesh.yourdomain.com. admin.yourdomain.com. (
                        2024010101      ; Serial (YYYYMMDDNN)
                        3600            ; Refresh
                        1800            ; Retry
                        604800          ; Expire
                        300 )           ; Negative Cache TTL

; Name servers
        IN      NS      ns1.mesh.yourdomain.com.

; A records
ns1     IN      A       165.232.177.123

; Initial TXT record for testing
test    IN      TXT     "DMP DNS Server Ready"

; DMP records will be added dynamically below this line
```

### Step 5: Set Permissions and Restart
```bash
# Set ownership
sudo chown bind:bind /var/lib/bind/mesh.yourdomain.com.zone

# Check configuration
sudo named-checkconf
sudo named-checkzone mesh.yourdomain.com /var/lib/bind/mesh.yourdomain.com.zone

# Restart BIND9
sudo systemctl restart bind9

# Check logs
sudo journalctl -u bind9 -f
```

## Part 4: Test DNS Setup

### Step 1: Test Local DNS Resolution
```bash
# Test from the server itself
dig @localhost test.mesh.yourdomain.com TXT

# Should return:
# test.mesh.yourdomain.com. 300 IN TXT "DMP DNS Server Ready"
```

### Step 2: Test Dynamic Updates
```bash
# Get the TSIG key secret
sudo cat /etc/bind/dmp-key.key | grep secret

# Test update with nsupdate
nsupdate -k /etc/bind/dmp-key.key <<EOF
server 127.0.0.1
zone mesh.yourdomain.com
update add test2.mesh.yourdomain.com 300 TXT "Hello from nsupdate"
send
EOF

# Verify it worked
dig @localhost test2.mesh.yourdomain.com TXT
```

### Step 3: Test from External Network
```bash
# From your local machine
dig @165.232.177.123 test.mesh.yourdomain.com TXT

# If firewall blocks, on server run:
sudo ufw allow 53
```

## Part 5: Install DMP and Create Test Script

### Step 1: Create DMP Test Script
```bash
# On the server
cd ~/DNSMeshProtocol
vim test_dmp_server.py
```

Add this code:
```python
#!/usr/bin/env python3
"""
DMP Server Test Script for DigitalOcean
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dmp.client import DMPClient
from dmp.network.dns_publisher import DNSUpdatePublisher
from dmp.core.dns import DNSEncoder, DMPDNSRecord
import dns.resolver

# Configuration - UPDATE THESE!
DOMAIN = "mesh.yourdomain.com"  # Your domain
NAMESERVER = "127.0.0.1"        # Local BIND9
TSIG_KEY_NAME = "dmp-key"        
TSIG_SECRET = "YOUR_SECRET_FROM_KEY_FILE"  # From /etc/bind/dmp-key.key

class DMPServer:
    def __init__(self):
        self.publisher = DNSUpdatePublisher(
            zone=DOMAIN,
            nameserver=NAMESERVER,
            keyname=TSIG_KEY_NAME,
            secret=TSIG_SECRET
        )
        self.clients = {}
        
    def create_user(self, username, password):
        """Create a new DMP user"""
        print(f"Creating user: {username}")
        
        client = DMPClient(username, password, DOMAIN)
        self.clients[username] = client
        
        # Publish identity to DNS
        identity_domain = f"id-{username}.{DOMAIN}"
        
        record = DMPDNSRecord(
            version=1,
            record_type='identity',
            data=client.crypto.get_public_key_bytes(),
            metadata={'username': username}
        )
        
        success = self.publisher.publish_txt_record(
            subdomain=f"id-{username}",
            txt_data=record.to_txt_record(),
            ttl=3600
        )
        
        if success:
            print(f"  ✓ Published identity to DNS: {identity_domain}")
            
            # Verify it's queryable
            time.sleep(2)
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [NAMESERVER]
            
            try:
                answers = resolver.resolve(identity_domain, 'TXT')
                print(f"  ✓ Identity verified via DNS")
                print(f"  Public key: {client.get_public_key_hex()[:32]}...")
                return client
            except Exception as e:
                print(f"  ✗ DNS verification failed: {e}")
        
        return None
    
    def send_message(self, from_user, to_user, message):
        """Send a message between users via DNS"""
        if from_user not in self.clients:
            print(f"Unknown sender: {from_user}")
            return
            
        sender = self.clients[from_user]
        
        # Look up recipient's public key
        identity_domain = f"id-{to_user}.{DOMAIN}"
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [NAMESERVER]
        
        try:
            answers = resolver.resolve(identity_domain, 'TXT')
            for rdata in answers:
                txt = ''.join(s.decode('utf-8') for s in rdata.strings)
                if 'v=dmp' in txt:
                    record = DMPDNSRecord.from_txt_record(txt)
                    recipient_key = record.data
                    break
        except:
            print(f"Cannot find {to_user}'s identity")
            return
        
        print(f"\n📤 {from_user} → {to_user}: \"{message}\"")
        
        # Create and chunk message (simplified)
        from dmp.core.message import DMPMessage, DMPHeader, MessageType
        msg = DMPMessage(
            header=DMPHeader(
                message_type=MessageType.DATA,
                sender_id=sender.user_id,
                recipient_id=recipient_key[:32]
            ),
            payload=message.encode()
        )
        
        # Store message chunks in DNS
        chunks = sender.chunker.chunk_message(msg)
        
        for i, (chunk_num, chunk_data) in enumerate(chunks):
            chunk_domain = f"msg-{msg.header.message_id.hex()[:8]}-{chunk_num:04d}"
            
            record = DMPDNSRecord(
                version=1,
                record_type='chunk',
                data=chunk_data,
                metadata={'from': from_user, 'to': to_user}
            )
            
            self.publisher.publish_txt_record(
                subdomain=chunk_domain,
                txt_data=record.to_txt_record(),
                ttl=300
            )
            
            print(f"  ✓ Published chunk {chunk_num} to DNS")
        
        print(f"  ✓ Message sent via DNS ({len(chunks)} chunks)")

def main():
    print("=" * 60)
    print("DMP Server Test on DigitalOcean")
    print("=" * 60)
    print(f"Domain: {DOMAIN}")
    print(f"DNS Server: {NAMESERVER}")
    print()
    
    server = DMPServer()
    
    # Create test users
    print("1️⃣  Creating test users...")
    alice = server.create_user("alice", "alice_password_123")
    bob = server.create_user("bob", "bob_password_456")
    
    if not alice or not bob:
        print("Failed to create users. Check DNS configuration.")
        return
    
    # Send test messages
    print("\n2️⃣  Sending test messages...")
    server.send_message("alice", "bob", "Hello Bob! This is Alice using DMP over DNS!")
    server.send_message("bob", "alice", "Hi Alice! Got your message!")
    
    # Query DNS to verify
    print("\n3️⃣  Verifying DNS records...")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [NAMESERVER]
    
    # Check identity records
    for username in ["alice", "bob"]:
        try:
            domain = f"id-{username}.{DOMAIN}"
            answers = resolver.resolve(domain, 'TXT')
            print(f"  ✓ {username}'s identity found in DNS")
        except:
            print(f"  ✗ {username}'s identity not found")
    
    print("\n" + "=" * 60)
    print("✅ DMP Server Test Complete!")
    print("Your DNS server is working with DMP!")
    print("=" * 60)

if __name__ == "__main__":
    main()
```

### Step 2: Update Configuration
```bash
# Get your TSIG secret
sudo grep secret /etc/bind/dmp-key.key

# Edit the script and update:
# - DOMAIN = "mesh.yourdomain.com"
# - TSIG_SECRET = "your-secret-here"
```

### Step 3: Run the Test
```bash
# Make executable
chmod +x test_dmp_server.py

# Run it
python3 test_dmp_server.py
```

## Part 6: Create Web Interface (Optional)

### Step 1: Create Flask Web App
```bash
vim web_interface.py
```

```python
#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify
import sys
sys.path.insert(0, '.')

from dmp.client import DMPClient
from dmp.network.dns_publisher import DNSUpdatePublisher
import dns.resolver

app = Flask(__name__)

# Configuration
DOMAIN = "mesh.yourdomain.com"
NAMESERVER = "127.0.0.1"
TSIG_KEY_NAME = "dmp-key"
TSIG_SECRET = "YOUR_SECRET_HERE"

publisher = DNSUpdatePublisher(
    zone=DOMAIN,
    nameserver=NAMESERVER,
    keyname=TSIG_KEY_NAME,
    secret=TSIG_SECRET
)

@app.route('/')
def index():
    return '''
    <html>
    <head><title>DMP Test Interface</title></head>
    <body>
        <h1>DNS Mesh Protocol Test</h1>
        <h2>Create User</h2>
        <form id="userForm">
            Username: <input type="text" id="username"><br>
            Password: <input type="password" id="password"><br>
            <button type="submit">Create User</button>
        </form>
        
        <h2>Send Message</h2>
        <form id="messageForm">
            From: <input type="text" id="from"><br>
            To: <input type="text" id="to"><br>
            Message: <input type="text" id="message"><br>
            <button type="submit">Send via DNS</button>
        </form>
        
        <h2>DNS Records</h2>
        <button onclick="checkDNS()">Check DNS Records</button>
        <pre id="dnsRecords"></pre>
        
        <script>
        document.getElementById('userForm').onsubmit = async (e) => {
            e.preventDefault();
            const response = await fetch('/create_user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            });
            const result = await response.json();
            alert(result.message);
        };
        
        document.getElementById('messageForm').onsubmit = async (e) => {
            e.preventDefault();
            const response = await fetch('/send_message', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    from: document.getElementById('from').value,
                    to: document.getElementById('to').value,
                    message: document.getElementById('message').value
                })
            });
            const result = await response.json();
            alert(result.message);
        };
        
        async function checkDNS() {
            const response = await fetch('/check_dns');
            const result = await response.json();
            document.getElementById('dnsRecords').textContent = JSON.stringify(result, null, 2);
        }
        </script>
    </body>
    </html>
    '''

@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.json
    client = DMPClient(data['username'], data['password'], DOMAIN)
    
    # Publish to DNS
    from dmp.core.dns import DMPDNSRecord
    record = DMPDNSRecord(
        version=1,
        record_type='identity',
        data=client.crypto.get_public_key_bytes(),
        metadata={'username': data['username']}
    )
    
    success = publisher.publish_txt_record(
        subdomain=f"id-{data['username']}",
        txt_data=record.to_txt_record(),
        ttl=3600
    )
    
    return jsonify({
        'success': success,
        'message': f"User {data['username']} created" if success else "Failed",
        'public_key': client.get_public_key_hex()[:32] + '...'
    })

@app.route('/check_dns')
def check_dns():
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [NAMESERVER]
    
    records = []
    # Check for identity records
    for username in ['alice', 'bob', 'charlie']:
        try:
            domain = f"id-{username}.{DOMAIN}"
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = ''.join(s.decode('utf-8') for s in rdata.strings)
                records.append({
                    'domain': domain,
                    'type': 'identity',
                    'data': txt[:100] + '...' if len(txt) > 100 else txt
                })
        except:
            pass
    
    return jsonify(records)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### Step 2: Run Web Interface
```bash
# Run Flask app
python3 web_interface.py

# Access from browser
# http://165.232.177.123:5000
```

## Part 7: Test Everything

### Step 1: Test from Your Local Machine
```bash
# From your local computer
# Install dnspython
pip install dnspython

# Create test script
cat > test_remote.py << 'EOF'
import dns.resolver

# Your server IP
SERVER_IP = "165.232.177.123"
DOMAIN = "mesh.yourdomain.com"

resolver = dns.resolver.Resolver()
resolver.nameservers = [SERVER_IP]

# Query test record
try:
    answers = resolver.resolve(f"test.{DOMAIN}", 'TXT')
    for rdata in answers:
        print(f"Found: {rdata}")
except Exception as e:
    print(f"Error: {e}")
EOF

python test_remote.py
```

### Step 2: Monitor DNS Queries
```bash
# On the server, watch DNS logs
sudo journalctl -u bind9 -f

# Or watch query log
sudo rndc querylog on
sudo tail -f /var/log/bind/queries.log
```

## Part 8: Troubleshooting

### Common Issues and Solutions

1. **DNS not responding externally**
```bash
# Check firewall
sudo ufw status
sudo ufw allow 53

# Check BIND is listening on all interfaces
sudo netstat -tlnp | grep :53
# Should show 0.0.0.0:53 not 127.0.0.1:53

# Edit /etc/bind/named.conf.options
listen-on { any; };
listen-on-v6 { any; };
allow-query { any; };
```

2. **Dynamic updates failing**
```bash
# Check TSIG key
sudo named-checkconf

# Test with debug
nsupdate -d -k /etc/bind/dmp-key.key

# Check permissions
ls -la /var/lib/bind/
sudo chown bind:bind /var/lib/bind/*.zone
```

3. **Python import errors**
```bash
# Install in correct Python
python3 -m pip install dnspython cryptography reedsolo

# Add to path
export PYTHONPATH=/home/dmpuser/DNSMeshProtocol:$PYTHONPATH
```

## Part 9: Production Considerations

### Security Hardening
```bash
# Limit DNS recursion
# In /etc/bind/named.conf.options
recursion no;

# Or limit to specific IPs
allow-recursion { 127.0.0.1; 10.0.0.0/8; };

# Rate limiting
rate-limit {
    responses-per-second 10;
    window 5;
};

# DNSSEC (optional but recommended)
dnssec-enable yes;
dnssec-validation yes;
```

### Backup and Monitoring
```bash
# Backup DNS zones
sudo cp -r /var/lib/bind /backup/

# Monitor with fail2ban
sudo apt install fail2ban
sudo vim /etc/fail2ban/jail.local
# Add:
[named-refused]
enabled = true

# Set up monitoring
# Use DigitalOcean monitoring or:
sudo apt install netdata
```

### Scaling
```bash
# For production, consider:
# 1. Secondary DNS servers
# 2. GeoDNS for global distribution
# 3. DDoS protection (Cloudflare in front)
# 4. Larger droplet (2GB+ RAM)
```

## Part 10: Clean Up

When done testing:
```bash
# Remove DNS records
nsupdate -k /etc/bind/dmp-key.key <<EOF
zone mesh.yourdomain.com
update delete *.mesh.yourdomain.com
send
EOF

# Or destroy droplet from DigitalOcean dashboard
# (This permanently deletes everything)
```

## Summary

You now have:
1. ✅ Ubuntu server on DigitalOcean ($6/month)
2. ✅ BIND9 DNS server with dynamic updates
3. ✅ DMP protocol working over real DNS
4. ✅ Test scripts to verify functionality
5. ✅ Optional web interface

Total cost: **$6/month** (or free with credits)
Setup time: **~30 minutes**

Your DMP messages are now being sent through actual DNS infrastructure! 🎉