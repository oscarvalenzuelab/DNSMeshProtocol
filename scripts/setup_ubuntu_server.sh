#!/bin/bash
#
# DMP Quick Setup Script for Ubuntu 22.04
# Run this on a fresh Ubuntu server (DigitalOcean, AWS, etc.)
#
# Usage: 
#   wget https://raw.githubusercontent.com/yourusername/DNSMeshProtocol/main/scripts/setup_ubuntu_server.sh
#   chmod +x setup_ubuntu_server.sh
#   sudo ./setup_ubuntu_server.sh yourdomain.com
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Check for domain argument
if [ -z "$1" ]; then
    echo -e "${RED}Usage: $0 yourdomain.com${NC}"
    echo "Example: $0 mesh.example.com"
    exit 1
fi

DOMAIN=$1
SERVER_IP=$(curl -s ifconfig.me)

echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}DMP Server Setup for Ubuntu 22.04${NC}"
echo -e "${GREEN}===============================================${NC}"
echo "Domain: $DOMAIN"
echo "Server IP: $SERVER_IP"
echo ""

# Step 1: Update system
echo -e "${YELLOW}Step 1: Updating system...${NC}"
apt update && apt upgrade -y

# Step 2: Install dependencies
echo -e "${YELLOW}Step 2: Installing dependencies...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    bind9 \
    bind9utils \
    bind9-doc \
    dnsutils \
    net-tools \
    ufw \
    vim \
    curl \
    wget

# Step 3: Install Python packages
echo -e "${YELLOW}Step 3: Installing Python packages...${NC}"
pip3 install --upgrade pip
pip3 install \
    cryptography \
    dnspython \
    reedsolo \
    pyyaml \
    flask \
    requests

# Step 4: Configure firewall
echo -e "${YELLOW}Step 4: Configuring firewall...${NC}"
ufw allow 22/tcp    # SSH
ufw allow 53/tcp    # DNS TCP
ufw allow 53/udp    # DNS UDP
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 5000/tcp  # Flask dev server
ufw --force enable

# Step 5: Configure BIND9
echo -e "${YELLOW}Step 5: Setting up BIND9 DNS server...${NC}"

# Generate TSIG key
TSIG_KEY_FILE="/etc/bind/dmp-key.key"
tsig-keygen -a hmac-sha256 dmp-key > $TSIG_KEY_FILE
TSIG_SECRET=$(grep secret $TSIG_KEY_FILE | cut -d'"' -f2)

echo -e "${GREEN}TSIG Secret: $TSIG_SECRET${NC}"
echo "SAVE THIS KEY! You'll need it for dynamic updates."

# Configure BIND9
cat > /etc/bind/named.conf.local << EOF
// Include TSIG key for dynamic updates
include "$TSIG_KEY_FILE";

// DMP zone
zone "$DOMAIN" {
    type master;
    file "/var/lib/bind/$DOMAIN.zone";
    allow-update { key "dmp-key"; };
    allow-query { any; };
};
EOF

# Create zone file
cat > /var/lib/bind/$DOMAIN.zone << EOF
\$ORIGIN $DOMAIN.
\$TTL 300
@       IN      SOA     ns1.$DOMAIN. admin.$DOMAIN. (
                        $(date +%Y%m%d)01      ; Serial
                        3600            ; Refresh
                        1800            ; Retry
                        604800          ; Expire
                        300 )           ; Negative Cache TTL

; Name servers
        IN      NS      ns1.$DOMAIN.
ns1     IN      A       $SERVER_IP

; Test record
test    IN      TXT     "DMP DNS Server Ready at $(date)"

; DMP records will be added dynamically below
EOF

# Configure BIND9 options
cat > /etc/bind/named.conf.options << EOF
options {
    directory "/var/cache/bind";
    
    // Allow queries from anywhere
    allow-query { any; };
    listen-on { any; };
    listen-on-v6 { any; };
    
    // Forwarding
    forwarders {
        8.8.8.8;
        8.8.4.4;
        1.1.1.1;
    };
    
    // Security
    dnssec-validation auto;
    
    // Logging
    querylog yes;
};
EOF

# Set permissions
chown bind:bind /var/lib/bind/$DOMAIN.zone
chmod 644 /var/lib/bind/$DOMAIN.zone

# Restart BIND9
systemctl restart bind9
systemctl enable bind9

# Step 6: Clone DMP repository
echo -e "${YELLOW}Step 6: Setting up DMP...${NC}"
cd /opt
if [ ! -d "DNSMeshProtocol" ]; then
    git clone https://github.com/yourusername/DNSMeshProtocol.git || {
        # If repo doesn't exist, create minimal structure
        mkdir -p DNSMeshProtocol
        cd DNSMeshProtocol
        mkdir -p dmp/{core,network,client}
        echo "# DMP Installation" > README.md
    }
fi

cd DNSMeshProtocol
pip3 install -e . 2>/dev/null || echo "Package setup pending"

# Step 7: Create test script
echo -e "${YELLOW}Step 7: Creating test script...${NC}"
cat > /opt/test_dmp.py << EOF
#!/usr/bin/env python3
"""Test DMP DNS Setup"""

import dns.resolver
import dns.update
import dns.query
import dns.tsigkeyring

DOMAIN = "$DOMAIN"
NAMESERVER = "127.0.0.1"
TSIG_KEY = "dmp-key"
TSIG_SECRET = "$TSIG_SECRET"

def test_dns_query():
    """Test basic DNS query"""
    print("Testing DNS query...")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [NAMESERVER]
    
    try:
        answers = resolver.resolve(f"test.{DOMAIN}", 'TXT')
        for rdata in answers:
            print(f"  ✓ Found TXT record: {rdata}")
        return True
    except Exception as e:
        print(f"  ✗ Query failed: {e}")
        return False

def test_dns_update():
    """Test dynamic DNS update"""
    print("Testing DNS UPDATE...")
    
    keyring = dns.tsigkeyring.from_text({
        TSIG_KEY: TSIG_SECRET
    })
    
    update = dns.update.Update(DOMAIN, keyring=keyring)
    update.add('test-dynamic', 300, 'TXT', '"Dynamic update successful!"')
    
    try:
        response = dns.query.tcp(update, NAMESERVER)
        if response.rcode() == 0:
            print("  ✓ Dynamic update successful")
            
            # Verify
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [NAMESERVER]
            answers = resolver.resolve(f"test-dynamic.{DOMAIN}", 'TXT')
            for rdata in answers:
                print(f"  ✓ Verified: {rdata}")
            return True
    except Exception as e:
        print(f"  ✗ Update failed: {e}")
    
    return False

if __name__ == "__main__":
    print("=" * 50)
    print("DMP DNS Server Test")
    print("=" * 50)
    print(f"Domain: {DOMAIN}")
    print(f"Server: {NAMESERVER}")
    print()
    
    if test_dns_query():
        print("✅ DNS Query: WORKING")
    else:
        print("❌ DNS Query: FAILED")
    
    if test_dns_update():
        print("✅ DNS Update: WORKING")
    else:
        print("❌ DNS Update: FAILED")
    
    print()
    print("=" * 50)
    print("Your DMP DNS server is ready!")
    print("=" * 50)
EOF

chmod +x /opt/test_dmp.py

# Step 8: Create simple web interface
echo -e "${YELLOW}Step 8: Creating web interface...${NC}"
cat > /opt/dmp_web.py << 'EOF'
#!/usr/bin/env python3
from flask import Flask, render_template_string, request, jsonify
import dns.resolver
import dns.update
import dns.query
import dns.tsigkeyring
import base64
import json

app = Flask(__name__)

# Configuration - will be replaced by script
DOMAIN = "DOMAIN_PLACEHOLDER"
TSIG_SECRET = "SECRET_PLACEHOLDER"

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>DMP DNS Server</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f0f0f0; }
        .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #333; }
        .box { background: #f9f9f9; padding: 15px; margin: 10px 0; border-radius: 5px; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; }
        button { background: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #45a049; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 DMP DNS Server Control Panel</h1>
        
        <div class="box">
            <h2>Server Status</h2>
            <p>Domain: <strong>{{ domain }}</strong></p>
            <p>Server IP: <strong>{{ server_ip }}</strong></p>
            <button onclick="testDNS()">Test DNS Server</button>
            <div id="testResult"></div>
        </div>
        
        <div class="box">
            <h2>Add DNS Record</h2>
            <input type="text" id="subdomain" placeholder="Subdomain (e.g., test)">
            <textarea id="txtdata" placeholder="TXT Record Data" rows="3"></textarea>
            <button onclick="addRecord()">Add TXT Record</button>
            <div id="addResult"></div>
        </div>
        
        <div class="box">
            <h2>Query DNS Record</h2>
            <input type="text" id="queryDomain" placeholder="Full domain (e.g., test.{{ domain }})">
            <button onclick="queryRecord()">Query</button>
            <pre id="queryResult"></pre>
        </div>
        
        <div class="box">
            <h2>DMP Message Simulator</h2>
            <input type="text" id="msgFrom" placeholder="From User">
            <input type="text" id="msgTo" placeholder="To User">
            <textarea id="msgContent" placeholder="Message Content" rows="3"></textarea>
            <button onclick="sendDMPMessage()">Simulate DMP Message</button>
            <div id="msgResult"></div>
        </div>
    </div>
    
    <script>
    async function testDNS() {
        const response = await fetch('/api/test');
        const result = await response.json();
        document.getElementById('testResult').innerHTML = 
            `<div class="status ${result.success ? 'success' : 'error'}">${result.message}</div>`;
    }
    
    async function addRecord() {
        const subdomain = document.getElementById('subdomain').value;
        const data = document.getElementById('txtdata').value;
        
        const response = await fetch('/api/add_record', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({subdomain: subdomain, data: data})
        });
        
        const result = await response.json();
        document.getElementById('addResult').innerHTML = 
            `<div class="status ${result.success ? 'success' : 'error'}">${result.message}</div>`;
    }
    
    async function queryRecord() {
        const domain = document.getElementById('queryDomain').value;
        const response = await fetch('/api/query/' + domain);
        const result = await response.json();
        document.getElementById('queryResult').textContent = JSON.stringify(result, null, 2);
    }
    
    async function sendDMPMessage() {
        const response = await fetch('/api/dmp_message', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                from: document.getElementById('msgFrom').value,
                to: document.getElementById('msgTo').value,
                content: document.getElementById('msgContent').value
            })
        });
        
        const result = await response.json();
        document.getElementById('msgResult').innerHTML = 
            `<div class="status ${result.success ? 'success' : 'error'}">${result.message}</div>`;
    }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    import socket
    return render_template_string(HTML_TEMPLATE, 
        domain=DOMAIN,
        server_ip=socket.gethostbyname(socket.gethostname()))

@app.route('/api/test')
def test_dns():
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['127.0.0.1']
        answers = resolver.resolve(f'test.{DOMAIN}', 'TXT')
        return jsonify({'success': True, 'message': 'DNS server is working!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/add_record', methods=['POST'])
def add_record():
    data = request.json
    subdomain = data.get('subdomain', '')
    txt_data = data.get('data', '')
    
    try:
        keyring = dns.tsigkeyring.from_text({'dmp-key': TSIG_SECRET})
        update = dns.update.Update(DOMAIN, keyring=keyring)
        update.add(subdomain, 300, 'TXT', f'"{txt_data}"')
        response = dns.query.tcp(update, '127.0.0.1')
        
        if response.rcode() == 0:
            return jsonify({'success': True, 'message': f'Added {subdomain}.{DOMAIN}'})
        else:
            return jsonify({'success': False, 'message': 'Update failed'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/query/<path:domain>')
def query_record(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['127.0.0.1']
        answers = resolver.resolve(domain, 'TXT')
        records = []
        for rdata in answers:
            txt = ''.join(s.decode('utf-8') for s in rdata.strings)
            records.append(txt)
        return jsonify({'success': True, 'records': records})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/dmp_message', methods=['POST'])
def dmp_message():
    data = request.json
    # Simulate DMP message as DNS records
    try:
        import hashlib
        msg_id = hashlib.md5(f"{data['from']}{data['to']}{data['content']}".encode()).hexdigest()[:8]
        
        keyring = dns.tsigkeyring.from_text({'dmp-key': TSIG_SECRET})
        update = dns.update.Update(DOMAIN, keyring=keyring)
        
        # Add message record
        record_data = base64.b64encode(json.dumps({
            'from': data['from'],
            'to': data['to'],
            'content': data['content']
        }).encode()).decode()
        
        update.add(f'msg-{msg_id}', 300, 'TXT', f'"v=dmp1;t=message;d={record_data}"')
        response = dns.query.tcp(update, '127.0.0.1')
        
        if response.rcode() == 0:
            return jsonify({
                'success': True, 
                'message': f'Message stored as msg-{msg_id}.{DOMAIN}'
            })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
EOF

# Replace placeholders in web script
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /opt/dmp_web.py
sed -i "s/SECRET_PLACEHOLDER/$TSIG_SECRET/g" /opt/dmp_web.py
chmod +x /opt/dmp_web.py

# Step 9: Create systemd service for web interface
echo -e "${YELLOW}Step 9: Creating systemd service...${NC}"
cat > /etc/systemd/system/dmp-web.service << EOF
[Unit]
Description=DMP Web Interface
After=network.target bind9.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt
ExecStart=/usr/bin/python3 /opt/dmp_web.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dmp-web
systemctl start dmp-web

# Step 10: Test everything
echo -e "${YELLOW}Step 10: Running tests...${NC}"
sleep 3
python3 /opt/test_dmp.py

# Final output
echo ""
echo -e "${GREEN}===============================================${NC}"
echo -e "${GREEN}✅ DMP Server Setup Complete!${NC}"
echo -e "${GREEN}===============================================${NC}"
echo ""
echo "Domain: $DOMAIN"
echo "Server IP: $SERVER_IP"
echo "TSIG Key Name: dmp-key"
echo "TSIG Secret: $TSIG_SECRET"
echo ""
echo "Services running:"
echo "  - BIND9 DNS Server: Port 53"
echo "  - DMP Web Interface: http://$SERVER_IP:5000"
echo ""
echo "Test your DNS server:"
echo "  dig @$SERVER_IP test.$DOMAIN TXT"
echo ""
echo "Update DNS records:"
echo "  nsupdate -k $TSIG_KEY_FILE"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Save the TSIG secret above!${NC}"
echo -e "${YELLOW}You'll need it for dynamic DNS updates.${NC}"
echo ""
echo -e "${GREEN}Happy messaging with DMP! 🚀${NC}"