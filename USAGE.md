# DMP Usage Guide

## Installation

### From Source
```bash
git clone https://github.com/yourusername/DNSMeshProtocol.git
cd DNSMeshProtocol
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

### Dependencies Only
```bash
pip install cryptography dnspython reedsolo pyyaml
```

## Basic Usage

### 1. Import the Library
```python
from dmp.client import DMPClient
from dmp.core.crypto import DMPCrypto
from dmp.core.message import DMPMessage
```

### 2. Create Your Identity
```python
# Create a client with username and passphrase
client = DMPClient("alice", "strong_passphrase_here")

# Get your public key to share with others
my_public_key = client.get_public_key_hex()
print(f"My public key: {my_public_key}")
```

### 3. Add Contacts
```python
# Add Bob's public key (obtained out-of-band)
client.add_contact("bob", "3618f3de5a97645d8c2d2e0b7dc3be25...")
```

### 4. Send Messages
```python
# Send encrypted message to Bob
client.send_message("bob", "Hello Bob! This message is encrypted.")
```

### 5. Receive Messages
```python
# Check for new messages
messages = client.receive_messages()
for sender, message in messages:
    print(f"From {sender}: {message}")
```

## Advanced Features

### Custom Encryption
```python
from dmp.core.crypto import DMPCrypto

# Generate keypair from passphrase
crypto = DMPCrypto.from_passphrase("my_secret_pass")

# Encrypt data
encrypted = crypto.encrypt_for_recipient(
    plaintext=b"Secret data",
    recipient_public_key=recipient_key
)

# Decrypt data
decrypted = crypto.decrypt_message(encrypted)
```

### Message Chunking
```python
from dmp.core.chunking import MessageChunker, MessageAssembler

# Split large message
chunker = MessageChunker(enable_error_correction=True)
chunks = chunker.chunk_message(large_message)

# Reassemble from chunks
assembler = MessageAssembler(enable_error_correction=True)
for chunk_num, chunk_data in chunks:
    complete = assembler.add_chunk(msg_id, chunk_num, chunk_data, total)
    if complete:
        print("Message assembled!")
```

### DNS Operations
```python
from dmp.core.dns import DNSEncoder, DMPDNSRecord

# Create DNS record
record = DMPDNSRecord(
    version=1,
    record_type='identity',
    data=public_key_bytes,
    metadata={'username': 'alice'}
)

# Convert to TXT record
txt_record = record.to_txt_record()
print(f"DNS TXT: {txt_record}")
```

## Testing Your Setup

### Run Unit Tests
```bash
pytest tests/ -v
```

### Run Simple Functionality Test
```bash
python examples/simple_test.py
```

### Run Demo
```bash
python examples/demo.py
```

## Security Best Practices

### Passphrase Selection
Choose a strong passphrase with:
- Minimum 20 characters
- Mix of words, numbers, and symbols
- Unique for DMP (not reused)

Example:
```python
# Good
client = DMPClient("alice", "correct-horse-battery-staple-2024!@#")

# Bad
client = DMPClient("alice", "password123")
```

### Key Verification
Always verify public keys out-of-band:
```python
# Share your key via secure channel
my_key = client.get_public_key_hex()
# Send via Signal, in person, QR code, etc.

# Verify received keys
expected_key = "3618f3de5a97645d..."
if contact_key == expected_key:
    client.add_contact("bob", contact_key)
else:
    print("WARNING: Key mismatch!")
```

### Message Handling
```python
# Always handle errors
try:
    client.send_message("bob", "Secret message")
except Exception as e:
    print(f"Failed to send: {e}")
    # Don't leak sensitive info in errors
```

## Troubleshooting

### Module Not Found
```bash
# Ensure package is installed
pip install -e .

# Or add to Python path
export PYTHONPATH=/path/to/DNSMeshProtocol:$PYTHONPATH
```

### Encryption Errors
```python
# Check key formats
assert len(public_key_bytes) == 32
assert len(private_key_bytes) == 32

# Verify recipient exists
if "bob" not in client.contacts:
    print("Add Bob as contact first")
```

### Chunking Issues
```python
# Check chunk integrity
from dmp.core.chunking import ChunkInfo
chunk = ChunkInfo(...)
if not chunk.verify_checksum():
    print("Corrupted chunk detected")

# Check missing chunks
missing = assembler.get_missing_chunks(msg_id, total)
print(f"Missing chunks: {missing}")
```

## Performance Tips

### Batch Operations
```python
# Send multiple messages efficiently
messages = [
    ("bob", "Message 1"),
    ("charlie", "Message 2"),
    ("alice", "Message 3")
]

for recipient, text in messages:
    client.send_message(recipient, text)
```

### Async Operations (Future)
```python
# Coming soon: Async support
# await client.send_message_async("bob", "Hello")
```

### Caching
```python
# Cache frequently used keys
key_cache = {}
key_cache["bob"] = bob_public_key
```

## Integration Examples

### Web Service
```python
from flask import Flask, request, jsonify

app = Flask(__name__)
client = DMPClient("service", "service_pass")

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    success = client.send_message(
        data['recipient'],
        data['message']
    )
    return jsonify({'success': success})
```

### CLI Tool
```python
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('recipient')
parser.add_argument('message')
args = parser.parse_args()

client = DMPClient("user", input("Passphrase: "))
client.send_message(args.recipient, args.message)
```

### Discord Bot
```python
import discord
from dmp.client import DMPClient

dmp = DMPClient("bot", "bot_passphrase")

@bot.command()
async def secure_send(ctx, recipient, *, message):
    success = dmp.send_message(recipient, message)
    await ctx.send(f"Sent securely: {success}")
```

## FAQ

**Q: How secure is DMP?**
A: DMP uses industry-standard ChaCha20-Poly1305 encryption with X25519 key exchange, providing strong end-to-end encryption with forward secrecy.

**Q: Can messages be intercepted?**
A: While DNS queries are visible, the message content is encrypted and can only be read by the intended recipient.

**Q: What's the message size limit?**
A: No hard limit, but larger messages take longer due to DNS chunking. Optimal size is under 10KB.

**Q: Does it work with real DNS?**
A: The current implementation simulates DNS. Real DNS integration requires control of a DNS server or zone.

**Q: Is it anonymous?**
A: DMP provides encryption, not anonymity. DNS queries can reveal communication patterns.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

AGPL-3.0 - See [LICENSE](LICENSE) for details.