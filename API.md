# DMP API Documentation

## Quick Start

```python
from dmp.client import DMPClient

# Create a client
client = DMPClient("alice", "secure_passphrase")

# Publish your identity
client.publish_identity()

# Add a contact
client.add_contact("bob", "his_public_key_hex_string")

# Send a message
client.send_message("bob", "Hello Bob!")

# Receive messages
messages = client.receive_messages()
```

## Core Components

### 1. DMPClient

Main client class for interacting with the DMP network.

#### Constructor
```python
DMPClient(username: str, passphrase: str, domain: str = "mesh.local")
```

**Parameters:**
- `username`: Your chosen username
- `passphrase`: Secret passphrase for key derivation
- `domain`: DNS domain for the mesh network

**Example:**
```python
client = DMPClient("alice", "my_secret_pass", "mesh.example.com")
```

#### Methods

##### publish_identity()
Publishes your identity to the DNS network.

```python
success = client.publish_identity()
```

**Returns:** `bool` - True if published successfully

##### add_contact(username, public_key_hex)
Adds a contact to your address book.

```python
client.add_contact("bob", "4a5b6c7d8e9f...")
```

**Parameters:**
- `username`: Contact's username
- `public_key_hex`: Contact's public key as hex string

**Returns:** `bool` - True if contact added successfully

##### send_message(recipient_username, message)
Sends an encrypted message to a contact.

```python
success = client.send_message("bob", "Hello Bob!")
```

**Parameters:**
- `recipient_username`: Username of recipient
- `message`: Message text to send

**Returns:** `bool` - True if message sent successfully

##### receive_messages()
Checks for new messages.

```python
messages = client.receive_messages()
for sender, message in messages:
    print(f"From {sender}: {message}")
```

**Returns:** `List[Tuple[str, str]]` - List of (sender, message) tuples

##### get_public_key_hex()
Gets your public key as hex string.

```python
my_key = client.get_public_key_hex()
print(f"Share this key: {my_key}")
```

**Returns:** `str` - Public key as hex string

### 2. Message Structure

#### DMPMessage
Core message container.

```python
from dmp.core.message import DMPMessage, DMPHeader, MessageType

message = DMPMessage(
    header=DMPHeader(
        message_type=MessageType.DATA,
        sender_id=sender_bytes,
        recipient_id=recipient_bytes
    ),
    payload=b"Message content"
)
```

**Fields:**
- `header`: Message metadata
- `payload`: Message content (bytes)
- `signature`: Cryptographic signature

#### DMPHeader
Message header with metadata.

**Fields:**
- `version`: Protocol version (int)
- `message_type`: Type of message (MessageType enum)
- `message_id`: Unique message identifier (bytes)
- `sender_id`: Sender's ID (bytes)
- `recipient_id`: Recipient's ID (bytes)
- `total_chunks`: Total number of chunks
- `chunk_number`: Current chunk number
- `timestamp`: Unix timestamp
- `ttl`: Time-to-live in seconds

### 3. Cryptography

#### DMPCrypto
Core cryptographic operations.

```python
from dmp.core.crypto import DMPCrypto

# From passphrase
crypto = DMPCrypto.from_passphrase("my_passphrase")

# Generate new keypair
private_key, public_key = DMPCrypto.generate_keypair()

# Encrypt for recipient
encrypted = crypto.encrypt_for_recipient(
    plaintext=b"Secret message",
    recipient_public_key=recipient_key
)

# Decrypt received message
plaintext = crypto.decrypt_message(encrypted)
```

#### Key Derivation
```python
# Deterministic key from passphrase
crypto = DMPCrypto.from_passphrase("passphrase", salt=b"optional_salt")

# From private key bytes
crypto = DMPCrypto.from_private_bytes(key_bytes)
```

### 4. Message Chunking

#### MessageChunker
Splits messages into DNS-compatible chunks.

```python
from dmp.core.chunking import MessageChunker

chunker = MessageChunker(enable_error_correction=True)

# Chunk a message
chunks = chunker.chunk_message(message, include_redundancy=True)

# Each chunk is (chunk_number, chunk_data)
for chunk_num, data in chunks:
    print(f"Chunk {chunk_num}: {len(data)} bytes")
```

#### MessageAssembler
Reassembles messages from chunks.

```python
from dmp.core.chunking import MessageAssembler

assembler = MessageAssembler(enable_error_correction=True)

# Add chunks as they arrive
for chunk_num, data in chunks:
    complete_message = assembler.add_chunk(
        message_id=msg_id,
        chunk_number=chunk_num,
        chunk_data=data,
        total_chunks=total
    )
    
    if complete_message:
        print("Message complete!")
        break

# Check missing chunks
missing = assembler.get_missing_chunks(msg_id, total)
print(f"Missing chunks: {missing}")

# Get progress
progress = assembler.get_assembly_progress(msg_id, total)
print(f"Progress: {progress * 100}%")
```

### 5. DNS Operations

#### DNSEncoder
Encodes data for DNS transport.

```python
from dmp.core.dns import DNSEncoder

# Generate domains
chunk_domain = DNSEncoder.encode_chunk_domain(
    chunk_id="0001",
    message_id=msg_id,
    base_domain="mesh.example.com"
)

identity_domain = DNSEncoder.encode_identity_domain(
    username="alice",
    base_domain="mesh.example.com"
)

mailbox_domain = DNSEncoder.encode_mailbox_domain(
    user_id=user_bytes,
    slot=0,
    base_domain="mesh.example.com"
)

# Validate domain
is_valid = DNSEncoder.validate_domain("example.com")
```

#### DMPDNSRecord
Container for DNS TXT records.

```python
from dmp.core.dns import DMPDNSRecord

record = DMPDNSRecord(
    version=1,
    record_type='chunk',
    data=b'chunk data',
    metadata={'chunk': 0}
)

# Convert to TXT record
txt = record.to_txt_record()
# Output: "v=dmp1;t=chunk;d=Y2h1bmsgZGF0YQ==;m=..."

# Parse from TXT record
parsed = DMPDNSRecord.from_txt_record(txt)
```

## Complete Examples

### Example 1: Basic Messaging

```python
from dmp.client import DMPClient

# Setup clients
alice = DMPClient("alice", "alice_pass")
bob = DMPClient("bob", "bob_pass")

# Exchange public keys
alice_key = alice.get_public_key_hex()
bob_key = bob.get_public_key_hex()

# Add each other as contacts
alice.add_contact("bob", bob_key)
bob.add_contact("alice", alice_key)

# Send messages
alice.send_message("bob", "Hello Bob!")
bob.send_message("alice", "Hi Alice!")
```

### Example 2: Group Messaging

```python
# Create group members
members = []
for name in ["alice", "bob", "charlie"]:
    client = DMPClient(name, f"{name}_pass")
    client.publish_identity()
    members.append(client)

# Exchange keys
for sender in members:
    for recipient in members:
        if sender != recipient:
            sender.add_contact(
                recipient.username,
                recipient.get_public_key_hex()
            )

# Broadcast message
alice = members[0]
for member in members[1:]:
    alice.send_message(member.username, "Team meeting at 3pm")
```

### Example 3: Secure Key Exchange

```python
from dmp.core.crypto import DMPCrypto
import qrcode

# Alice generates her identity
alice_crypto = DMPCrypto.from_passphrase("alice_secure_pass")
alice_pubkey = alice_crypto.get_public_key_bytes().hex()

# Create QR code for in-person exchange
qr = qrcode.QRCode()
qr.add_data(f"dmp:{alice_pubkey}")
qr.make()
qr.print_ascii()

# Bob scans QR code and adds Alice
bob = DMPClient("bob", "bob_pass")
bob.add_contact("alice", alice_pubkey)
```

### Example 4: Offline Message Storage

```python
# Alice sends to offline Bob
alice = DMPClient("alice", "alice_pass")
alice.add_contact("bob", bob_public_key)
alice.send_message("bob", "You'll get this when you're online")

# Later, Bob comes online
bob = DMPClient("bob", "bob_pass")
messages = bob.receive_messages()

for sender, message in messages:
    print(f"Offline message from {sender}: {message}")
```

### Example 5: Error Recovery

```python
from dmp.core.chunking import MessageAssembler

assembler = MessageAssembler(enable_error_correction=True)

# Simulate receiving chunks with some missing
received_chunks = [0, 1, 3, 4]  # Chunk 2 is missing
total_chunks = 5

for chunk_num in received_chunks:
    assembler.add_chunk(
        message_id,
        chunk_num,
        chunk_data[chunk_num],
        total_chunks
    )

# Check if we can still recover
missing = assembler.get_missing_chunks(message_id, total_chunks)
if len(missing) <= total_chunks * 0.3:  # 30% redundancy
    print("Message can be recovered with Reed-Solomon!")
```

## Security Considerations

### Key Management
- Private keys are derived deterministically from passphrases
- Use strong, unique passphrases (minimum 20 characters recommended)
- Never share your passphrase or private key

### Encryption
- All messages use ChaCha20-Poly1305 authenticated encryption
- Ephemeral keys provide forward secrecy
- Each message has a unique encryption key

### Identity Verification
- Always verify public keys out-of-band (QR code, secure channel)
- Public keys are 32 bytes (64 hex characters)
- User IDs are SHA-256 hashes of public keys

### Best Practices
```python
# Good: Strong passphrase
client = DMPClient("alice", "correct-horse-battery-staple-2024")

# Bad: Weak passphrase
client = DMPClient("alice", "password123")  # Don't do this!

# Good: Verify keys
if contact_key == expected_key:
    client.add_contact("bob", contact_key)

# Good: Handle errors
try:
    client.send_message("bob", "Secret message")
except Exception as e:
    print(f"Failed to send: {e}")
```

## Troubleshooting

### Common Issues

#### 1. Import Errors
```python
# Make sure package is installed
pip install -e .

# Or add to path
import sys
sys.path.insert(0, '/path/to/DNSMeshProtocol')
```

#### 2. Missing Dependencies
```bash
pip install cryptography dnspython reedsolo pyyaml
```

#### 3. Key Derivation Takes Too Long
```python
# Reduce PBKDF2 iterations for testing (not for production!)
# Modify in dmp/core/crypto.py if needed
```

#### 4. Message Not Assembling
```python
# Check all chunks received
missing = assembler.get_missing_chunks(msg_id, total)
print(f"Missing chunks: {missing}")

# Check chunk integrity
for chunk in chunks:
    if not verify_checksum(chunk):
        print("Corrupted chunk detected")
```

## Advanced Usage

### Custom Resolver Configuration
```python
from dmp.core.dns import DNSOperations

dns_ops = DNSOperations(resolvers=['8.8.8.8', '1.1.1.1'])
```

### Manual Chunk Management
```python
from dmp.core.chunking import MessageChunker, ChunkRouter

chunker = MessageChunker(enable_error_correction=True)
router = ChunkRouter()

# Check if should forward
if router.should_forward_chunk(msg_id, chunk_num):
    destinations = router.get_forward_destinations(recipient_id)
    for dest in destinations:
        forward_chunk(dest, chunk_data)
```

### Custom Encryption Parameters
```python
from dmp.core.crypto import DMPCrypto
import os

# Custom salt for key derivation
salt = os.urandom(16)
crypto = DMPCrypto.from_passphrase("passphrase", salt=salt)

# With associated data for authentication
encrypted = crypto.encrypt_for_recipient(
    plaintext=b"message",
    recipient_public_key=key,
    associated_data=b"metadata"
)
```