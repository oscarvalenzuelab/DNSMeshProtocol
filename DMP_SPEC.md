# DNS Mesh Protocol (DMP) - Implementation Requirements

## Project Overview

Implement a decentralized peer-to-peer messaging system that leverages the global DNS infrastructure to create a resilient, censorship-resistant communication network. The system uses DNS queries and responses to transport encrypted messages across a distributed network of DNS resolvers.

## Core Requirements

### 1. Protocol Architecture

#### 1.1 Network Topology
- Implement mesh network topology where each node can route messages for others
- Support routing through distributed DNS resolver pools (8.8.8.8, 1.1.1.1, 9.9.9.9, etc.)
- Enable automatic failover between resolvers

#### 1.2 Protocol Stack Implementation
```
┌─────────────────────────────────┐
│ Application Layer (Messages)    │
├─────────────────────────────────┤
│ DMP Security Layer (ChaCha20)   │
├─────────────────────────────────┤
│ DMP Transport Layer (Chunking)  │
├─────────────────────────────────┤
│ DNS Application Protocol        │
├─────────────────────────────────┤
│ UDP Transport Protocol          │
├─────────────────────────────────┤
│ IP Network Layer               │
└─────────────────────────────────┘
```

### 2. Message Structure and Encapsulation

#### 2.1 Core Message Classes
```python
class DMPMessage:
    def __init__(self):
        self.header = DMPHeader()
        self.payload = bytes()
        self.signature = bytes(32)  # Poly1305 MAC

class DMPHeader:
    def __init__(self):
        self.version = 1                    # Protocol version
        self.message_type = MessageType     # DATA, ACK, DISCOVERY
        self.message_id = bytes(16)         # Unique message identifier
        self.sender_id = bytes(32)          # Sender's public key hash
        self.recipient_id = bytes(32)       # Recipient's public key hash
        self.total_chunks = int             # Total number of chunks
        self.chunk_number = int             # Current chunk number
        self.timestamp = int                # Unix timestamp
        self.ttl = int                      # Time-to-live in seconds
```

#### 2.2 DNS Encapsulation Format
- Embed messages in DNS TXT records using base64 encoding
- DNS Query format: `chunk-{chunk_num}-{msg_id}.{sender_domain}`
- TXT Record format: `"v=1;t=DATA;d={base64_encoded_chunk}"`
- Example: `chunk-001-a1b2c3d4.node123.mesh.example.com`

### 3. Transport Layer Implementation

#### 3.1 Message Chunking System
```python
class MessageChunker:
    DATA_PER_CHUNK = 128  # raw bytes per chunk (before RS + checksum)

    def chunk_message(self, message: bytes, message_id: bytes) -> List[DMPChunk]:
        # Per-chunk Reed-Solomon (32 parity bytes) for bit-error repair
        # Split into DNS-compatible chunks that fit one 255-byte TXT string
        # Add SHA-256 prefix checksum for integrity
        # Return list of chunks with metadata
```

#### 3.2 Reed-Solomon Error Correction

The implementation uses **per-chunk** Reed-Solomon: each chunk carries 32
parity bytes that can repair up to 16 byte-errors inside that chunk. This is
bit-error protection, not cross-chunk erasure coding — a lost chunk still
kills the message. True RS(k, n) erasure across chunks is documented as
future work.

#### 3.3 Packet Assembly and Verification
```python
class PacketAssembler:
    def __init__(self):
        self.pending_messages = {}  # message_id -> chunks
        self.assembly_timeout = 30  # seconds
    
    def receive_chunk(self, chunk: DMPChunk) -> Optional[CompleteMessage]:
        # Verify chunk integrity and authentication
        # Assemble complete messages
        # Request missing chunks if needed
        # Use Reed-Solomon for recovery
```

### 4. Security and Encryption

#### 4.1 Hybrid Encryption System
```python
class DMPMessageCrypto:
    def __init__(self, my_private_key: X25519PrivateKey):
        # Implement X25519 key exchange + ChaCha20-Poly1305
        # Generate ephemeral keys per message
        # Provide forward secrecy
        
    def encrypt_for_recipient(self, message: bytes, recipient_public_key: X25519PublicKey) -> EncryptedMessage:
        # ECDH key exchange with ephemeral keys
        # Derive encryption keys using HKDF
        # Encrypt with ChaCha20, authenticate with Poly1305
        
    def decrypt_message(self, encrypted_msg: EncryptedMessage) -> bytes:
        # Verify authentication tags
        # Decrypt and return plaintext
```

#### 4.2 Authentication and Identity
```python
class DMPAuth:
    def create_identity(self, username: str) -> DMPIdentity:
        # Generate long-term identity keypair
        # Create signed identity record
        # Publish identity to DNS
        # Return identity object
        
    def authenticate_to_network(self) -> AuthToken:
        # Challenge-response authentication
        # Prove private key ownership without revealing it
```

#### 4.3 Security Features
- ChaCha20-Poly1305 encryption with 256-bit keys
- X25519 key exchange for forward secrecy
- Deterministic nonce generation to prevent replay attacks
- Timestamp validation for message freshness
- Per-message ephemeral keys

### 5. User Identity and Mailbox System

#### 5.1 Identity Management
```python
class IdentityDirectory:
    def publish_identity(self, identity: DMPIdentity):
        # Publish to multiple DNS locations for redundancy
        # Format: id-{username_hash}.identity.mesh.example.com
        # Reverse lookup: pk-{pubkey_hash}.identity.mesh.example.com
        
    def lookup_user(self, username: str) -> Optional[DMPIdentity]:
        # Query DNS for user identity
        # Verify identity signatures
        # Return identity object
```

#### 5.2 Mailbox System
```python
class DMPMailbox:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.mailbox_domain = f"mailbox-{hash(user_id)[:8]}.mesh.example.com"
        
    def get_mailbox_address(self) -> str:
        # Public mailbox identifier: mb-{public_key_hash}.mesh.example.com
        # 10 rotating message slots per mailbox: msg-0 through msg-9
        
    def poll_for_messages(self) -> List[EncryptedMessage]:
        # Query DNS for messages in all slots
        # Filter messages intended for this user
        # Return encrypted messages
```

### 6. Offline Message Handling

#### 6.1 Store-and-Forward System
```python
class OfflineMessageHandling:
    def send_message_to_offline_user(self, recipient: str, message: EncryptedMessage):
        # Store message on distributed storage nodes
        # 7-day TTL for offline messages
        # 3x redundancy across storage nodes
        
    def retrieve_offline_messages(self, user_id: str) -> List[EncryptedMessage]:
        # Check all potential storage nodes
        # Retrieve and delete messages after successful retrieval
        # Handle storage node failures
```

#### 6.2 Storage Node Selection
- Deterministic selection based on user ID hash
- 3x redundancy across different storage nodes
- Message availability notifications via DNS

### 7. Resolver and Network Management

#### 7.1 Dynamic Resolver Discovery
```python
class ResolverManager:
    def __init__(self):
        self.active_resolvers = set()
        self.resolver_performance = {}
        self.blacklisted_resolvers = set()
    
    def discover_resolvers(self) -> List[str]:
        # Test major public resolvers
        # Discover local ISP resolvers
        # Measure performance and reliability
        # Return ranked list of working resolvers
```

#### 7.2 Automatic Resolver Switching
```python
class ResolverFailover:
    def send_chunk_with_failover(self, chunk: DMPChunk, max_retries=3):
        # Try multiple resolvers on failure
        # Update resolver performance metrics
        # Blacklist unreliable resolvers
        # Discover new resolvers when needed
```

### 8. Mesh Routing and Peer Discovery

#### 8.1 Node Discovery Protocol
```python
class NodeDiscovery:
    def announce_presence(self):
        # Publish signed node announcements via DNS
        # Include node capabilities and public key
        # Format: announce.{node_domain}
        
    def discover_peers(self) -> List[PeerNode]:
        # Query known discovery domains
        # Verify peer signatures
        # Return list of active peers
```

#### 8.2 Mesh Routing Implementation
```python
class MeshRouter:
    def route_message(self, message: DMPMessage, destination: NodeID) -> List[NodeID]:
        # Find optimal path to destination
        # Support direct delivery and multi-hop routing
        # Implement Dijkstra's algorithm for path finding
        # Fallback to flooding for unreachable destinations
```

### 9. Implementation Architecture

#### 9.1 Client Implementation
```python
class DMPClient:
    def __init__(self, node_domain: str):
        self.node_domain = node_domain
        self.crypto = DMPMessageCrypto()
        self.resolver_manager = ResolverManager()
        self.packet_assembler = PacketAssembler()
        self.mesh_router = MeshRouter()
        self.mailbox = DMPMailbox()
        self.offline_handler = OfflineMessageHandling()
        
    def send_message(self, recipient: str, data: bytes):
        # Look up recipient identity
        # Encrypt message for recipient
        # Chunk and send via optimal resolvers
        # Handle offline recipients via storage
        
    def receive_messages(self):
        # Poll mailbox for new messages
        # Check offline storage
        # Decrypt and return messages
        
    def start_listening(self):
        # Continuous polling for incoming messages
        # Handle message assembly and verification
        # Trigger message handlers
```

#### 9.2 Server/Node Implementation
```python
class DMPServer:
    def __init__(self, domain: str):
        self.domain = domain
        self.dns_server = AuthoritativeDNSServer(domain)
        self.message_store = MessageStore()
        self.relay_service = RelayService()
        
    def start(self):
        # Start DNS server for domain
        # Start message relay service
        # Start cleanup and maintenance services
        
    def handle_dns_query(self, query: DNSQuery) -> DNSResponse:
        # Serve stored chunks
        # Handle identity lookups
        # Process standard DNS queries
```

### 10. Configuration System

#### 10.1 Node Configuration Format (YAML)
```yaml
node:
  domain: "node123.mesh.example.com"
  private_key_file: "node.key"
  public_key_file: "node.pub"

network:
  discovery_domains:
    - "mesh.example.com"
    - "nodes.dmprotocol.org"
  
  preferred_resolvers:
    - "8.8.8.8"
    - "1.1.1.1"
    - "9.9.9.9"
  
  resolver_timeout: 5
  max_chunk_retries: 3

security:
  encryption: "chacha20-poly1305"
  key_rotation_interval: 86400  # 24 hours
  max_message_age: 300  # 5 minutes

mesh:
  max_hops: 5
  relay_enabled: true
  storage_enabled: true
  cleanup_interval: 300
```

### 11. User Workflow Implementation

#### 11.1 Initial Setup Function
```python
def setup_new_user(username: str, passphrase: str):
    # Generate deterministic keypair from passphrase (PBKDF2)
    # Create and publish identity to DNS
    # Set up mailbox system
    # Save encrypted configuration
    # Return user configuration
```

#### 11.2 Daily Usage Functions
```python
def check_messages(username: str, passphrase: str):
    # Load and decrypt private key
    # Poll mailbox for new messages
    # Check offline storage nodes
    # Decrypt and return all messages
    
def send_message(username: str, passphrase: str, recipient: str, content: str):
    # Load sender's keys
    # Look up recipient's public key
    # Encrypt message for recipient
    # Send via mesh network (online or offline storage)
```

### 12. Performance and Reliability Requirements

#### 12.1 Performance Targets
- **Latency**: 2-30 seconds for message delivery (depending on DNS propagation)
- **Throughput**: Support 1000+ queries per second per resolver
- **Reliability**: 99%+ delivery rate with Reed-Solomon correction
- **Overhead**: Maximum 20% overhead for encryption and error correction

#### 12.2 Scalability Requirements
- Support unlimited nodes through distributed resolver pools
- Handle resolver failures gracefully
- Scale message storage across multiple nodes
- Efficient chunk reassembly and verification

### 13. Security Considerations

#### 13.1 Protection Against Attacks
- **Forward Secrecy**: New session keys for each conversation
- **Replay Protection**: Timestamp validation and nonce tracking
- **Traffic Analysis**: Random delays and dummy traffic capabilities
- **Key Compromise**: Automatic key rotation and revocation support
- **DNS Poisoning**: Multiple resolver verification
- **Censorship Resistance**: Dynamic resolver discovery and routing

#### 13.2 Privacy Features
- Public key-based identity (no real names required)
- Encrypted message content and metadata
- Decentralized architecture with no central logging
- Anonymous routing through mesh network

### 14. Testing and Validation Requirements

#### 14.1 Unit Tests
- Cryptographic operations (encryption/decryption)
- Message chunking and assembly
- DNS record parsing and generation
- Error correction algorithms
- Resolver management and failover

#### 14.2 Integration Tests
- End-to-end message delivery
- Multi-hop routing through mesh
- Offline message storage and retrieval
- Resolver failure scenarios
- Large message handling

#### 14.3 Performance Tests
- DNS query load testing
- Message throughput benchmarks
- Network latency measurements
- Storage scalability tests
- Concurrent user handling

### 15. Dependencies and Libraries

#### 15.1 Required Libraries
- **Cryptography**: `cryptography` library for X25519, ChaCha20, Poly1305
- **DNS**: `dnspython` for DNS operations
- **Error Correction**: `reedsolo` for Reed-Solomon coding
- **Networking**: `asyncio` for async operations
- **Configuration**: `PyYAML` for configuration parsing
- **Persistence**: `sqlite3` for local message storage

#### 15.2 Optional Dependencies
- **GUI Framework**: `tkinter` or `PyQt` for desktop client
- **Web Interface**: `Flask` or `FastAPI` for web-based client
- **Mobile**: Consider cross-platform frameworks for mobile clients

### 16. Deployment Considerations

#### 16.1 Node Deployment
- Docker containers for easy deployment
- Systemd service files for Linux servers
- Configuration management for multiple nodes
- Monitoring and logging capabilities

#### 16.2 Network Bootstrap
- Initial discovery domain setup
- Seed node configuration
- DNS zone configuration examples
- Network health monitoring

### 17. Documentation Requirements

#### 17.1 Technical Documentation
- API reference for all classes and methods
- Protocol specification document
- Security analysis and threat model
- Performance benchmarks and tuning guide

#### 17.2 User Documentation
- Installation and setup guide
- User manual for message sending/receiving
- Troubleshooting guide
- FAQ and common issues

### 18. Implementation Phases

#### Phase 1: Core Protocol
1. Message structure and serialization
2. Encryption and authentication
3. DNS encapsulation and parsing
4. Basic chunking and assembly

#### Phase 2: Network Layer
1. Resolver management and failover
2. Peer discovery and routing
3. Message relay and forwarding
4. Error correction implementation

#### Phase 3: User Interface
1. Identity management system
2. Mailbox and offline storage
3. Client application (CLI)
4. Configuration management

#### Phase 4: Advanced Features
1. Mesh routing optimization
2. Traffic analysis resistance
3. Performance optimizations
4. GUI/Web interface

#### Phase 5: Production Readiness
1. Comprehensive testing suite
2. Security audit and fixes
3. Documentation completion
4. Deployment automation

This requirements document provides a comprehensive specification for implementing the DNS Mesh Protocol using Claude Coder. Each component should be implemented with proper error handling, logging, and documentation to ensure a robust and maintainable system.
