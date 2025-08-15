# DNS Mesh Protocol (DMP)

A decentralized peer-to-peer messaging system that leverages DNS infrastructure for censorship-resistant communication.

## Features

End-to-end encryption using ChaCha20-Poly1305  
Decentralized architecture with no single point of failure  
DNS-based message transport for firewall traversal  
Reed-Solomon error correction for reliability  
Offline message storage and retrieval  
Forward secrecy with ephemeral keys

## Installation

```bash
pip install -e .
```

For development:
```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from dmp.client import DMPClient

# Initialize client
client = DMPClient("node.example.com")

# Send a message
client.send_message("alice@mesh.network", b"Hello, Alice!")

# Receive messages
messages = client.receive_messages()
```

## Testing

Run all tests:
```bash
pytest tests/ -v
```

Run specific test module:
```bash
pytest tests/test_message.py -v
pytest tests/test_crypto.py -v
pytest tests/test_dns.py -v
```

## Project Structure

```
dmp/
├── core/           # Core protocol implementation
│   ├── message.py  # Message structures
│   ├── crypto.py   # Encryption layer
│   ├── dns.py      # DNS operations
│   └── chunking.py # Message chunking
├── network/        # Network operations
├── storage/        # Persistence layer
├── client/         # Client implementation
└── server/         # Server implementation
```

## Development

Install development dependencies:
```bash
pip install -e ".[dev]"
```

Run tests with coverage:
```bash
pytest tests/ --cov=dmp --cov-report=html
```

Format code:
```bash
black dmp/ tests/
```

Type checking:
```bash
mypy dmp/
```

## Author

Oscar Valenzuela B  
oscar.valenzuela.b@gmail.com

## License

AGPL-3.0 (GNU Affero General Public License v3.0)