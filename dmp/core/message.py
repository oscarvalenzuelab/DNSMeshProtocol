"""Core message structures for DMP protocol"""

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any
import json


class MessageType(Enum):
    """DMP message types"""

    DATA = "DATA"
    ACK = "ACK"
    DISCOVERY = "DISCOVERY"
    IDENTITY = "IDENTITY"
    MAILBOX = "MAILBOX"


@dataclass
class DMPHeader:
    """DMP message header containing metadata"""

    version: int = 1
    message_type: MessageType = MessageType.DATA
    message_id: bytes = field(default_factory=lambda: uuid.uuid4().bytes)
    sender_id: bytes = field(default_factory=lambda: b"\x00" * 32)
    recipient_id: bytes = field(default_factory=lambda: b"\x00" * 32)
    total_chunks: int = 1
    chunk_number: int = 0
    timestamp: int = field(default_factory=lambda: int(time.time()))
    ttl: int = 300  # 5 minutes default

    def to_bytes(self) -> bytes:
        """Serialize header to bytes"""
        data = {
            "v": self.version,
            "type": self.message_type.value,
            "msg_id": self.message_id.hex(),
            "sender": self.sender_id.hex(),
            "recipient": self.recipient_id.hex(),
            "total": self.total_chunks,
            "chunk": self.chunk_number,
            "ts": self.timestamp,
            "ttl": self.ttl,
        }
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "DMPHeader":
        """Deserialize header from bytes"""
        obj = json.loads(data.decode("utf-8"))
        return cls(
            version=obj["v"],
            message_type=MessageType(obj["type"]),
            message_id=bytes.fromhex(obj["msg_id"]),
            sender_id=bytes.fromhex(obj["sender"]),
            recipient_id=bytes.fromhex(obj["recipient"]),
            total_chunks=obj["total"],
            chunk_number=obj["chunk"],
            timestamp=obj["ts"],
            ttl=obj["ttl"],
        )

    def is_expired(self) -> bool:
        """Check if message has expired based on TTL"""
        return int(time.time()) > (self.timestamp + self.ttl)

    def get_chunk_id(self) -> str:
        """Generate unique chunk identifier"""
        return f"{self.message_id.hex()}-{self.chunk_number:04d}"


@dataclass
class DMPMessage:
    """Complete DMP message with header and payload"""

    header: DMPHeader = field(default_factory=DMPHeader)
    payload: bytes = b""
    signature: bytes = b"\x00" * 32  # Poly1305 MAC placeholder

    def to_bytes(self) -> bytes:
        """Serialize complete message to bytes"""
        header_bytes = self.header.to_bytes()
        header_len = len(header_bytes).to_bytes(2, "big")
        return header_len + header_bytes + self.payload + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "DMPMessage":
        """Deserialize message from bytes"""
        if len(data) < 34:  # Minimum size: 2 (header len) + 32 (signature)
            raise ValueError("Invalid message: too short")

        header_len = int.from_bytes(data[:2], "big")
        if len(data) < 2 + header_len + 32:
            raise ValueError("Invalid message: incomplete")

        header_bytes = data[2 : 2 + header_len]
        payload = data[2 + header_len : -32]
        signature = data[-32:]

        return cls(
            header=DMPHeader.from_bytes(header_bytes),
            payload=payload,
            signature=signature,
        )

    def calculate_message_hash(self) -> bytes:
        """Calculate SHA-256 hash of the message for identification"""
        content = self.header.to_bytes() + self.payload
        return hashlib.sha256(content).digest()

    def create_chunk(self, chunk_num: int, chunk_data: bytes) -> "DMPMessage":
        """Create a chunk message from this message"""
        chunk_header = DMPHeader(
            version=self.header.version,
            message_type=self.header.message_type,
            message_id=self.header.message_id,
            sender_id=self.header.sender_id,
            recipient_id=self.header.recipient_id,
            total_chunks=self.header.total_chunks,
            chunk_number=chunk_num,
            timestamp=self.header.timestamp,
            ttl=self.header.ttl,
        )
        return DMPMessage(
            header=chunk_header, payload=chunk_data, signature=self.signature
        )

    def validate_basic(self) -> tuple[bool, str]:
        """Perform basic message validation"""
        if self.header.version != 1:
            return False, f"Unsupported version: {self.header.version}"

        if self.header.is_expired():
            return False, "Message has expired"

        if self.header.chunk_number >= self.header.total_chunks:
            return (
                False,
                f"Invalid chunk number: {self.header.chunk_number} >= {self.header.total_chunks}",
            )

        if len(self.header.message_id) != 16:
            return False, "Invalid message ID length"

        if len(self.header.sender_id) != 32:
            return False, "Invalid sender ID length"

        if len(self.header.recipient_id) != 32:
            return False, "Invalid recipient ID length"

        return True, "Valid"


@dataclass
class DMPIdentity:
    """User identity for DMP network"""

    username: str
    public_key: bytes
    created_at: int = field(default_factory=lambda: int(time.time()))
    signature: bytes = b""  # Self-signed identity
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_user_id(self) -> bytes:
        """Generate user ID from public key"""
        return hashlib.sha256(self.public_key).digest()

    def to_dns_record(self) -> str:
        """Format identity for DNS TXT record"""
        data = {
            "username": self.username,
            "pubkey": self.public_key.hex(),
            "created": self.created_at,
            "sig": self.signature.hex(),
            "meta": self.metadata,
        }
        json_str = json.dumps(data, separators=(",", ":"))
        return f"v=dmp1;type=identity;data={json_str}"

    @classmethod
    def from_dns_record(cls, record: str) -> "DMPIdentity":
        """Parse identity from DNS TXT record"""
        if not record.startswith("v=dmp1;type=identity;data="):
            raise ValueError("Invalid identity record format")

        json_str = record.split("data=", 1)[1]
        data = json.loads(json_str)

        return cls(
            username=data["username"],
            public_key=bytes.fromhex(data["pubkey"]),
            created_at=data["created"],
            signature=bytes.fromhex(data["sig"]),
            metadata=data.get("meta", {}),
        )
