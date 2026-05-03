"""DNS encapsulation and operations for DMP protocol"""

import base64
import json
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
import dns.flags
import dns.resolver
import dns.message
import dns.rdatatype
import dns.name


@dataclass
class DMPDNSRecord:
    """Container for DMP data in DNS records"""

    version: int
    record_type: str  # 'chunk', 'identity', 'mailbox', 'announce'
    data: bytes
    metadata: Dict[str, Any]

    def to_txt_record(self) -> str:
        """Convert to DNS TXT record format"""
        # Encode data as base64 for DNS compatibility
        b64_data = base64.b64encode(self.data).decode("ascii")

        # Create record string with key-value pairs
        parts = [f"v=dmp{self.version}", f"t={self.record_type}", f"d={b64_data}"]

        # Add metadata if present
        if self.metadata:
            meta_json = json.dumps(self.metadata, separators=(",", ":"))
            meta_b64 = base64.b64encode(meta_json.encode()).decode("ascii")
            parts.append(f"m={meta_b64}")

        return ";".join(parts)

    @classmethod
    def from_txt_record(cls, txt_record: str) -> "DMPDNSRecord":
        """Parse DMP data from DNS TXT record"""
        # Parse key-value pairs
        params = {}
        for part in txt_record.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                params[key.strip()] = value.strip()

        # Extract version
        version_str = params.get("v", "dmp1")
        version = int(version_str.replace("dmp", ""))

        # Extract type
        record_type = params.get("t", "chunk")

        # Decode data
        try:
            data = base64.b64decode(params.get("d", ""))
        except Exception:
            data = b""  # Default to empty on decode error

        # Decode metadata if present
        metadata = {}
        if "m" in params:
            try:
                meta_json = base64.b64decode(params["m"]).decode("utf-8")
                metadata = json.loads(meta_json)
            except (ValueError, json.JSONDecodeError):
                pass

        return cls(
            version=version, record_type=record_type, data=data, metadata=metadata
        )


class DNSEncoder:
    """Encode DMP messages for DNS transport"""

    MAX_TXT_LENGTH = 255  # DNS TXT record max length
    MAX_LABEL_LENGTH = 63  # DNS label max length
    SAFE_CHUNK_SIZE = 240  # Conservative size for base64 encoded data

    @staticmethod
    def encode_chunk_domain(chunk_id: str, message_id: bytes, base_domain: str) -> str:
        """Generate DNS domain name for a chunk"""
        # Create subdomain from chunk info
        # Format: chunk-{num}-{msg_hash}.{base_domain}
        msg_hash = hashlib.sha256(message_id).hexdigest()[:12]
        subdomain = f"chunk-{chunk_id}-{msg_hash}"

        # Ensure subdomain fits in DNS label limit
        if len(subdomain) > DNSEncoder.MAX_LABEL_LENGTH:
            subdomain = subdomain[: DNSEncoder.MAX_LABEL_LENGTH]

        return f"{subdomain}.{base_domain}"

    @staticmethod
    def encode_identity_domain(username: str, base_domain: str) -> str:
        """Generate DNS domain for user identity"""
        # Hash username for privacy and DNS compatibility
        username_hash = hashlib.sha256(username.encode()).hexdigest()[:16]
        return f"id-{username_hash}.{base_domain}"

    @staticmethod
    def encode_mailbox_domain(user_id: bytes, slot: int, base_domain: str) -> str:
        """Generate DNS domain for mailbox slot"""
        user_hash = hashlib.sha256(user_id).hexdigest()[:12]
        return f"mb-{user_hash}-{slot:02d}.{base_domain}"

    @staticmethod
    def split_for_txt_records(data: bytes) -> List[bytes]:
        """Split data into chunks suitable for TXT records"""
        chunks = []
        # Account for base64 expansion (4/3) and TXT record overhead
        chunk_size = DNSEncoder.SAFE_CHUNK_SIZE

        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            chunks.append(chunk)

        return chunks

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate that domain name is DNS-compliant"""
        if not domain or len(domain) > 253:
            return False

        labels = domain.split(".")
        for label in labels:
            if not label or len(label) > 63:
                return False
            # Check for valid characters (alphanumeric and hyphen)
            if not all(c.isalnum() or c == "-" for c in label):
                return False
            # Cannot start or end with hyphen
            if label.startswith("-") or label.endswith("-"):
                return False

        return True


class DNSOperations:
    """DNS query and response operations for DMP.

    ``dnssec_required`` (P0-4): when True the resolver requests DNSSEC
    processing (EDNS0 + DO bit) and every reply must carry the AD
    (Authenticated Data) flag — i.e. the upstream recursor DNSSEC-
    validated the answer. Replies missing AD are rejected. The trust
    boundary is the channel between this client and the recursor, so
    AD-bit policy is meaningful only over a transport an on-path
    attacker cannot rewrite (DoT/DoH or a pinned local recursor); over
    plaintext UDP to a public resolver an on-path attacker can flip AD
    and the check becomes theatre. Local trust-anchor validation is a
    larger separate project.
    """

    def __init__(
        self,
        resolvers: Optional[List[str]] = None,
        *,
        dnssec_required: bool = False,
    ):
        """Initialize with optional custom resolvers"""
        self.resolver = dns.resolver.Resolver()
        if resolvers:
            self.resolver.nameservers = resolvers
        else:
            # Use default system resolvers
            pass

        # Set reasonable timeouts
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0
        self._dnssec_required = dnssec_required
        if dnssec_required:
            # Ask the recursor to do DNSSEC processing. Without DO bit
            # many recursors strip RRSIGs and never set AD, which would
            # make every answer fail the gate even from a validating
            # resolver.
            self.resolver.use_edns(0, dns.flags.DO, 4096)

    def query_txt_record(self, domain: str) -> Optional[List[str]]:
        """Query TXT records for a domain"""
        try:
            answers = self.resolver.resolve(domain, "TXT")
            if self._dnssec_required:
                response = getattr(answers, "response", None)
                flags = getattr(response, "flags", 0) if response else 0
                if not (flags & dns.flags.AD):
                    # Upstream didn't validate (or the chain failed).
                    # Drop the answer — DMP must not consume DNS data
                    # without validation when the operator opted in.
                    return None
            records = []
            for rdata in answers:
                # TXT records can have multiple strings
                txt_data = "".join(s.decode("utf-8") for s in rdata.strings)
                records.append(txt_data)
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
            return None

    def query_dmp_record(self, domain: str) -> Optional[DMPDNSRecord]:
        """Query and parse DMP record from DNS"""
        records = self.query_txt_record(domain)
        if not records:
            return None

        # Look for DMP records (starting with v=dmp)
        for record in records:
            if record.startswith("v=dmp"):
                try:
                    return DMPDNSRecord.from_txt_record(record)
                except Exception:
                    continue

        return None

    def publish_txt_record(
        self, domain: str, record: DMPDNSRecord, ttl: int = 300
    ) -> bool:
        """Publish DMP record to DNS (requires DNS server access)"""
        # This is a placeholder - actual implementation would require
        # DNS UPDATE support or control of authoritative DNS server
        # For testing, we'll simulate success
        txt_data = record.to_txt_record()

        # Validate record doesn't exceed DNS limits
        if len(txt_data) > 255:
            return False

        # In production, this would use DNS UPDATE protocol
        # or API calls to DNS provider
        return True

    def discover_nodes(self, discovery_domain: str) -> List[str]:
        """Discover active nodes in the network"""
        nodes = []

        # Query for node announcements
        announce_domain = f"announce.{discovery_domain}"
        records = self.query_txt_record(announce_domain)

        if records:
            for record in records:
                if record.startswith("node="):
                    node_domain = record.split("=", 1)[1]
                    nodes.append(node_domain)

        return nodes

    def check_mailbox(
        self, user_id: bytes, base_domain: str, num_slots: int = 10
    ) -> List[Tuple[int, DMPDNSRecord]]:
        """Check all mailbox slots for messages"""
        messages = []

        for slot in range(num_slots):
            domain = DNSEncoder.encode_mailbox_domain(user_id, slot, base_domain)
            record = self.query_dmp_record(domain)
            if record:
                messages.append((slot, record))

        return messages


class DNSChunkManager:
    """Manage DNS-based chunk storage and retrieval"""

    def __init__(self, dns_ops: DNSOperations):
        self.dns_ops = dns_ops
        self.pending_chunks: Dict[bytes, Dict[int, bytes]] = {}

    def store_chunk(
        self, message_id: bytes, chunk_number: int, chunk_data: bytes, base_domain: str
    ) -> bool:
        """Store a chunk in DNS"""
        # Create chunk record
        chunk_id = f"{chunk_number:04d}"
        domain = DNSEncoder.encode_chunk_domain(chunk_id, message_id, base_domain)

        record = DMPDNSRecord(
            version=1,
            record_type="chunk",
            data=chunk_data,
            metadata={"chunk": chunk_number, "msg_id": message_id.hex()},
        )

        return self.dns_ops.publish_txt_record(domain, record)

    def retrieve_chunk(
        self, message_id: bytes, chunk_number: int, base_domain: str
    ) -> Optional[bytes]:
        """Retrieve a chunk from DNS"""
        chunk_id = f"{chunk_number:04d}"
        domain = DNSEncoder.encode_chunk_domain(chunk_id, message_id, base_domain)

        record = self.dns_ops.query_dmp_record(domain)
        if record and record.record_type == "chunk":
            return record.data

        return None

    def retrieve_all_chunks(
        self, message_id: bytes, total_chunks: int, base_domain: str
    ) -> Optional[List[bytes]]:
        """Retrieve all chunks for a message"""
        chunks = []

        for chunk_num in range(total_chunks):
            chunk_data = self.retrieve_chunk(message_id, chunk_num, base_domain)
            if chunk_data is None:
                return None  # Missing chunk
            chunks.append(chunk_data)

        return chunks
