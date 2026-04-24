#!/usr/bin/env python3
"""
Real DNS Demo - Shows how to use DMP with actual DNS infrastructure

This demo can work with:
1. Cloudflare (easiest - free tier)
2. Local BIND9 with DNS UPDATE
3. AWS Route53
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmp.client import DMPClient
from dmp.core.message import DMPMessage, DMPHeader, MessageType
from dmp.core.crypto import DMPCrypto
from dmp.core.chunking import MessageChunker
from dmp.core.dns import DNSEncoder, DMPDNSRecord
from dmp.network.dns_publisher import (
    CloudflarePublisher,
    DNSUpdatePublisher,
    Route53Publisher,
    LocalDNSPublisher,
)
import dns.resolver
from typing import Optional


class RealDNSClient(DMPClient):
    """Extended DMP client that uses real DNS"""

    def __init__(self, username: str, passphrase: str, domain: str, dns_publisher):
        super().__init__(username, passphrase, domain)
        self.dns_publisher = dns_publisher
        self.resolver = dns.resolver.Resolver()
        # Use public DNS servers for queries
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def publish_identity(self) -> bool:
        """Publish identity to real DNS"""
        domain = DNSEncoder.encode_identity_domain(self.username, self.domain)

        record = DMPDNSRecord(
            version=1,
            record_type="identity",
            data=self.identity.public_key,
            metadata={"username": self.username, "created": self.identity.created_at},
        )

        txt_data = record.to_txt_record()
        success = self.dns_publisher.publish_txt_record(
            name=domain, content=txt_data, ttl=3600  # 1 hour for identity
        )

        if success:
            print(f"✓ Published identity to DNS: {domain}")

            # Wait for DNS propagation
            print("  Waiting for DNS propagation...")
            time.sleep(5)

            # Verify it's queryable
            try:
                answers = self.resolver.resolve(domain, "TXT")
                for rdata in answers:
                    txt = "".join(s.decode("utf-8") for s in rdata.strings)
                    if "v=dmp1" in txt:
                        print(f"  ✓ Identity verified via DNS query")
                        return True
            except:
                print(f"  ⚠ DNS not propagated yet (this is normal)")

        return success

    def lookup_identity(self, username: str) -> Optional[bytes]:
        """Look up a user's public key via DNS"""
        domain = DNSEncoder.encode_identity_domain(username, self.domain)

        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(s.decode("utf-8") for s in rdata.strings)
                if txt.startswith("v=dmp"):
                    record = DMPDNSRecord.from_txt_record(txt)
                    if record.record_type == "identity":
                        print(f"✓ Found {username}'s identity via DNS")
                        return record.data
        except dns.resolver.NXDOMAIN:
            print(f"✗ User {username} not found in DNS")
        except Exception as e:
            print(f"✗ DNS lookup error: {e}")

        return None

    def send_message_via_dns(self, recipient_username: str, message: str) -> bool:
        """Send a message by publishing chunks to DNS"""

        # Look up recipient's public key
        recipient_pubkey = self.lookup_identity(recipient_username)
        if not recipient_pubkey:
            print(f"Cannot find {recipient_username}'s public key in DNS")
            return False

        # Create and encrypt message
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        recipient_key = X25519PublicKey.from_public_bytes(recipient_pubkey)

        msg = DMPMessage(
            header=DMPHeader(
                message_type=MessageType.DATA,
                sender_id=self.user_id,
                recipient_id=DMPCrypto.derive_user_id(recipient_key),
            ),
            payload=message.encode("utf-8"),
        )

        # Encrypt
        encrypted = self.encryption.encrypt_message(
            msg.payload, recipient_key, msg.header.message_id
        )

        encrypted_msg = DMPMessage(header=msg.header, payload=encrypted.to_bytes())

        # Chunk the message
        chunks = self.chunker.chunk_message(encrypted_msg)

        print(f"\n📤 Sending message to {recipient_username}")
        print(f'   Message: "{message}"')
        print(f"   Publishing {len(chunks)} chunks to DNS...")

        # Publish each chunk to DNS
        published = 0
        for chunk_num, chunk_data in chunks:
            chunk_id = f"{chunk_num:04d}"
            chunk_domain = DNSEncoder.encode_chunk_domain(
                chunk_id, msg.header.message_id, self.domain
            )

            record = DMPDNSRecord(
                version=1,
                record_type="chunk",
                data=chunk_data,
                metadata={
                    "chunk": chunk_num,
                    "total": len(chunks),
                    "sender": self.username,
                    "recipient": recipient_username,
                },
            )

            success = self.dns_publisher.publish_txt_record(
                name=chunk_domain,
                content=record.to_txt_record(),
                ttl=300,  # 5 minutes for chunks
            )

            if success:
                published += 1
                print(f"   ✓ Chunk {chunk_num}/{len(chunks)-1} → {chunk_domain}")
            else:
                print(f"   ✗ Failed to publish chunk {chunk_num}")

        if published == len(chunks):
            print(f"   ✓ All chunks published successfully!")

            # Publish notification in mailbox
            mailbox_domain = DNSEncoder.encode_mailbox_domain(
                DMPCrypto.derive_user_id(recipient_key), 0, self.domain  # Slot 0
            )

            notification = DMPDNSRecord(
                version=1,
                record_type="mailbox",
                data=msg.header.message_id,
                metadata={
                    "from": self.username,
                    "chunks": len(chunks),
                    "timestamp": int(time.time()),
                },
            )

            self.dns_publisher.publish_txt_record(
                name=mailbox_domain, content=notification.to_txt_record(), ttl=300
            )
            print(f"   ✓ Mailbox notification sent to {mailbox_domain}")

            return True

        return False

    def check_messages_via_dns(self) -> list:
        """Check for messages in DNS mailbox"""
        print(f"\n📥 Checking DNS mailbox for {self.username}...")

        messages = []

        # Check mailbox slots
        for slot in range(10):
            mailbox_domain = DNSEncoder.encode_mailbox_domain(
                self.user_id, slot, self.domain
            )

            try:
                answers = self.resolver.resolve(mailbox_domain, "TXT")
                for rdata in answers:
                    txt = "".join(s.decode("utf-8") for s in rdata.strings)
                    if txt.startswith("v=dmp"):
                        record = DMPDNSRecord.from_txt_record(txt)
                        if record.record_type == "mailbox":
                            print(f"   ✓ Found message in slot {slot}")
                            messages.append((record.data, record.metadata))
            except:
                pass  # No message in this slot

        if not messages:
            print("   No new messages")
            return []

        # Retrieve and decrypt messages
        decrypted_messages = []
        for message_id, metadata in messages:
            print(f"   Retrieving message from {metadata.get('from', 'Unknown')}...")

            # Get all chunks
            chunks_data = []
            total_chunks = metadata.get("chunks", 0)

            for chunk_num in range(total_chunks):
                chunk_id = f"{chunk_num:04d}"
                chunk_domain = DNSEncoder.encode_chunk_domain(
                    chunk_id, message_id, self.domain
                )

                try:
                    answers = self.resolver.resolve(chunk_domain, "TXT")
                    for rdata in answers:
                        txt = "".join(s.decode("utf-8") for s in rdata.strings)
                        if txt.startswith("v=dmp"):
                            record = DMPDNSRecord.from_txt_record(txt)
                            if record.record_type == "chunk":
                                chunks_data.append((chunk_num, record.data))
                                print(f"     ✓ Retrieved chunk {chunk_num}")
                except:
                    print(f"     ✗ Failed to retrieve chunk {chunk_num}")

            # Assemble and decrypt
            if len(chunks_data) == total_chunks:
                assembled = None
                for chunk_num, chunk_data in sorted(chunks_data):
                    assembled = self.assembler.add_chunk(
                        message_id, chunk_num, chunk_data, total_chunks
                    )

                if assembled:
                    try:
                        msg = DMPMessage.from_bytes(assembled)
                        from dmp.core.crypto import EncryptedMessage

                        encrypted = EncryptedMessage.from_bytes(msg.payload)
                        decrypted = self.encryption.decrypt_message(
                            encrypted, msg.header.message_id, 0
                        )
                        text = decrypted.decode("utf-8")
                        sender = metadata.get("from", "Unknown")
                        decrypted_messages.append((sender, text))
                        print(f'     ✓ Decrypted message: "{text}"')
                    except Exception as e:
                        print(f"     ✗ Decryption failed: {e}")

        return decrypted_messages


def demo_with_cloudflare():
    """Demo using Cloudflare DNS"""
    print("=" * 60)
    print("DMP with Cloudflare DNS Demo")
    print("=" * 60)

    # Configure Cloudflare (you need to set these)
    ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID", "your-zone-id")
    API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "your-api-token")
    DOMAIN = os.environ.get("DMP_DOMAIN", "mesh.yourdomain.com")

    if ZONE_ID == "your-zone-id":
        print("\n⚠️  Please set environment variables:")
        print("  export CLOUDFLARE_ZONE_ID='your-zone-id'")
        print("  export CLOUDFLARE_API_TOKEN='your-api-token'")
        print("  export DMP_DOMAIN='mesh.yourdomain.com'")
        return

    # Create publisher
    publisher = CloudflarePublisher(ZONE_ID, API_TOKEN)

    # Create Alice
    print("\n1️⃣  Creating Alice...")
    alice = RealDNSClient("alice", "alice_pass_123", DOMAIN, publisher)
    alice.publish_identity()

    # Create Bob
    print("\n2️⃣  Creating Bob...")
    bob = RealDNSClient("bob", "bob_pass_456", DOMAIN, publisher)
    bob.publish_identity()

    # Alice sends to Bob
    print("\n3️⃣  Alice sending message to Bob...")
    alice.send_message_via_dns("bob", "Hello Bob! This is sent via real DNS!")

    # Wait for DNS propagation
    print("\n⏳ Waiting 10 seconds for DNS propagation...")
    time.sleep(10)

    # Bob checks messages
    print("\n4️⃣  Bob checking messages...")
    messages = bob.check_messages_via_dns()

    for sender, text in messages:
        print(f'\n✅ Bob received from {sender}: "{text}"')

    print("\n" + "=" * 60)
    print("✅ Real DNS Demo Complete!")
    print("Messages were sent through actual DNS infrastructure!")
    print("=" * 60)


def demo_with_local_bind():
    """Demo using local BIND9 with DNS UPDATE"""
    print("=" * 60)
    print("DMP with Local BIND9 Demo")
    print("=" * 60)

    # Configure BIND9 (adjust for your setup)
    publisher = DNSUpdatePublisher(
        zone="mesh.local",
        nameserver="127.0.0.1",
        keyname="dmp-update",
        secret="your-tsig-key-base64",  # From dnssec-keygen
    )

    # Create clients and test
    alice = RealDNSClient("alice", "alice_pass", "mesh.local", publisher)
    bob = RealDNSClient("bob", "bob_pass", "mesh.local", publisher)

    # ... rest of demo similar to Cloudflare


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DMP Real DNS Demo")
    parser.add_argument(
        "--provider",
        choices=["cloudflare", "bind", "route53", "local"],
        default="cloudflare",
        help="DNS provider to use",
    )
    args = parser.parse_args()

    if args.provider == "cloudflare":
        demo_with_cloudflare()
    elif args.provider == "bind":
        demo_with_local_bind()
    else:
        print(f"Provider {args.provider} demo not implemented yet")
        print("Please use --provider cloudflare or implement your own!")
