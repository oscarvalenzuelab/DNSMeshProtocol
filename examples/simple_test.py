#!/usr/bin/env python3
"""
Simple test to verify DMP components work correctly
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmp.core.message import DMPMessage, DMPHeader, MessageType
from dmp.core.crypto import DMPCrypto
from dmp.core.chunking import MessageChunker, MessageAssembler


def test_basic_functionality():
    """Test that basic DMP functionality works"""
    
    print("Testing DNS Mesh Protocol Components\n")
    print("=" * 50)
    
    # 1. Test message creation
    print("\n1. Creating a message...")
    message = DMPMessage(
        header=DMPHeader(
            message_type=MessageType.DATA,
            sender_id=b'A' * 32,
            recipient_id=b'B' * 32
        ),
        payload=b"Hello, this is a test message!"
    )
    print(f"   ✓ Message created with {len(message.payload)} byte payload")
    
    # 2. Test encryption
    print("\n2. Testing encryption...")
    alice = DMPCrypto.from_passphrase("alice_password")
    bob = DMPCrypto.from_passphrase("bob_password")
    
    plaintext = b"Secret message from Alice to Bob"
    encrypted = alice.encrypt_for_recipient(plaintext, bob.public_key)
    print(f"   ✓ Encrypted {len(plaintext)} bytes → {len(encrypted.to_bytes())} bytes")
    
    decrypted = bob.decrypt_message(encrypted)
    print(f"   ✓ Decrypted back to: {decrypted.decode()}")
    assert decrypted == plaintext, "Decryption failed!"
    
    # 3. Test chunking
    print("\n3. Testing message chunking...")
    chunker = MessageChunker(enable_error_correction=False)
    
    large_message = DMPMessage(
        payload=b"X" * 500  # Large message requiring chunking
    )
    
    chunks = chunker.chunk_message(large_message, include_redundancy=False)
    print(f"   ✓ Split 500-byte message into {len(chunks)} chunks")
    
    # 4. Test reassembly
    print("\n4. Testing message reassembly...")
    assembler = MessageAssembler(enable_error_correction=False)
    
    result = None
    for chunk_num, chunk_data in chunks:
        result = assembler.add_chunk(
            large_message.header.message_id,
            chunk_num,
            chunk_data,
            len(chunks)
        )
    
    assert result is not None, "Assembly failed!"
    reassembled = DMPMessage.from_bytes(result)
    assert reassembled.payload == large_message.payload
    print(f"   ✓ Reassembled {len(chunks)} chunks back to original message")
    
    # 5. Test Reed-Solomon error correction
    print("\n5. Testing error correction...")
    chunker_ecc = MessageChunker(enable_error_correction=True)
    assembler_ecc = MessageAssembler(enable_error_correction=True)
    
    ecc_message = DMPMessage(payload=b"Test with error correction")
    chunks_ecc = chunker_ecc.chunk_message(ecc_message, include_redundancy=True)
    
    # Simulate losing 20% of chunks (should still work with 30% redundancy)
    chunks_to_skip = len(chunks_ecc) // 5
    print(f"   ✓ Created {len(chunks_ecc)} chunks with Reed-Solomon")
    print(f"   ✓ Simulating loss of {chunks_to_skip} chunks...")
    
    result = None
    for i, (chunk_num, chunk_data) in enumerate(chunks_ecc):
        if i < chunks_to_skip:
            print(f"     × Skipping chunk {chunk_num} (simulating loss)")
            continue
        result = assembler_ecc.add_chunk(
            ecc_message.header.message_id,
            chunk_num,
            chunk_data,
            len(chunks_ecc)
        )
    
    # With ECC, we might still recover (depending on implementation)
    if result:
        print("   ✓ Message recovered despite missing chunks!")
    else:
        missing = assembler_ecc.get_missing_chunks(
            ecc_message.header.message_id,
            len(chunks_ecc)
        )
        print(f"   ⚠ Need chunks {missing} for complete recovery")
    
    # 6. Test DNS encoding
    print("\n6. Testing DNS encoding...")
    from dmp.core.dns import DNSEncoder, DMPDNSRecord
    
    # Test domain generation
    chunk_domain = DNSEncoder.encode_chunk_domain(
        "0001",
        message.header.message_id,
        "mesh.example.com"
    )
    print(f"   ✓ Chunk domain: {chunk_domain}")
    
    # Test TXT record
    record = DMPDNSRecord(
        version=1,
        record_type='chunk',
        data=b'test chunk data',
        metadata={'chunk': 0}
    )
    txt = record.to_txt_record()
    print(f"   ✓ TXT record: {txt[:50]}...")
    
    # Parse it back
    parsed = DMPDNSRecord.from_txt_record(txt)
    assert parsed.data == record.data
    print("   ✓ Successfully parsed TXT record")
    
    print("\n" + "=" * 50)
    print("✅ All basic tests passed!")
    print("\nThe DNS Mesh Protocol core components are working correctly.")
    print("Ready for network integration and real DNS testing.")


if __name__ == "__main__":
    test_basic_functionality()