"""
Example: Post-Quantum File Encryption
=====================================
Encrypts a file using ML-KEM-768 (key encapsulation) + AES-256-GCM (bulk encryption).

Pattern:
    1. Recipient generates ML-KEM key pair, distributes public key
    2. Sender encapsulates against recipient's public key → (ciphertext, shared_secret)
    3. Sender encrypts file with AES-256-GCM using shared_secret as key
    4. Sender sends: [ML-KEM ciphertext] + [AES nonce] + [AES ciphertext]
    5. Recipient decapsulates → recovers shared_secret → decrypts file

This replaces RSA-OAEP or ECDH-based hybrid encryption with a quantum-safe equivalent.
"""

import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Add src to path for local dev
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pqc_sdk import KEM


def generate_recipient_keypair(algorithm: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """Generate recipient's key pair. Public key is shared; secret key stays private."""
    kem = KEM(algorithm)
    public_key, secret_key = kem.keygen()
    print(f"[keygen] {algorithm}")
    print(f"  Public key:  {len(public_key):>5} bytes")
    print(f"  Secret key:  {len(secret_key):>5} bytes")
    return public_key, secret_key


def encrypt_file(
    plaintext: bytes,
    recipient_public_key: bytes,
    algorithm: str = "ML-KEM-768",
) -> bytes:
    """
    Encrypt plaintext for a recipient using their ML-KEM public key.

    Wire format:
        [4B algo name length] [algo name] [KEM ciphertext] [12B AES nonce] [AES-GCM ciphertext+tag]
    """
    kem = KEM(algorithm)

    # Step 1: Encapsulate → shared secret
    kem_ciphertext, shared_secret = kem.encapsulate(recipient_public_key)
    print(f"\n[encrypt] encapsulated shared secret ({len(shared_secret)} bytes)")
    print(f"  KEM ciphertext: {len(kem_ciphertext)} bytes")

    # Step 2: Encrypt with AES-256-GCM using shared secret as key
    nonce = os.urandom(12)
    aesgcm = AESGCM(shared_secret)
    aes_ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    print(f"  AES-GCM ciphertext+tag: {len(aes_ciphertext)} bytes")

    # Step 3: Pack wire format
    algo_bytes = algorithm.encode()
    packed = (
        struct.pack(">I", len(algo_bytes))
        + algo_bytes
        + kem_ciphertext
        + nonce
        + aes_ciphertext
    )
    print(f"  Total encrypted blob: {len(packed)} bytes")
    return packed


def decrypt_file(
    encrypted_blob: bytes,
    recipient_secret_key: bytes,
) -> bytes:
    """
    Decrypt an encrypted blob using the recipient's ML-KEM secret key.
    """
    # Unpack wire format
    offset = 0
    algo_len = struct.unpack(">I", encrypted_blob[offset:offset + 4])[0]
    offset += 4
    algorithm = encrypted_blob[offset:offset + algo_len].decode()
    offset += algo_len

    kem = KEM(algorithm)
    ct_size = kem.ciphertext_size
    kem_ciphertext = encrypted_blob[offset:offset + ct_size]
    offset += ct_size
    nonce = encrypted_blob[offset:offset + 12]
    offset += 12
    aes_ciphertext = encrypted_blob[offset:]

    # Step 1: Decapsulate → recover shared secret
    shared_secret = kem.decapsulate(recipient_secret_key, kem_ciphertext)
    print(f"\n[decrypt] recovered shared secret ({len(shared_secret)} bytes)")

    # Step 2: Decrypt with AES-256-GCM
    aesgcm = AESGCM(shared_secret)
    plaintext = aesgcm.decrypt(nonce, aes_ciphertext, None)
    print(f"  Decrypted {len(plaintext)} bytes successfully")
    return plaintext


if __name__ == "__main__":
    print("=" * 60)
    print("PQC File Encryption: ML-KEM-768 + AES-256-GCM")
    print("=" * 60)

    # Recipient setup
    public_key, secret_key = generate_recipient_keypair("ML-KEM-768")

    # Encrypt a file
    original = b"TOP SECRET: This document is protected by post-quantum encryption. " * 10
    print(f"\nOriginal size: {len(original)} bytes")

    encrypted = encrypt_file(original, public_key)

    # Decrypt
    decrypted = decrypt_file(encrypted, secret_key)

    assert decrypted == original, "Decryption mismatch!"
    print("\n✓ File encryption/decryption round-trip successful")
    print(f"  Overhead: {len(encrypted) - len(original)} bytes ({algorithm_overhead(encrypted, original):.1f}%)")


def algorithm_overhead(encrypted: bytes, original: bytes) -> float:
    return ((len(encrypted) - len(original)) / len(original)) * 100
