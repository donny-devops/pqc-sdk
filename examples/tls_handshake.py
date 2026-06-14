"""
Example: Post-Quantum TLS Handshake Simulation
================================================
Simulates a TLS 1.3-style key exchange using HybridKEM (X25519 + ML-KEM-768).

This mirrors what RFC 9420 (MLS) and TLS PQC hybrid extensions (draft-ietf-tls-hybrid-design)
do in practice: combine X25519 with ML-KEM for forward secrecy against quantum attacks.

Handshake flow:
    Client                              Server
    ──────                              ──────
    (server_pk, server_sk) = keygen()
                            <── server_pk ──
    (ct, shared_secret_c) = encapsulate(server_pk)
    ── ct ──>
                            shared_secret_s = decapsulate(server_sk, ct)

    assert shared_secret_c == shared_secret_s
    → derive session_key via HKDF
    → symmetric encryption begins (AES-256-GCM)
"""

import os
import hashlib
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pqc_sdk import HybridKEM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_session_keys(shared_secret: bytes, handshake_transcript: bytes) -> dict:
    """
    Derive session keys from the shared secret using HKDF (mirrors TLS 1.3 key schedule).

    Returns client_write_key, server_write_key, client_iv, server_iv
    """
    def hkdf_expand(label: bytes, length: int) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=handshake_transcript,
            info=b"pqc-tls " + label,
        ).derive(shared_secret)

    return {
        "client_write_key": hkdf_expand(b"client key", 32),
        "server_write_key": hkdf_expand(b"server key", 32),
        "client_iv":        hkdf_expand(b"client iv", 12),
        "server_iv":        hkdf_expand(b"server iv", 12),
    }


def run_handshake():
    print("=" * 60)
    print("PQC Hybrid TLS Handshake: X25519 + ML-KEM-768")
    print("=" * 60)

    hkem = HybridKEM("ML-KEM-768")

    # ── Server setup ──────────────────────────────────────────────────
    print("\n[Server] Generating hybrid key pair...")
    t0 = time.perf_counter()
    server_pk, server_sk = hkem.keygen()
    keygen_ms = (time.perf_counter() - t0) * 1000
    print(f"  Public key: {len(server_pk)} bytes  ({keygen_ms:.2f} ms)")

    # ── Client encapsulates ────────────────────────────────────────────
    print("\n[Client] Encapsulating against server public key...")
    t0 = time.perf_counter()
    ciphertext, client_shared_secret = hkem.encapsulate(server_pk)
    encap_ms = (time.perf_counter() - t0) * 1000
    print(f"  Ciphertext:    {len(ciphertext)} bytes  ({encap_ms:.2f} ms)")
    print(f"  Shared secret: {len(client_shared_secret)} bytes")

    # ── Server decapsulates ────────────────────────────────────────────
    print("\n[Server] Decapsulating...")
    t0 = time.perf_counter()
    server_shared_secret = hkem.decapsulate(server_sk, ciphertext)
    decap_ms = (time.perf_counter() - t0) * 1000
    print(f"  Shared secret: {len(server_shared_secret)} bytes  ({decap_ms:.2f} ms)")

    # ── Verify shared secrets match ────────────────────────────────────
    assert client_shared_secret == server_shared_secret, "Shared secret mismatch!"
    print(f"\n✓ Shared secrets match: {client_shared_secret.hex()[:32]}...")

    # ── Derive session keys ────────────────────────────────────────────
    # Transcript = hash of everything seen so far (simplified)
    transcript = hashlib.sha256(server_pk + ciphertext).digest()
    client_keys = derive_session_keys(client_shared_secret, transcript)
    server_keys = derive_session_keys(server_shared_secret, transcript)

    print(f"\n[Keys] Session keys derived:")
    print(f"  client_write_key: {client_keys['client_write_key'].hex()[:32]}...")
    print(f"  server_write_key: {server_keys['server_write_key'].hex()[:32]}...")

    # ── Simulate application data exchange ─────────────────────────────
    print("\n[Application] Simulating encrypted channel...")

    # Client → Server
    aesgcm_client = AESGCM(client_keys["client_write_key"])
    nonce = client_keys["client_iv"]
    plaintext = b"GET /api/pqc-data HTTP/1.1\r\nHost: postquantumstudio.com\r\n\r\n"
    encrypted_request = aesgcm_client.encrypt(nonce, plaintext, None)

    aesgcm_server = AESGCM(server_keys["client_write_key"])
    decrypted_request = aesgcm_server.decrypt(nonce, encrypted_request, None)
    assert decrypted_request == plaintext

    # Server → Client
    aesgcm_server2 = AESGCM(server_keys["server_write_key"])
    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"quantum-safe\"}"
    encrypted_response = aesgcm_server2.encrypt(server_keys["server_iv"], response, None)

    aesgcm_client2 = AESGCM(client_keys["server_write_key"])
    decrypted_response = aesgcm_client2.decrypt(server_keys["server_iv"], encrypted_response, None)
    assert decrypted_response == response

    print(f"  ✓ Client→Server: {len(plaintext)}B request encrypted/decrypted")
    print(f"  ✓ Server→Client: {len(response)}B response encrypted/decrypted")

    print(f"\n{'─' * 60}")
    print(f"Handshake summary:")
    print(f"  Algorithm:      X25519 + ML-KEM-768 (FIPS 203)")
    print(f"  Keygen:         {keygen_ms:.2f} ms")
    print(f"  Encapsulate:    {encap_ms:.2f} ms")
    print(f"  Decapsulate:    {decap_ms:.2f} ms")
    print(f"  Total overhead: {keygen_ms + encap_ms + decap_ms:.2f} ms")
    print(f"  Wire overhead:  {len(ciphertext) - 32} bytes (PQ ciphertext vs X25519 32B)")
    print(f"{'─' * 60}")
    print("✓ Hybrid PQC handshake complete — quantum-safe channel established")


if __name__ == "__main__":
    run_handshake()
