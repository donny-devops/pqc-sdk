"""
pqc-sdk — Post-Quantum Cryptography SDK
NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)

Quick start:
    from pqc_sdk import KEM, DSA, hash_message

    # Key Encapsulation (ML-KEM / Kyber)
    kem = KEM("ML-KEM-768")
    public_key, secret_key = kem.keygen()
    ciphertext, shared_secret = kem.encapsulate(public_key)
    recovered = kem.decapsulate(secret_key, ciphertext)

    # Digital Signatures (ML-DSA / Dilithium)
    dsa = DSA("ML-DSA-65")
    pk, sk = dsa.keygen()
    sig = dsa.sign(sk, b"hello pqc world")
    assert dsa.verify(pk, b"hello pqc world", sig)
"""

from pqc_sdk.kem.api import KEM
from pqc_sdk.dsa.api import DSA
from pqc_sdk.hash.api import hash_message, HashAlgorithm
from pqc_sdk.utils.hybrid import HybridKEM
from pqc_sdk._version import __version__

__all__ = [
    "KEM",
    "DSA",
    "HybridKEM",
    "hash_message",
    "HashAlgorithm",
    "__version__",
]
