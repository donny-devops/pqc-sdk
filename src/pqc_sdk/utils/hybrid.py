"""
Hybrid KEM: ML-KEM-768 + X25519

Combines classical ECDH (X25519) with post-quantum ML-KEM-768.
The shared secret is the HKDF combination of both — breaking the
hybrid requires breaking BOTH algorithms simultaneously.

This is the recommended approach during the PQC migration period
per NIST SP 800-227 and BSI TR-02102-1.

Wire format (encapsulate output):
    [32 bytes X25519 ephemeral pubkey] + [ML-KEM ciphertext]

Shared secret derivation:
    HKDF-SHA3-256(x25519_ss || mlkem_ss, info="pqc-sdk-hybrid-v1")
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pqc_sdk.kem.api import KEM

_HKDF_INFO = b"pqc-sdk-hybrid-v1"
_SHARED_SECRET_SIZE = 32


class HybridKEM:
    """
    Hybrid KEM: X25519 + ML-KEM-768.

    Provides defense-in-depth during the classical→PQC migration.
    Security is maintained if either algorithm remains unbroken.

    Example:
        >>> hkem = HybridKEM()
        >>> public_key, secret_key = hkem.keygen()
        >>> ciphertext, shared_secret = hkem.encapsulate(public_key)
        >>> recovered = hkem.decapsulate(secret_key, ciphertext)
        >>> assert shared_secret == recovered
    """

    def __init__(self, pq_algorithm: str = "ML-KEM-768") -> None:
        self._pq = KEM(pq_algorithm)
        self.algorithm = f"X25519+{pq_algorithm}"

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Generate a hybrid key pair.

        Returns:
            (public_key, secret_key)
            public_key  = [32B X25519 pubkey] + [ML-KEM pubkey]
            secret_key  = [32B X25519 privkey] + [ML-KEM secret key]
        """
        # Classical
        x_priv = X25519PrivateKey.generate()
        x_pub = x_priv.public_key()
        x_pub_bytes = x_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        x_priv_bytes = x_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

        # Post-quantum
        pq_pub, pq_sec = self._pq.keygen()

        public_key = x_pub_bytes + pq_pub       # 32 + pk_size
        secret_key = x_priv_bytes + pq_sec      # 32 + sk_size
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate against a hybrid public key.

        Returns:
            (ciphertext, shared_secret)
            ciphertext = [32B X25519 ephemeral pubkey] + [ML-KEM ciphertext]
        """
        x_pub_bytes = public_key[:32]
        pq_pub = public_key[32:]

        # Classical half
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        eph_pub_bytes = eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        x_peer = X25519PublicKey.from_public_bytes(x_pub_bytes)
        x_ss = eph_priv.exchange(x_peer)

        # PQ half
        pq_ct, pq_ss = self._pq.encapsulate(pq_pub)

        # Combine
        shared_secret = self._kdf(x_ss, pq_ss)
        ciphertext = eph_pub_bytes + pq_ct
        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate and recover the shared secret.
        """
        x_priv_bytes = secret_key[:32]
        pq_sk = secret_key[32:]

        eph_pub_bytes = ciphertext[:32]
        pq_ct = ciphertext[32:]

        # Classical half
        x_priv = X25519PrivateKey.from_private_bytes(x_priv_bytes)
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        x_ss = x_priv.exchange(eph_pub)

        # PQ half
        pq_ss = self._pq.decapsulate(pq_sk, pq_ct)

        return self._kdf(x_ss, pq_ss)

    def _kdf(self, x_ss: bytes, pq_ss: bytes) -> bytes:
        """HKDF-SHA3-256 over concatenated shared secrets."""
        ikm = x_ss + pq_ss
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=_SHARED_SECRET_SIZE,
            salt=None,
            info=_HKDF_INFO,
        )
        return hkdf.derive(ikm)

    def __repr__(self) -> str:
        return f"HybridKEM(algorithm={self.algorithm!r}, backend={self._pq.backend!r})"
