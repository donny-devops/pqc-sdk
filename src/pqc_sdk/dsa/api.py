"""
ML-DSA (FIPS 204) Digital Signature Algorithm
Formerly known as CRYSTALS-Dilithium

Supported algorithms:
    ML-DSA-44  — NIST security level 2 (~AES-128)
    ML-DSA-65  — NIST security level 3 (~AES-192)  ← recommended default
    ML-DSA-87  — NIST security level 5 (~AES-256)

    Also supported:
    SLH-DSA-SHAKE-128s  — stateless hash-based (FIPS 205, small sigs)
    SLH-DSA-SHAKE-256f  — stateless hash-based (FIPS 205, fast verify)
"""

from __future__ import annotations
from typing import Tuple
from pqc_sdk._backend import get_backend
from pqc_sdk.exceptions import AlgorithmNotSupportedError, PQCError, SignatureVerificationError

_ALIASES: dict[str, str] = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
    "Dilithium2": "ML-DSA-44",
    "Dilithium3": "ML-DSA-65",
    "Dilithium5": "ML-DSA-87",
    "dilithium2": "ML-DSA-44",
    "dilithium3": "ML-DSA-65",
    "dilithium5": "ML-DSA-87",
    # SLH-DSA (FIPS 205)
    "SLH-DSA-SHAKE-128s": "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-128f": "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-256s": "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f": "SLH-DSA-SHAKE-256f",
}

_PARAMS: dict[str, dict] = {
    "ML-DSA-44": {
        "pk_size": 1312, "sk_size": 2528, "sig_size": 2420,
        "security_level": 2, "oqs_name": "ML-DSA-44", "fips": "FIPS 204",
    },
    "ML-DSA-65": {
        "pk_size": 1952, "sk_size": 4000, "sig_size": 3309,
        "security_level": 3, "oqs_name": "ML-DSA-65", "fips": "FIPS 204",
    },
    "ML-DSA-87": {
        "pk_size": 2592, "sk_size": 4864, "sig_size": 4627,
        "security_level": 5, "oqs_name": "ML-DSA-87", "fips": "FIPS 204",
    },
    "SLH-DSA-SHAKE-128s": {
        "pk_size": 32, "sk_size": 64, "sig_size": 7856,
        "security_level": 1, "oqs_name": "SPHINCS+-SHAKE-128s-simple", "fips": "FIPS 205",
    },
    "SLH-DSA-SHAKE-128f": {
        "pk_size": 32, "sk_size": 64, "sig_size": 17088,
        "security_level": 1, "oqs_name": "SPHINCS+-SHAKE-128f-simple", "fips": "FIPS 205",
    },
    "SLH-DSA-SHAKE-256s": {
        "pk_size": 64, "sk_size": 128, "sig_size": 29792,
        "security_level": 5, "oqs_name": "SPHINCS+-SHAKE-256s-simple", "fips": "FIPS 205",
    },
    "SLH-DSA-SHAKE-256f": {
        "pk_size": 64, "sk_size": 128, "sig_size": 49856,
        "security_level": 5, "oqs_name": "SPHINCS+-SHAKE-256f-simple", "fips": "FIPS 205",
    },
}

SUPPORTED_ALGORITHMS = list(_PARAMS.keys()) + list(_ALIASES.keys())


class DSA:
    """
    Post-Quantum Digital Signature Algorithm (ML-DSA / FIPS 204, SLH-DSA / FIPS 205).

    Args:
        algorithm: Algorithm name. Accepts ML-DSA-44/65/87,
                   SLH-DSA-SHAKE-* variants, or legacy Dilithium aliases.

    Example:
        >>> dsa = DSA("ML-DSA-65")
        >>> public_key, secret_key = dsa.keygen()
        >>> signature = dsa.sign(secret_key, b"message to sign")
        >>> dsa.verify(public_key, b"message to sign", signature)  # True
        >>> dsa.verify(public_key, b"tampered", signature)          # raises SignatureVerificationError
    """

    def __init__(self, algorithm: str = "ML-DSA-65") -> None:
        canonical = _ALIASES.get(algorithm, algorithm)
        if canonical not in _PARAMS:
            raise AlgorithmNotSupportedError(
                f"Unsupported DSA algorithm: {algorithm!r}. "
                f"Supported: {list(_PARAMS.keys())}"
            )
        self.algorithm = canonical
        self._params = _PARAMS[canonical]
        self._backend = get_backend()
        self._dsa = self._backend.create_dsa(self._params["oqs_name"])

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate a DSA key pair.

        Returns:
            (public_key, secret_key) — both as raw bytes.
        """
        return self._dsa.keygen()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Sign a message.

        Args:
            secret_key: Signer's secret key (from keygen).
            message: Arbitrary bytes to sign.

        Returns:
            signature bytes.
        """
        return self._dsa.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature.

        Args:
            public_key: Signer's public key.
            message: Original message bytes.
            signature: Signature from sign().

        Returns:
            True if valid.

        Raises:
            SignatureVerificationError: If signature is invalid.
        """
        result = self._dsa.verify(public_key, message, signature)
        if not result:
            raise SignatureVerificationError(
                f"Signature verification failed for {self.algorithm}"
            )
        return True

    # ------------------------------------------------------------------ #
    # Metadata                                                             #
    # ------------------------------------------------------------------ #

    @property
    def public_key_size(self) -> int:
        return self._params["pk_size"]

    @property
    def secret_key_size(self) -> int:
        return self._params["sk_size"]

    @property
    def signature_size(self) -> int:
        return self._params["sig_size"]

    @property
    def security_level(self) -> int:
        return self._params["security_level"]

    @property
    def fips_standard(self) -> str:
        return self._params["fips"]

    @property
    def backend(self) -> str:
        return self._backend.name

    def __repr__(self) -> str:
        return (
            f"DSA(algorithm={self.algorithm!r}, "
            f"fips={self.fips_standard!r}, "
            f"security_level={self.security_level}, "
            f"backend={self.backend!r})"
        )
