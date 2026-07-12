"""
ML-KEM (FIPS 203) Key Encapsulation Mechanism
Formerly known as CRYSTALS-Kyber

Supported algorithms:
    ML-KEM-512   — NIST security level 1 (~AES-128)
    ML-KEM-768   — NIST security level 3 (~AES-192)  ← recommended default
    ML-KEM-1024  — NIST security level 5 (~AES-256)

    Legacy aliases (pre-standardization):
    Kyber512, Kyber768, Kyber1024
"""

from __future__ import annotations

from typing import TypedDict

from pqc_sdk._backend import get_backend
from pqc_sdk.exceptions import AlgorithmNotSupportedError, PQCError


class KEMParams(TypedDict):
    pk_size: int
    sk_size: int
    ct_size: int
    ss_size: int
    security_level: int
    oqs_name: str


# Algorithm name normalization map
_ALIASES: dict[str, str] = {
    "ML-KEM-512": "ML-KEM-512",
    "ML-KEM-768": "ML-KEM-768",
    "ML-KEM-1024": "ML-KEM-1024",
    "Kyber512": "ML-KEM-512",
    "Kyber768": "ML-KEM-768",
    "Kyber1024": "ML-KEM-1024",
    "kyber512": "ML-KEM-512",
    "kyber768": "ML-KEM-768",
    "kyber1024": "ML-KEM-1024",
}

# Key/ciphertext sizes in bytes (FIPS 203 Table 2)
_PARAMS: dict[str, KEMParams] = {
    "ML-KEM-512": {
        "pk_size": 800,
        "sk_size": 1632,
        "ct_size": 768,
        "ss_size": 32,
        "security_level": 1,
        "oqs_name": "ML-KEM-512",
    },
    "ML-KEM-768": {
        "pk_size": 1184,
        "sk_size": 2400,
        "ct_size": 1088,
        "ss_size": 32,
        "security_level": 3,
        "oqs_name": "ML-KEM-768",
    },
    "ML-KEM-1024": {
        "pk_size": 1568,
        "sk_size": 3168,
        "ct_size": 1568,
        "ss_size": 32,
        "security_level": 5,
        "oqs_name": "ML-KEM-1024",
    },
}

SUPPORTED_ALGORITHMS = list(_PARAMS.keys()) + list(_ALIASES.keys())


class KEM:
    """
    Post-Quantum Key Encapsulation Mechanism (ML-KEM / FIPS 203).

    Uses liboqs when available; falls back to a simulation backend for
    testing and development environments without native liboqs.

    Args:
        algorithm: Algorithm name. Accepts ML-KEM-512/768/1024 or
                   legacy Kyber512/768/1024 aliases.

    Example:
        >>> kem = KEM("ML-KEM-768")
        >>> public_key, secret_key = kem.keygen()
        >>> ciphertext, shared_secret = kem.encapsulate(public_key)
        >>> recovered = kem.decapsulate(secret_key, ciphertext)
        >>> assert shared_secret == recovered
    """

    def __init__(self, algorithm: str = "ML-KEM-768") -> None:
        canonical = _ALIASES.get(algorithm, algorithm)
        if canonical not in _PARAMS:
            raise AlgorithmNotSupportedError(
                f"Unsupported KEM algorithm: {algorithm!r}. " f"Supported: {list(_PARAMS.keys())}"
            )
        self.algorithm = canonical
        self._params: KEMParams = _PARAMS[canonical]
        self._backend = get_backend()
        self._kem = self._backend.create_kem(self._params["oqs_name"])

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Generate a KEM key pair.

        Returns:
            (public_key, secret_key) — both as raw bytes.
            Public key is safe to share; secret key must remain private.
        """
        return self._kem.keygen()

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate: generate a shared secret and ciphertext.

        Args:
            public_key: Recipient's public key (from keygen).

        Returns:
            (ciphertext, shared_secret)
            - ciphertext: Send to the recipient
            - shared_secret: Use as symmetric key material (32 bytes)
        """
        self._validate_key_size(public_key, "public_key", self._params["pk_size"])
        return self._kem.encapsulate(public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext.

        Args:
            secret_key: Recipient's secret key (from keygen).
            ciphertext: Ciphertext from encapsulate.

        Returns:
            shared_secret (32 bytes) — must match encapsulate output.
        """
        self._validate_key_size(secret_key, "secret_key", self._params["sk_size"])
        self._validate_key_size(ciphertext, "ciphertext", self._params["ct_size"])
        return self._kem.decapsulate(secret_key, ciphertext)

    # ------------------------------------------------------------------ #
    # Metadata                                                             #
    # ------------------------------------------------------------------ #

    @property
    def public_key_size(self) -> int:
        """Size of public key in bytes."""
        return self._params["pk_size"]

    @property
    def secret_key_size(self) -> int:
        """Size of secret key in bytes."""
        return self._params["sk_size"]

    @property
    def ciphertext_size(self) -> int:
        """Size of ciphertext in bytes."""
        return self._params["ct_size"]

    @property
    def shared_secret_size(self) -> int:
        """Size of shared secret in bytes (always 32)."""
        return self._params["ss_size"]

    @property
    def security_level(self) -> int:
        """NIST security level (1, 3, or 5)."""
        return self._params["security_level"]

    @property
    def backend(self) -> str:
        """Active backend: 'liboqs' or 'simulation'."""
        return self._backend.name

    def __repr__(self) -> str:
        return (
            f"KEM(algorithm={self.algorithm!r}, "
            f"security_level={self.security_level}, "
            f"backend={self.backend!r})"
        )

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _validate_key_size(self, data: bytes, name: str, expected: int) -> None:
        if len(data) != expected:
            raise PQCError(
                f"Invalid {name} size for {self.algorithm}: "
                f"expected {expected} bytes, got {len(data)}"
            )
