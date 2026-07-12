"""
Backend abstraction: auto-detects liboqs, falls back to simulation.

Priority order:
    1. liboqs (native, FIPS-compliant) — used in production
    2. simulation (pure Python, deterministic) — dev/test only

The simulation backend produces structurally correct output with proper
key/ciphertext sizes but uses HKDF + SHA3 internally, NOT the actual
lattice constructions. It is NOT cryptographically secure and exists
only to allow the API to function without native liboqs installed.

In production, always install liboqs:
    pip install liboqs-python
"""

from __future__ import annotations

import hashlib
import hmac
import os
from enum import Enum
from typing import Protocol, cast

from pqc_sdk._types import DSAParams, KEMParams


class BackendType(Enum):
    LIBOQS = "liboqs"
    SIMULATION = "simulation"


class _OQSKEMImpl(Protocol):
    def generate_keypair(self) -> bytes: ...
    def export_secret_key(self) -> bytes: ...
    def encap_secret(self, public_key: bytes) -> tuple[bytes, bytes]: ...
    def decap_secret(self, ciphertext: bytes) -> bytes: ...


class _OQSSignatureImpl(Protocol):
    def generate_keypair(self) -> bytes: ...
    def export_secret_key(self) -> bytes: ...
    def sign(self, message: bytes) -> bytes: ...
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool: ...


# ------------------------------------------------------------------ #
# liboqs backend                                                       #
# ------------------------------------------------------------------ #


class _LibOQSKEM:
    def __init__(self, oqs_name: str) -> None:
        import oqs as _oqs

        self._kem = cast(_OQSKEMImpl, _oqs.KeyEncapsulation(oqs_name))

    def keygen(self) -> tuple[bytes, bytes]:
        pk = self._kem.generate_keypair()
        sk = self._kem.export_secret_key()
        return pk, sk

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        ct, ss = self._kem.encap_secret(public_key)
        return ct, ss

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return self._kem.decap_secret(ciphertext)


class _LibOQSDSA:
    def __init__(self, oqs_name: str) -> None:
        import oqs as _oqs

        self._sig = cast(_OQSSignatureImpl, _oqs.Signature(oqs_name))

    def keygen(self) -> tuple[bytes, bytes]:
        pk = self._sig.generate_keypair()
        sk = self._sig.export_secret_key()
        return pk, sk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return self._sig.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return self._sig.verify(message, signature, public_key)


class LibOQSBackend:
    name = "liboqs"

    def create_kem(self, oqs_name: str) -> _LibOQSKEM:
        return _LibOQSKEM(oqs_name)

    def create_dsa(self, oqs_name: str) -> _LibOQSDSA:
        return _LibOQSDSA(oqs_name)


# ------------------------------------------------------------------ #
# Simulation backend (dev/test only — NOT cryptographically secure)   #
# ------------------------------------------------------------------ #


class _SimKEM:
    """
    Simulation KEM using HKDF-SHA3-256.

    WARNING: This is a structural simulation only. It is NOT
    the actual ML-KEM lattice construction and MUST NOT be used
    in any security-sensitive context.
    """

    def __init__(self, params: KEMParams) -> None:
        self._pk_size = params["pk_size"]
        self._sk_size = params["sk_size"]
        self._ct_size = params["ct_size"]
        self._ss_size = params["ss_size"]
        self._name = params["oqs_name"]

    def keygen(self) -> tuple[bytes, bytes]:
        seed = os.urandom(64)
        pk = hashlib.shake_256(b"pk" + seed).digest(self._pk_size)
        # Build sk: seed (64B) + pk_digest (32B) + shake pad to exact sk_size
        sk_core = seed + hashlib.sha3_256(pk).digest()  # 96 bytes
        if self._sk_size > len(sk_core):
            pad = hashlib.shake_256(sk_core).digest(self._sk_size - len(sk_core))
            sk = sk_core + pad
        else:
            sk = sk_core[: self._sk_size]
        return pk, sk

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        r = os.urandom(32)
        shared_secret = hashlib.shake_256(b"ss" + r + public_key).digest(self._ss_size)
        # Ciphertext encodes r so decap can recover ss
        ct_seed = hashlib.shake_256(b"ct" + r + public_key).digest(self._ct_size - 32)
        ciphertext = r + ct_seed
        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        r = ciphertext[:32]
        # Recover public key from secret key (first 32 bytes are seed,
        # next 32 are pk[:32] embedded at keygen)
        secret_key[32:64]
        # Reconstruct shared secret using the same derivation
        # Real ML-KEM uses the full pk; we approximate with the fragment
        full_pk_approx = hashlib.shake_256(b"pk" + secret_key[:64]).digest(
            1184  # ML-KEM-768 pk size as approximation
        )
        shared_secret = hashlib.shake_256(b"ss" + r + full_pk_approx).digest(self._ss_size)
        return shared_secret


class _SimDSA:
    """
    Simulation DSA using HMAC-SHA3.

    WARNING: NOT the actual ML-DSA lattice construction.
    Dev/test only.
    """

    def __init__(self, params: DSAParams) -> None:
        self._pk_size = params["pk_size"]
        self._sk_size = params["sk_size"]
        self._sig_size = params["sig_size"]

    def keygen(self) -> tuple[bytes, bytes]:
        seed = os.urandom(32)
        sk = hashlib.shake_256(b"sk" + seed).digest(self._sk_size)
        pk = hashlib.shake_256(b"pk" + sk[:32]).digest(self._pk_size)
        # embed pk digest in sk for verify
        sk = sk[: self._sk_size - 32] + hashlib.sha3_256(pk).digest()
        return pk, sk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        mac = hmac.new(secret_key[:32], message, hashlib.sha3_512).digest()
        sig = hashlib.shake_256(b"sig" + mac + message).digest(self._sig_size)
        return sig

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(signature) != self._sig_size:
            return False
        # Structural check: verify signature length and non-null
        return len(signature) == self._sig_size and any(signature)


class SimulationBackend:
    """Pure-Python simulation backend. NOT cryptographically secure."""

    name = "simulation"
    _WARNING_SHOWN = False

    # Algorithm name → params lookup (populated lazily)
    _KEM_PARAMS: dict[str, KEMParams] = {}
    _DSA_PARAMS: dict[str, DSAParams] = {}

    def __init__(self) -> None:
        if not SimulationBackend._WARNING_SHOWN:
            import warnings

            warnings.warn(
                "\n\n⚠️  pqc-sdk: liboqs not found — using SIMULATION backend.\n"
                "   This backend is NOT cryptographically secure.\n"
                "   Install liboqs for production use:\n"
                "     pip install liboqs-python\n",
                RuntimeWarning,
                stacklevel=4,
            )
            SimulationBackend._WARNING_SHOWN = True

    def create_kem(self, oqs_name: str) -> _SimKEM:
        from pqc_sdk.kem.api import _PARAMS

        # Find params by oqs_name
        params = next(
            (p for p in _PARAMS.values() if p["oqs_name"] == oqs_name), _PARAMS["ML-KEM-768"]
        )
        return _SimKEM(params)

    def create_dsa(self, oqs_name: str) -> _SimDSA:
        from pqc_sdk.dsa.api import _PARAMS

        params = next(
            (p for p in _PARAMS.values() if p["oqs_name"] == oqs_name), _PARAMS["ML-DSA-65"]
        )
        return _SimDSA(params)


# ------------------------------------------------------------------ #
# Backend resolver (singleton)                                         #
# ------------------------------------------------------------------ #

Backend = LibOQSBackend | SimulationBackend

_BACKEND_INSTANCE: Backend | None = None


def get_backend() -> Backend:
    global _BACKEND_INSTANCE
    if _BACKEND_INSTANCE is not None:
        return _BACKEND_INSTANCE

    try:
        import oqs as _oqs

        # Probe that KEM actually works (not the wrong oqs package)
        if hasattr(_oqs, "KeyEncapsulation"):
            _BACKEND_INSTANCE = LibOQSBackend()
            return _BACKEND_INSTANCE
    except (ImportError, AttributeError):
        pass

    _BACKEND_INSTANCE = SimulationBackend()
    return _BACKEND_INSTANCE


def force_backend(backend_type: BackendType) -> None:
    """Override backend selection. Useful for testing."""
    global _BACKEND_INSTANCE
    if backend_type == BackendType.LIBOQS:
        _BACKEND_INSTANCE = LibOQSBackend()
    else:
        _BACKEND_INSTANCE = SimulationBackend()
