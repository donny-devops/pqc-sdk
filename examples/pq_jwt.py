"""
Example: Post-Quantum JWT Replacement
======================================
Replaces RS256/ES256 JWTs with ML-DSA-65 signed tokens.

Standard JWTs use RSA or ECDSA — both broken by Shor's algorithm.
This example implements a drop-in PQ token format using ML-DSA-65 (FIPS 204).

Token format (base64url-encoded):
    header.payload.signature
    where header includes "alg": "ML-DSA-65"

Usage pattern mirrors PyJWT:
    token = pqjwt.encode({"sub": "user123", "exp": ...}, secret_key)
    claims = pqjwt.decode(token, public_key)
"""

import base64
import json
import time
from pathlib import Path
from typing import Any

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pqc_sdk import DSA
from pqc_sdk.exceptions import SignatureVerificationError


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


class PQJWTError(Exception):
    pass


class ExpiredTokenError(PQJWTError):
    pass


class PQJWTSigner:
    """
    Post-quantum JWT issuer/verifier using ML-DSA-65.

    Drop-in replacement for PyJWT with quantum-safe signatures.

    Example:
        signer = PQJWTSigner()
        public_key, secret_key = signer.generate_keypair()

        token = signer.encode({"sub": "user_123", "role": "admin"}, secret_key)
        claims = signer.decode(token, public_key)
    """

    def __init__(self, algorithm: str = "ML-DSA-65") -> None:
        self._dsa = DSA(algorithm)
        self.algorithm = algorithm

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate issuer key pair. Distribute public key to verifiers."""
        pk, sk = self._dsa.keygen()
        print(f"[keygen] {self.algorithm}")
        print(f"  Public key: {len(pk):>5} bytes (distribute to token verifiers)")
        print(f"  Secret key: {len(sk):>5} bytes (keep private on auth server)")
        return pk, sk

    def encode(
        self,
        payload: dict[str, Any],
        secret_key: bytes,
        expiry_seconds: int = 3600,
    ) -> str:
        """
        Issue a PQ-signed token.

        Args:
            payload: Claims dict (sub, role, etc.)
            secret_key: Issuer's ML-DSA secret key.
            expiry_seconds: Token lifetime.

        Returns:
            Compact serialization: header.payload.signature
        """
        now = int(time.time())
        full_payload = {
            **payload,
            "iat": now,
            "exp": now + expiry_seconds,
        }

        header = {"alg": self.algorithm, "typ": "PQJWT"}
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(full_payload, separators=(",", ":")).encode())

        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = self._dsa.sign(secret_key, signing_input)
        sig_b64 = _b64url_encode(signature)

        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        print(f"\n[encode] Token issued")
        print(f"  Total token size: {len(token)} bytes")
        print(f"  Signature size:   {len(signature)} bytes (ML-DSA-65)")
        return token

    def decode(self, token: str, public_key: bytes) -> dict[str, Any]:
        """
        Verify and decode a PQ-signed token.

        Args:
            token: Compact serialization string.
            public_key: Issuer's ML-DSA public key.

        Returns:
            Verified claims dict.

        Raises:
            PQJWTError: If token is malformed or signature invalid.
            ExpiredTokenError: If token has expired.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise PQJWTError("Malformed token: expected 3 parts")

        header_b64, payload_b64, sig_b64 = parts

        # Verify header
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") != self.algorithm:
            raise PQJWTError(
                f"Algorithm mismatch: token uses {header.get('alg')!r}, "
                f"expected {self.algorithm!r}"
            )

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = _b64url_decode(sig_b64)
        try:
            self._dsa.verify(public_key, signing_input, signature)
        except SignatureVerificationError as e:
            raise PQJWTError(f"Invalid signature: {e}") from e

        # Decode and check expiry
        claims = json.loads(_b64url_decode(payload_b64))
        if "exp" in claims and claims["exp"] < int(time.time()):
            raise ExpiredTokenError("Token has expired")

        print(f"\n[decode] Signature verified ✓")
        return claims


if __name__ == "__main__":
    print("=" * 60)
    print("PQC JWT Replacement: ML-DSA-65 (FIPS 204)")
    print("=" * 60)

    signer = PQJWTSigner("ML-DSA-65")

    # Auth server generates keys once at startup
    public_key, secret_key = signer.generate_keypair()

    # Issue a token
    token = signer.encode(
        payload={"sub": "user_donny_42", "role": "admin", "org": "DreamTech"},
        secret_key=secret_key,
        expiry_seconds=3600,
    )

    # Any service with public_key can verify
    claims = signer.decode(token, public_key)
    print(f"  Claims: {json.dumps(claims, indent=2)}")

    # Test tampering detection
    print("\n[tamper test] Modifying token payload...")
    parts = token.split(".")
    evil_payload = _b64url_encode(json.dumps({"sub": "attacker", "role": "admin"}).encode())
    tampered = f"{parts[0]}.{evil_payload}.{parts[2]}"
    try:
        signer.decode(tampered, public_key)
        print("  FAILED: Tampered token was accepted!")
    except PQJWTError as e:
        print(f"  ✓ Tampered token correctly rejected: {e}")

    print("\n✓ PQ JWT example complete")
