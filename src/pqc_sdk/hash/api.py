"""
Hash functions approved for use in PQC contexts.

FIPS 202 (SHA-3 / SHAKE) and FIPS 180-4 (SHA-2) are both approved
for use alongside FIPS 203/204/205 algorithms.

SHA-3 variants are generally preferred in new PQC deployments.
"""

from __future__ import annotations

import hashlib
from enum import Enum


class HashAlgorithm(Enum):
    SHA3_256 = "sha3_256"      # 256-bit, FIPS 202
    SHA3_384 = "sha3_384"      # 384-bit, FIPS 202
    SHA3_512 = "sha3_512"      # 512-bit, FIPS 202
    SHAKE_128 = "shake_128"    # XOF, variable output, FIPS 202
    SHAKE_256 = "shake_256"    # XOF, variable output, FIPS 202 ← preferred for PQC
    SHA2_256 = "sha256"        # Legacy compat, FIPS 180-4
    SHA2_512 = "sha512"        # Legacy compat, FIPS 180-4


_DEFAULT_OUTPUT_SIZES = {
    HashAlgorithm.SHA3_256: 32,
    HashAlgorithm.SHA3_384: 48,
    HashAlgorithm.SHA3_512: 64,
    HashAlgorithm.SHAKE_128: 32,
    HashAlgorithm.SHAKE_256: 32,
    HashAlgorithm.SHA2_256: 32,
    HashAlgorithm.SHA2_512: 64,
}


def hash_message(
    message: bytes,
    algorithm: HashAlgorithm = HashAlgorithm.SHAKE_256,
    output_size: int | None = None,
) -> bytes:
    """
    Hash a message using a FIPS-approved algorithm.

    Args:
        message: Input bytes to hash.
        algorithm: Hash algorithm to use. Defaults to SHAKE-256.
        output_size: Output length in bytes (only applies to XOF variants
                     SHAKE_128 / SHAKE_256). Ignored for fixed-output algorithms.

    Returns:
        Hash digest as bytes.

    Example:
        >>> digest = hash_message(b"hello world", HashAlgorithm.SHA3_256)
        >>> len(digest)
        32
        >>> xof = hash_message(b"hello", HashAlgorithm.SHAKE_256, output_size=64)
        >>> len(xof)
        64
    """
    size = output_size or _DEFAULT_OUTPUT_SIZES[algorithm]
    name = algorithm.value

    if algorithm in (HashAlgorithm.SHAKE_128, HashAlgorithm.SHAKE_256):
        h = hashlib.new(name)
        h.update(message)
        return h.digest(size)

    h = hashlib.new(name)
    h.update(message)
    return h.digest()
