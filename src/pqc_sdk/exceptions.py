"""pqc-sdk custom exceptions."""


class PQCError(Exception):
    """Base exception for all pqc-sdk errors."""


class AlgorithmNotSupportedError(PQCError):
    """Raised when an unsupported algorithm is requested."""


class SignatureVerificationError(PQCError):
    """Raised when signature verification fails."""


class BackendError(PQCError):
    """Raised when the cryptographic backend encounters an error."""


class KeySizeError(PQCError):
    """Raised when key or ciphertext sizes don't match algorithm parameters."""
