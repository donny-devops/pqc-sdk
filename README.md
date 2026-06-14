# pqc-sdk

**Post-Quantum Cryptography SDK for Python** — drop-in ML-KEM, ML-DSA, and SLH-DSA primitives aligned with NIST FIPS 203, 204, and 205.

[![CI](https://github.com/donny-devops/post-quantum-studio/actions/workflows/ci.yml/badge.svg)](https://github.com/donny-devops/post-quantum-studio/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/pqc-sdk.svg)](https://pypi.org/project/pqc-sdk/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![FIPS 203](https://img.shields.io/badge/FIPS-203-orange.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![FIPS 204](https://img.shields.io/badge/FIPS-204-orange.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![FIPS 205](https://img.shields.io/badge/FIPS-205-orange.svg)](https://csrc.nist.gov/pubs/fips/205/final)

---

## Why pqc-sdk?

RSA, ECDH, and ECDSA are broken by Shor's algorithm on a sufficiently powerful quantum computer. NIST finalized its post-quantum standards in 2024:

| Standard | Algorithm | Replaces |
|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | RSA-OAEP, ECDH |
| FIPS 204 | ML-DSA (Dilithium) | RSA-PSS, ECDSA |
| FIPS 205 | SLH-DSA (SPHINCS+) | RSA, ECDSA (stateless hash-based) |

`pqc-sdk` wraps these with a clean Python API so you can adopt PQC without reading 200-page NIST specs.

---

## Install

```bash
# Basic install (simulation backend — dev/testing only)
pip install pqc-sdk

# With native liboqs backend (production — cryptographically secure)
pip install "pqc-sdk[native]"
```

> **Backends:** pqc-sdk auto-detects liboqs. Without it, a simulation backend activates and emits a `RuntimeWarning`. The simulation backend is structurally correct (right key/ciphertext sizes) but **NOT cryptographically secure**. Always install `liboqs-python` for production.

---

## Quick start

### Key Encapsulation (ML-KEM / FIPS 203)

```python
from pqc_sdk import KEM

kem = KEM("ML-KEM-768")          # NIST security level 3 (recommended)
public_key, secret_key = kem.keygen()

# Sender
ciphertext, shared_secret = kem.encapsulate(public_key)

# Recipient
recovered = kem.decapsulate(secret_key, ciphertext)
assert shared_secret == recovered
```

### Digital Signatures (ML-DSA / FIPS 204)

```python
from pqc_sdk import DSA

dsa = DSA("ML-DSA-65")           # NIST security level 3 (recommended)
public_key, secret_key = dsa.keygen()

signature = dsa.sign(secret_key, b"message to sign")
dsa.verify(public_key, b"message to sign", signature)  # True or raises
```

### Hybrid KEM (X25519 + ML-KEM-768)

Recommended during the migration period — quantum-safe AND classically secure:

```python
from pqc_sdk import HybridKEM

hkem = HybridKEM()               # X25519 + ML-KEM-768
public_key, secret_key = hkem.keygen()
ciphertext, shared_secret = hkem.encapsulate(public_key)
recovered = hkem.decapsulate(secret_key, ciphertext)
assert shared_secret == recovered
```

---

## Algorithm support matrix

### ML-KEM (FIPS 203) — Key Encapsulation

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|---|---|---|---|---|---|
| `ML-KEM-512` | 1 (~AES-128) | 800 B | 1,632 B | 768 B | 32 B |
| `ML-KEM-768` ★ | 3 (~AES-192) | 1,184 B | 2,400 B | 1,088 B | 32 B |
| `ML-KEM-1024` | 5 (~AES-256) | 1,568 B | 3,168 B | 1,568 B | 32 B |

★ Recommended default. Legacy aliases: `Kyber512`, `Kyber768`, `Kyber1024`.

### ML-DSA (FIPS 204) — Digital Signatures

| Algorithm | Security Level | Public Key | Secret Key | Signature |
|---|---|---|---|---|
| `ML-DSA-44` | 2 (~AES-128) | 1,312 B | 2,528 B | 2,420 B |
| `ML-DSA-65` ★ | 3 (~AES-192) | 1,952 B | 4,000 B | 3,309 B |
| `ML-DSA-87` | 5 (~AES-256) | 2,592 B | 4,864 B | 4,627 B |

★ Recommended default. Legacy aliases: `Dilithium2`, `Dilithium3`, `Dilithium5`.

### SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures

| Algorithm | Security Level | Public Key | Signature | Notes |
|---|---|---|---|---|
| `SLH-DSA-SHAKE-128s` | 1 | 32 B | 7,856 B | Small signatures |
| `SLH-DSA-SHAKE-128f` | 1 | 32 B | 17,088 B | Fast signing |
| `SLH-DSA-SHAKE-256s` | 5 | 64 B | 29,792 B | Small, high security |
| `SLH-DSA-SHAKE-256f` | 5 | 64 B | 49,856 B | Fast, high security |

---

## Real-world examples

### File encryption (ML-KEM + AES-256-GCM)

```python
from pqc_sdk import KEM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Recipient generates key pair
kem = KEM("ML-KEM-768")
pk, sk = kem.keygen()

# Sender encrypts
ct_kem, shared_secret = kem.encapsulate(pk)
nonce = os.urandom(12)
ciphertext = AESGCM(shared_secret).encrypt(nonce, plaintext, None)
wire = ct_kem + nonce + ciphertext

# Recipient decrypts
ct_kem, nonce, ciphertext = wire[:1088], wire[1088:1100], wire[1100:]
shared_secret = kem.decapsulate(sk, ct_kem)
plaintext = AESGCM(shared_secret).decrypt(nonce, ciphertext, None)
```

See [examples/file_encryption.py](examples/file_encryption.py) for the full implementation.

### PQ JWT (ML-DSA replaces RS256/ES256)

```python
from pqc_sdk.examples.pq_jwt import PQJWTSigner

signer = PQJWTSigner("ML-DSA-65")
pk, sk = signer.generate_keypair()

token = signer.encode({"sub": "user_42", "role": "admin"}, sk)
claims = signer.decode(token, pk)
```

See [examples/pq_jwt.py](examples/pq_jwt.py).

### TLS handshake simulation (Hybrid KEM)

See [examples/tls_handshake.py](examples/tls_handshake.py) for a TLS 1.3-style key exchange using X25519 + ML-KEM-768 with full HKDF key schedule and AES-256-GCM session encryption.

---

## Benchmarks

Measured on Apple M2 Pro with native liboqs backend:

| Operation | Algorithm | Mean |
|---|---|---|
| KeyGen | ML-KEM-768 | 21 µs |
| Encapsulate | ML-KEM-768 | 26 µs |
| Decapsulate | ML-KEM-768 | 22 µs |
| KeyGen | ML-DSA-65 | 89 µs |
| Sign | ML-DSA-65 | 131 µs |
| Verify | ML-DSA-65 | 53 µs |
| KeyGen | X25519 + ML-KEM-768 | 48 µs |
| Encapsulate | X25519 + ML-KEM-768 | 58 µs |

Run benchmarks locally:

```bash
pytest benchmarks/ --benchmark-only --benchmark-sort=mean
```

---

## Hashes

FIPS-approved hash functions for use alongside PQC algorithms:

```python
from pqc_sdk import hash_message, HashAlgorithm

digest = hash_message(b"data", HashAlgorithm.SHAKE_256)          # 32 bytes
digest = hash_message(b"data", HashAlgorithm.SHA3_256)           # 32 bytes
xof    = hash_message(b"data", HashAlgorithm.SHAKE_256, output_size=64)  # 64 bytes
```

Supported: `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE_128`, `SHAKE_256`, `SHA2_256`, `SHA2_512`.

---

## Development

```bash
git clone https://github.com/donny-devops/post-quantum-studio
cd post-quantum-studio
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run benchmarks
pytest benchmarks/ --benchmark-only

# Lint
ruff check src/ tests/
black src/ tests/
```

---

## Production checklist

- [ ] Install `liboqs-python` (`pip install "pqc-sdk[native]"`)
- [ ] Verify backend: `from pqc_sdk import KEM; print(KEM().backend)` → should print `liboqs`
- [ ] Use `ML-KEM-768` or `HybridKEM` for key exchange
- [ ] Use `ML-DSA-65` for signatures
- [ ] Store secret keys in a secrets manager (AWS Secrets Manager, Vault, etc.)
- [ ] Rotate keys per your organization's key management policy

---

## License

MIT © [PostQuantumStudio](https://postquantumstudio.com) / Adonis Jimenez

---

## Links

- [PostQuantumStudio](https://postquantumstudio.com) — docs, migration guides, tooling
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [liboqs](https://github.com/open-quantum-safe/liboqs)
