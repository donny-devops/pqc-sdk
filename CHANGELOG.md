# Changelog

All notable changes to pqc-sdk are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.0] — 2026-06-14

### Added
- `KEM` class: ML-KEM-512/768/1024 (FIPS 203) with `keygen`, `encapsulate`, `decapsulate`
- `DSA` class: ML-DSA-44/65/87 (FIPS 204) and SLH-DSA-SHAKE variants (FIPS 205)
- `HybridKEM` class: X25519 + ML-KEM-768 with HKDF-SHA3-256 key combiner
- `hash_message`: SHA3-256/384/512, SHAKE-128/256, SHA2-256/512
- Legacy algorithm aliases: `Kyber512/768/1024`, `Dilithium2/3/5`
- Auto-detecting backend: liboqs (production) with simulation fallback (dev/test)
- `RuntimeWarning` when simulation backend activates
- Examples: file encryption, PQ JWT, TLS handshake simulation
- Benchmarks via pytest-benchmark
- GitHub Actions CI: lint → test (Python 3.10/3.11/3.12) → PyPI publish on release
- PyPI OIDC trusted publishing (no API key required)

[Unreleased]: https://github.com/donny-devops/post-quantum-studio/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/donny-devops/post-quantum-studio/releases/tag/v0.1.0
