# Copilot Code Review Instructions — Post-Quantum Cryptography SDK

## Cryptographic Security Standards (CRITICAL)

### 1. NIST FIPS 203/204/205 Compliance
- **Algorithm Implementation**
  - Verify implementations match NIST specifications exactly
  - Flag any deviations from ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
  - Check for proper parameter set usage (security levels 1-5)
  - Ensure no custom or experimental algorithm variants
- **Test Vectors**
  - All implementations must pass NIST Known Answer Tests (KATs)
  - Verify test vectors match NIST published values
  - Check for comprehensive edge case testing
- **Security Levels**
  - Clearly document which NIST security level (1-5) each function targets
  - Verify key sizes match security level requirements
  - Flag mixing of security levels without clear rationale

### 2. Cryptographic Best Practices (CRITICAL)
- **Key Management**
  - Private keys MUST be zeroed after use (`explicit_bzero`, `memzero_explicit`)
  - No key material in logs, error messages, or debug output
  - Check for proper key derivation functions (HKDF, KMAC)
  - Verify secure random number generation (OS-provided CSPRNG)
- **Side-Channel Resistance**
  - Flag timing-dependent operations on secret data
  - Verify constant-time comparisons for MACs/signatures
  - Check for cache-timing vulnerabilities in lookup tables
  - Ensure no secret-dependent branching
- **Memory Safety**
  - All buffers properly bounds-checked
  - No stack/heap overflows in key generation or operations
  - Secure memory allocation for sensitive data
  - Check for use-after-free vulnerabilities

### 3. Hybrid Classical-PQC Patterns
- **Transition Security**
  - Verify proper concatenation of classical + PQC keys
  - Check for hybrid signature schemes (e.g., ECDSA + ML-DSA)
  - Ensure both layers provide adequate security
  - Flag reliance on single algorithm for security
- **Backwards Compatibility**
  - Check for graceful fallback to classical crypto
  - Verify version negotiation for hybrid modes
  - Test interoperability with non-PQC systems

### 4. API Design Security
- **Input Validation**
  - All public functions validate input lengths and formats
  - Check for integer overflow in size calculations
  - Verify proper handling of malformed ciphertexts/signatures
  - Flag missing error handling on decode operations
- **Error Handling**
  - Cryptographic failures MUST NOT leak information
  - Use constant-time rejection sampling
  - No timing differences between valid/invalid inputs
  - Generic error messages only
- **Type Safety**
  - Use type hints for all function signatures
  - Verify proper use of `bytes` vs `str` in Python
  - Check for buffer type confusion (mutable vs immutable)

### 5. Dependencies & Supply Chain
- **Cryptographic Libraries**
  - Use well-vetted libraries (liboqs, PQClean) as reference
  - Pin exact versions with cryptographic hashes
  - Flag any unaudited or custom crypto implementations
  - Verify dependency integrity (checksums, signatures)
- **Build Reproducibility**
  - Ensure deterministic builds where possible
  - Check for supply chain hardening in CI/CD
  - Verify code signing of releases

### 6. Testing & Validation
- **Test Coverage Requirements**
  - Unit tests for all public functions
  - Known Answer Tests (KATs) from NIST
  - Negative tests (invalid keys, corrupted ciphertext)
  - Cross-implementation compatibility tests
  - Side-channel resistance tests (if applicable)
- **Fuzzing**
  - Check for fuzzing targets on decode/verification functions
  - Verify crash-free operation on malformed inputs
  - AFL/libFuzzer integration recommended

### 7. Documentation Requirements
- **Security Considerations**
  - Document threat model clearly
  - Specify which attacks are mitigated
  - List known limitations or vulnerabilities
  - Provide migration guide from classical crypto
- **Usage Examples**
  - Show secure key generation patterns
  - Demonstrate proper key lifecycle management
  - Include hybrid classical-PQC examples
  - Warn against common misuse patterns

### 8. Compliance & Standards
- **FIPS Compliance**
  - Implementations intended for FIPS validation must be unmodified
  - Document any deviations with clear rationale
  - Include compliance matrix in documentation
- **Export Controls**
  - Note if code subject to export restrictions
  - Include appropriate compliance notices

## Code Quality Standards
- Type hints on all public APIs
- Docstrings with security notes
- Follow PEP 8 for Python, appropriate style for other languages
- Use constant-time primitives where available
- Prefer audited libraries over custom implementations

## Response Format
```
**[CRITICAL]**: Cryptographic Vulnerability - Timing Leak in Signature Verification

**Location**: `pqc_sdk/ml_dsa.py:156`
**Problem**: Signature comparison uses standard `==` operator
**Risk**: Timing side-channel allows signature forgery (CVE-worthy vulnerability)
**Fix**: 
\```python
# Before (vulnerable)
if signature == expected_signature:
    return True

# After (constant-time)
import hmac
if hmac.compare_digest(signature, expected_signature):
    return True
\```
**Reference**: 
- NIST FIPS 204 §8.2 (Side-Channel Resistance)
- CWE-208: Observable Timing Discrepancy
```

Severity: CRITICAL | HIGH | MEDIUM | LOW | ADVISORY

## Special Notes
- **Any CRITICAL severity finding in cryptographic code should block merge immediately**
- **Consult cryptographic expert for novel patterns or optimizations**
- **When in doubt, choose security over performance**
