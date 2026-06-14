"""
pqc-sdk benchmarks
Run: pytest benchmarks/ --benchmark-only
"""

import sys
from pathlib import Path
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from pqc_sdk import KEM, DSA, HybridKEM
from pqc_sdk import _backend as _b

# Force simulation for sandbox; liboqs benchmarks run in CI
if _b._BACKEND_INSTANCE is None:
    _b._BACKEND_INSTANCE = _b.SimulationBackend()


# ── KEM Benchmarks ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def kem_512(): return KEM("ML-KEM-512")

@pytest.fixture(scope="module")
def kem_768(): return KEM("ML-KEM-768")

@pytest.fixture(scope="module")
def kem_1024(): return KEM("ML-KEM-1024")


def test_bench_kem512_keygen(benchmark, kem_512):
    benchmark(kem_512.keygen)

def test_bench_kem768_keygen(benchmark, kem_768):
    benchmark(kem_768.keygen)

def test_bench_kem1024_keygen(benchmark, kem_1024):
    benchmark(kem_1024.keygen)


def test_bench_kem768_encapsulate(benchmark, kem_768):
    pk, _ = kem_768.keygen()
    benchmark(kem_768.encapsulate, pk)


def test_bench_kem768_decapsulate(benchmark, kem_768):
    pk, sk = kem_768.keygen()
    ct, _ = kem_768.encapsulate(pk)
    benchmark(kem_768.decapsulate, sk, ct)


# ── DSA Benchmarks ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def dsa_44(): return DSA("ML-DSA-44")

@pytest.fixture(scope="module")
def dsa_65(): return DSA("ML-DSA-65")


def test_bench_dsa65_keygen(benchmark, dsa_65):
    benchmark(dsa_65.keygen)


def test_bench_dsa65_sign(benchmark, dsa_65):
    _, sk = dsa_65.keygen()
    msg = b"benchmark message for ML-DSA-65 signing"
    benchmark(dsa_65.sign, sk, msg)


def test_bench_dsa65_verify(benchmark, dsa_65):
    pk, sk = dsa_65.keygen()
    msg = b"benchmark message for ML-DSA-65 signing"
    sig = dsa_65.sign(sk, msg)
    benchmark(dsa_65.verify, pk, msg, sig)


# ── Hybrid KEM Benchmarks ─────────────────────────────────────────

@pytest.fixture(scope="module")
def hkem(): return HybridKEM("ML-KEM-768")


def test_bench_hybrid_keygen(benchmark, hkem):
    benchmark(hkem.keygen)


def test_bench_hybrid_encapsulate(benchmark, hkem):
    pk, _ = hkem.keygen()
    benchmark(hkem.encapsulate, pk)


def test_bench_hybrid_decapsulate(benchmark, hkem):
    pk, sk = hkem.keygen()
    ct, _ = hkem.encapsulate(pk)
    benchmark(hkem.decapsulate, sk, ct)
