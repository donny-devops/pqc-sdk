# Patch get_backend to skip liboqs detection in sandbox
import pqc_sdk._backend as _b

_orig = _b.get_backend
def _patched_get_backend():
    global _b
    if _b._BACKEND_INSTANCE is not None:
        return _b._BACKEND_INSTANCE
    _b._BACKEND_INSTANCE = _b.SimulationBackend()
    return _b._BACKEND_INSTANCE
_b.get_backend = _patched_get_backend
