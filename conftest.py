import sys, warnings
sys.path.insert(0, "src")
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Remove any partially imported oqs before tests touch the backend
sys.modules.pop("oqs", None)

from pqc_sdk import _backend as _b
_b._BACKEND_INSTANCE = _b.SimulationBackend()
