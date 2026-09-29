"""
Traceback package
Forwards Python standard library traceback functions so logging and pytest continue
to work, while exposing SAT-SA attack traceback submodules.
"""

import importlib.machinery
import importlib.util
import os
import sys

# Forward all stdlib traceback attributes
_paths = [p for p in sys.path if "backend" not in p and p not in ("", ".")]
_spec = importlib.machinery.PathFinder.find_spec("traceback", _paths)
if _spec and _spec.origin and os.path.abspath(_spec.origin) != os.path.abspath(__file__):
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    for _k, _v in _mod.__dict__.items():
        if not _k.startswith("__"):
            globals()[_k] = _v
