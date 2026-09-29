import os
import sys
import traceback

# Ensure backend/ directory is on sys.path
_backend_dir = os.path.dirname(os.path.abspath(__file__))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# Allow 'traceback' package submodules (correlate, path, service) to be resolved
# alongside the Python standard library traceback module.
_tb_dir = os.path.join(_backend_dir, "traceback")
if os.path.isdir(_tb_dir):
    if not hasattr(traceback, "__path__"):
        traceback.__path__ = [_tb_dir]
    elif _tb_dir not in traceback.__path__:
        traceback.__path__.append(_tb_dir)
