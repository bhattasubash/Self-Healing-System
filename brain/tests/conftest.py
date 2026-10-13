"""Pytest configuration and fixtures for brain test suite."""

import sys
from pathlib import Path

# Ensure 'brain' root is in sys.path so 'import app...' works seamlessly
brain_dir = Path(__file__).resolve().parent.parent
if str(brain_dir) not in sys.path:
    sys.path.insert(0, str(brain_dir))
