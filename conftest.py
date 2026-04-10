import sys
import os

# The repo root IS the soc_toolkit package.
# Add its parent directory to sys.path so that
# "from soc_toolkit.models..." works correctly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
