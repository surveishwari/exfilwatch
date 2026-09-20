import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# isolate the audit DB before anything imports db/main
os.environ.setdefault("EXFILWATCH_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
