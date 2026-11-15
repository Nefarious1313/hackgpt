"""Test package for HackGPT.

Sets an isolated HACKGPT_HOME before the hackgpt package is imported so the
suite never touches the operator's real config/sessions/output.
"""
import os
import tempfile

os.environ.setdefault("HACKGPT_HOME", tempfile.mkdtemp(prefix="hackgpt-test-"))
