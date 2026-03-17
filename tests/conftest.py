"""Shared fixtures for AICerberus tests."""
from __future__ import annotations

import io
import pickle
import pickletools
import struct
import zipfile
from pathlib import Path

import pytest


# ── Pickle helpers ────────────────────────────────────────────────────────────

def make_safe_pickle(obj: object) -> bytes:
    """Pickle a simple safe object."""
    return pickle.dumps(obj)


def make_malicious_pickle() -> bytes:
    """
    Build a pickle payload that references os.system (DANGEROUS GLOBAL).
    NOTE: This payload is NEVER executed in tests — it is only written to bytes
    and then analysed by the opcode scanner.
    """
    # Manually construct pickle opcodes that reference os.system
    # Protocol 2 header + GLOBAL os\nsystem + MARK + string + TUPLE + REDUCE + STOP
    buf = io.BytesIO()
    buf.write(b"\x80\x02")                    # PROTO 2
    buf.write(b"c")                            # GLOBAL opcode
    buf.write(b"os\nsystem\n")                # module + name
    buf.write(b"(")                            # MARK
    buf.write(b"X\x02\x00\x00\x00ls")         # SHORT_BINUNICODE 'ls'
    buf.write(b"t")                            # TUPLE (MARK to here)
    buf.write(b"R")                            # REDUCE
    buf.write(b".")                            # STOP
    return buf.getvalue()


def make_pytorch_zip_with_malicious_pkl() -> bytes:
    """Create a fake PyTorch ZIP checkpoint containing a malicious data.pkl."""
    malicious = make_malicious_pickle()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", malicious)
    return buf.getvalue()


def make_pytorch_zip_safe() -> bytes:
    """Create a safe PyTorch-style ZIP checkpoint."""
    safe_pkl = make_safe_pickle({"weights": [1.0, 2.0, 3.0]})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("model/data.pkl", safe_pkl)
    return buf.getvalue()


# ── Directory fixtures ────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    """An empty project directory."""
    return tmp_path


@pytest.fixture()
def project_with_requirements(tmp_path: Path) -> Path:
    """Project with a requirements.txt containing AI packages."""
    req = tmp_path / "requirements.txt"
    req.write_text(
        "torch==1.9.0\n"
        "transformers==4.20.0\n"
        "numpy>=1.21.0\n"
        "langchain==0.0.200\n"
        "requests==2.28.0\n"  # non-AI package
        "# comment line\n"
        "-r other.txt\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture()
def project_with_pyproject(tmp_path: Path) -> Path:
    """Project with a pyproject.toml containing AI dependencies."""
    ppt = tmp_path / "pyproject.toml"
    ppt.write_text(
        '[project]\nname = "myapp"\nversion = "1.0"\n'
        'dependencies = [\n'
        '  "openai>=1.0",\n'
        '  "langchain-core==0.1.0",\n'
        '  "flask>=2.0",\n'  # non-AI
        ']\n',
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture()
def project_with_pickle_model(tmp_path: Path) -> Path:
    """Project with a safe pickle model file."""
    model = tmp_path / "model.pkl"
    model.write_bytes(make_safe_pickle({"a": 1}))
    return tmp_path


@pytest.fixture()
def project_with_malicious_model(tmp_path: Path) -> Path:
    """Project with a malicious pickle model file."""
    model = tmp_path / "evil_model.pkl"
    model.write_bytes(make_malicious_pickle())
    return tmp_path


@pytest.fixture()
def project_with_pytorch_model(tmp_path: Path) -> Path:
    """Project with a PyTorch ZIP-format checkpoint."""
    model = tmp_path / "checkpoint.pt"
    model.write_bytes(make_pytorch_zip_safe())
    return tmp_path


@pytest.fixture()
def project_with_safetensors(tmp_path: Path) -> Path:
    """Project with a safetensors model file (fake content)."""
    model = tmp_path / "model.safetensors"
    model.write_bytes(b"\x00" * 64)  # fake content
    return tmp_path


@pytest.fixture()
def project_with_hf_config(tmp_path: Path) -> Path:
    """Project with a HuggingFace config.json containing a restricted license."""
    config = tmp_path / "config.json"
    config.write_text('{"license": "cc-by-nc-4.0", "model_type": "bert"}', encoding="utf-8")
    return tmp_path


@pytest.fixture()
def project_with_permissive_hf_config(tmp_path: Path) -> Path:
    """Project with a HuggingFace config.json with permissive license."""
    config = tmp_path / "config.json"
    config.write_text('{"license": "apache-2.0", "model_type": "bert"}', encoding="utf-8")
    return tmp_path
