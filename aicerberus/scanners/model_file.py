"""Model file scanner: detects unsafe serialization and malicious payloads."""
from __future__ import annotations

import hashlib
import io
import pickletools
from pathlib import Path

from aicerberus.models import ModelFileFinding, RiskType, Severity

# Model file extensions and their risk profiles
MODEL_EXTENSIONS: dict[str, dict] = {
    ".pkl": {"format": "pickle", "risk": RiskType.UNSAFE_SERIALIZATION, "severity": Severity.HIGH},
    ".pickle": {"format": "pickle", "risk": RiskType.UNSAFE_SERIALIZATION, "severity": Severity.HIGH},
    ".joblib": {"format": "joblib", "risk": RiskType.UNSAFE_SERIALIZATION, "severity": Severity.HIGH},
    ".pt": {"format": "pytorch", "risk": RiskType.UNSAFE_SERIALIZATION, "severity": Severity.HIGH},
    ".pth": {"format": "pytorch", "risk": RiskType.UNSAFE_SERIALIZATION, "severity": Severity.HIGH},
    ".bin": {"format": "binary", "risk": RiskType.UNSAFE_SERIALIZATION, "severity": Severity.MEDIUM},
    ".onnx": {"format": "onnx", "risk": RiskType.INTEGRITY, "severity": Severity.LOW},
    ".safetensors": {"format": "safetensors", "risk": RiskType.INTEGRITY, "severity": Severity.LOW},
    ".h5": {"format": "hdf5", "risk": RiskType.INTEGRITY, "severity": Severity.LOW},
    ".pb": {"format": "protobuf", "risk": RiskType.INTEGRITY, "severity": Severity.LOW},
}

# Dangerous global references in pickle payloads
DANGEROUS_GLOBALS: frozenset[str] = frozenset(
    {
        "os system", "os popen", "os execv", "os execve", "os execvp",
        "os spawnl", "os spawnle", "os spawnlp", "os spawnlpe",
        "subprocess Popen", "subprocess call", "subprocess check_call",
        "subprocess check_output", "subprocess run",
        "builtins eval", "builtins exec", "builtins compile",
        "builtins __import__",
        "importlib import_module",
        "nt system",  # Windows
        "posix system",  # POSIX alias
        "socket socket",
        "shutil rmtree",
    }
)

# PyTorch ZIP magic bytes (PK header)
_ZIP_MAGIC = b"PK\x03\x04"
# PyTorch legacy format magic
_PYTORCH_MAGIC = b"\x80\x02"


def _sha256(path: Path) -> str:
    """Compute SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _analyze_pickle_opcodes(data: bytes) -> list[str]:
    """
    Safely disassemble pickle bytecode and return list of dangerous patterns found.

    This function NEVER executes the pickle content — it only reads opcodes.
    Uses pickletools.genops() which is a pure parser.
    """
    dangerous_found: list[str] = []
    globals_seen: list[str] = []
    buf = io.BytesIO(data)

    try:
        for opcode, arg, _ in pickletools.genops(buf):
            opname = opcode.name
            if opname == "GLOBAL" and isinstance(arg, str):
                # arg is "module name" e.g. "os system"
                globals_seen.append(arg)
                if arg in DANGEROUS_GLOBALS:
                    dangerous_found.append(f"GLOBAL:{arg}")
            elif opname == "STACK_GLOBAL":
                # Two-arg form pushed onto stack; we catch the GLOBAL variant above
                pass
            elif opname in ("REDUCE", "BUILD", "NEWOBJ") and globals_seen:
                last_global = globals_seen[-1]
                if last_global in DANGEROUS_GLOBALS:
                    dangerous_found.append(f"CALL:{last_global}")
            elif opname == "SHORT_BINUNICODE" and isinstance(arg, str):
                # Catch string args that look like shell commands
                lower = arg.lower()
                if any(kw in lower for kw in ("eval(", "exec(", "import os", "__import__")):
                    dangerous_found.append(f"SUSPICIOUS_STRING:{arg[:80]}")
    except Exception:
        # Corrupted or truncated pickle — not our job to fix it
        pass

    return list(dict.fromkeys(dangerous_found))  # deduplicate, preserve order


def _analyze_pytorch_file(path: Path) -> list[str]:
    """
    PyTorch .pt/.pth files are ZIP archives containing pickle data (data.pkl).
    Extract and analyze the pickle without loading the model.
    """
    import zipfile

    dangerous: list[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("data.pkl") or name.endswith(".pkl"):
                    pkl_data = zf.read(name)
                    hits = _analyze_pickle_opcodes(pkl_data)
                    dangerous.extend(hits)
    except (zipfile.BadZipFile, Exception):
        # Legacy PyTorch format — first two bytes are pickle protocol header
        try:
            raw = path.read_bytes()
            if raw[:2] == _PYTORCH_MAGIC:
                dangerous.extend(_analyze_pickle_opcodes(raw))
        except Exception:
            pass
    return dangerous


def _is_pytorch_zip(path: Path) -> bool:
    """Check if file is a PyTorch ZIP-format checkpoint."""
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        return header[:4] == _ZIP_MAGIC
    except Exception:
        return False


class ModelFileScanner:
    """Scans model files for unsafe serialization formats and malicious payloads."""

    # Skip directories that are unlikely to contain user model files
    SKIP_DIRS: frozenset[str] = frozenset(
        {".git", "__pycache__", ".tox", ".venv", "venv", "node_modules", ".eggs", "build", "dist"}
    )

    def find_model_files(self, path: Path) -> list[Path]:
        """Recursively find model files under path."""
        found: list[Path] = []
        for ext in MODEL_EXTENSIONS:
            for fp in path.rglob(f"*{ext}"):
                # Skip if any parent is in SKIP_DIRS
                if any(part in self.SKIP_DIRS for part in fp.parts):
                    continue
                found.append(fp)
        return sorted(set(found))

    def scan_file(self, file_path: Path) -> ModelFileFinding | None:
        """Analyse a single model file and return a finding (or None if safe)."""
        ext = file_path.suffix.lower()
        meta = MODEL_EXTENSIONS.get(ext)
        if meta is None:
            return None

        try:
            size = file_path.stat().st_size
            sha = _sha256(file_path)
        except OSError:
            return None

        fmt: str = meta["format"]
        risk: RiskType = meta["risk"]
        severity: Severity = meta["severity"]
        opcodes: list[str] = []

        # ── Pickle / joblib analysis ──────────────────────────────────────────
        if fmt in ("pickle", "joblib"):
            try:
                raw = file_path.read_bytes()
                opcodes = _analyze_pickle_opcodes(raw)
            except OSError:
                pass

            if opcodes:
                severity = Severity.CRITICAL
                risk = RiskType.MALICIOUS_PAYLOAD
                description = (
                    f"Pickle file contains dangerous opcode patterns: {', '.join(opcodes[:5])}. "
                    "This may indicate a malicious payload that executes arbitrary code on load."
                )
                recommendation = (
                    "Do NOT load this file. Investigate origin and integrity. "
                    "Migrate to safetensors format for safe model storage."
                )
            else:
                description = (
                    f"{fmt.capitalize()} serialization is inherently unsafe — "
                    "any pickle file can execute arbitrary Python code when loaded with pickle.load()."
                )
                recommendation = (
                    "Migrate to safetensors (pip install safetensors) for PyTorch/numpy models, "
                    "or ONNX for cross-framework deployment. Never load untrusted pickle files."
                )

        # ── PyTorch checkpoint (ZIP + pickle inside) ──────────────────────────
        elif fmt == "pytorch":
            if _is_pytorch_zip(file_path):
                opcodes = _analyze_pytorch_file(file_path)
            else:
                try:
                    raw = file_path.read_bytes()
                    opcodes = _analyze_pickle_opcodes(raw)
                except OSError:
                    pass

            if opcodes:
                severity = Severity.CRITICAL
                risk = RiskType.MALICIOUS_PAYLOAD
                description = (
                    f"PyTorch checkpoint contains dangerous pickle opcodes: {', '.join(opcodes[:5])}."
                )
                recommendation = (
                    "Do NOT load this checkpoint. Use torch.load(..., weights_only=True) "
                    "as a mitigation, or migrate to safetensors format."
                )
            else:
                description = (
                    "PyTorch .pt/.pth files use pickle internally, "
                    "making them susceptible to arbitrary code execution on load."
                )
                recommendation = (
                    "Use torch.load(..., weights_only=True) to restrict deserialization. "
                    "Consider migrating to safetensors for immutable weight storage."
                )

        # ── Binary blobs (.bin — e.g. HuggingFace shards) ────────────────────
        elif fmt == "binary":
            description = (
                ".bin files from HuggingFace are typically pickle-based PyTorch shards. "
                "They carry the same arbitrary-code-execution risk as .pt files."
            )
            recommendation = (
                "Prefer .safetensors variants when available on HuggingFace Hub. "
                "Verify the source repository before loading."
            )
            # Try pickle analysis on .bin files too
            try:
                raw = file_path.read_bytes()
                if raw[:2] == _PYTORCH_MAGIC or raw[:4] == _ZIP_MAGIC:
                    opcodes = _analyze_pickle_opcodes(raw) if raw[:2] == _PYTORCH_MAGIC else _analyze_pytorch_file(file_path)
                    if opcodes:
                        severity = Severity.CRITICAL
                        risk = RiskType.MALICIOUS_PAYLOAD
                        description = (
                            f".bin file contains dangerous pickle opcodes: {', '.join(opcodes[:5])}."
                        )
            except OSError:
                pass

        # ── ONNX / safetensors / HDF5 / protobuf — lower risk ────────────────
        elif fmt == "onnx":
            description = (
                "ONNX model files use Protocol Buffers serialization, which does not support "
                "arbitrary code execution. Risk is low but file integrity should be verified."
            )
            recommendation = "Verify file hash matches the published model checksum."
        elif fmt == "safetensors":
            description = (
                "safetensors format is memory-safe and cannot execute code on load. "
                "This is the recommended format for model weight storage."
            )
            recommendation = "No action required. safetensors is the preferred safe format."
            severity = Severity.LOW
            risk = RiskType.INTEGRITY
        elif fmt == "hdf5":
            description = (
                "HDF5/Keras model files may contain serialized Python objects (Lambda layers). "
                "Loading from untrusted sources can execute arbitrary code."
            )
            recommendation = (
                "Avoid loading models with Lambda/custom layers from untrusted sources. "
                "Use tf.saved_model or ONNX export for safer distribution."
            )
        elif fmt == "protobuf":
            description = (
                "TensorFlow SavedModel / protobuf format. Low code-execution risk, "
                "but model graph can contain malicious ops on some older TF versions."
            )
            recommendation = "Verify model origin and update TensorFlow to the latest version."
        else:
            description = f"Unknown model format {fmt!r}. Manual review recommended."
            recommendation = "Verify file origin and format before loading."

        return ModelFileFinding(
            path=file_path,
            format=fmt,
            size_bytes=size,
            sha256=sha,
            risk_type=risk,
            severity=severity,
            description=description,
            recommendation=recommendation,
            opcodes_found=opcodes,
        )

    def scan(self, path: Path) -> list[ModelFileFinding]:
        """Scan all model files under path."""
        files = self.find_model_files(path)
        findings: list[ModelFileFinding] = []
        for f in files:
            finding = self.scan_file(f)
            if finding is not None:
                findings.append(finding)
        return findings
