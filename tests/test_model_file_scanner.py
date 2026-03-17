"""Tests for the model file scanner."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from aicerberus.models import RiskType, Severity
from aicerberus.scanners.model_file import (
    ModelFileScanner,
    _analyze_pickle_opcodes,
    _analyze_pytorch_file,
    _sha256,
)
from tests.conftest import (
    make_malicious_pickle,
    make_pytorch_zip_safe,
    make_pytorch_zip_with_malicious_pkl,
    make_safe_pickle,
)


class TestPickleOpcodeAnalysis:
    def test_safe_pickle_no_dangerous_opcodes(self):
        data = make_safe_pickle({"key": "value", "numbers": [1, 2, 3]})
        result = _analyze_pickle_opcodes(data)
        assert result == []

    def test_malicious_pickle_detected(self):
        data = make_malicious_pickle()
        result = _analyze_pickle_opcodes(data)
        assert any("os" in r.lower() or "system" in r.lower() for r in result)

    def test_safe_pickle_list(self):
        data = make_safe_pickle([1, 2, 3, "hello"])
        result = _analyze_pickle_opcodes(data)
        assert result == []

    def test_safe_pickle_nested(self):
        data = make_safe_pickle({"a": {"b": {"c": 42}}})
        result = _analyze_pickle_opcodes(data)
        assert result == []

    def test_corrupted_data_no_crash(self):
        # Should not raise, just return empty or partial results
        result = _analyze_pickle_opcodes(b"\x80\x02CORRUPTED_DATA!!!!")
        assert isinstance(result, list)

    def test_empty_bytes(self):
        result = _analyze_pickle_opcodes(b"")
        assert isinstance(result, list)


class TestPytorchFileAnalysis:
    def test_safe_pytorch_zip(self, tmp_path: Path):
        model_file = tmp_path / "model.pt"
        model_file.write_bytes(make_pytorch_zip_safe())
        result = _analyze_pytorch_file(model_file)
        assert result == []

    def test_malicious_pytorch_zip(self, tmp_path: Path):
        model_file = tmp_path / "evil.pt"
        model_file.write_bytes(make_pytorch_zip_with_malicious_pkl())
        result = _analyze_pytorch_file(model_file)
        assert len(result) > 0

    def test_bad_zip_no_crash(self, tmp_path: Path):
        model_file = tmp_path / "bad.pt"
        model_file.write_bytes(b"\x00" * 100)
        result = _analyze_pytorch_file(model_file)
        assert isinstance(result, list)


class TestSha256:
    def test_sha256_consistent(self, tmp_path: Path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"hello world")
        h1 = _sha256(f)
        h2 = _sha256(f)
        assert h1 == h2
        assert len(h1) == 64

    def test_sha256_different_content(self, tmp_path: Path):
        f1 = tmp_path / "a.bin"
        f2 = tmp_path / "b.bin"
        f1.write_bytes(b"content A")
        f2.write_bytes(b"content B")
        assert _sha256(f1) != _sha256(f2)


class TestModelFileScanner:
    def test_find_model_files_pkl(self, project_with_pickle_model: Path):
        scanner = ModelFileScanner()
        files = scanner.find_model_files(project_with_pickle_model)
        assert any(f.suffix == ".pkl" for f in files)

    def test_find_model_files_empty_dir(self, tmp_project: Path):
        scanner = ModelFileScanner()
        files = scanner.find_model_files(tmp_project)
        assert files == []

    def test_find_model_files_multiple_types(self, tmp_path: Path):
        (tmp_path / "model.pkl").write_bytes(make_safe_pickle({}))
        (tmp_path / "weights.pt").write_bytes(make_pytorch_zip_safe())
        (tmp_path / "model.onnx").write_bytes(b"\x00" * 64)
        scanner = ModelFileScanner()
        files = scanner.find_model_files(tmp_path)
        exts = {f.suffix for f in files}
        assert ".pkl" in exts
        assert ".pt" in exts
        assert ".onnx" in exts

    def test_skip_venv_dirs(self, tmp_path: Path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "model.pkl").write_bytes(make_safe_pickle({}))
        scanner = ModelFileScanner()
        files = scanner.find_model_files(tmp_path)
        assert not any(".venv" in str(f) for f in files)

    def test_skip_git_dirs(self, tmp_path: Path):
        git_dir = tmp_path / ".git" / "objects"
        git_dir.mkdir(parents=True)
        (git_dir / "pack.pkl").write_bytes(b"\x00" * 10)
        scanner = ModelFileScanner()
        files = scanner.find_model_files(tmp_path)
        assert files == []

    def test_scan_safe_pickle(self, project_with_pickle_model: Path):
        scanner = ModelFileScanner()
        findings = scanner.scan(project_with_pickle_model)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.risk_type == RiskType.UNSAFE_SERIALIZATION
        assert finding.opcodes_found == []

    def test_scan_malicious_pickle(self, project_with_malicious_model: Path):
        scanner = ModelFileScanner()
        findings = scanner.scan(project_with_malicious_model)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.CRITICAL
        assert finding.risk_type == RiskType.MALICIOUS_PAYLOAD
        assert len(finding.opcodes_found) > 0

    def test_scan_safetensors(self, project_with_safetensors: Path):
        scanner = ModelFileScanner()
        findings = scanner.scan(project_with_safetensors)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.format == "safetensors"
        assert finding.severity == Severity.LOW

    def test_scan_pytorch_model(self, project_with_pytorch_model: Path):
        scanner = ModelFileScanner()
        findings = scanner.scan(project_with_pytorch_model)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.format == "pytorch"
        assert finding.severity == Severity.HIGH
        assert finding.opcodes_found == []

    def test_scan_pytorch_malicious(self, tmp_path: Path):
        model = tmp_path / "bad.pt"
        model.write_bytes(make_pytorch_zip_with_malicious_pkl())
        scanner = ModelFileScanner()
        findings = scanner.scan(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_scan_onnx_low_risk(self, tmp_path: Path):
        (tmp_path / "model.onnx").write_bytes(b"\x00" * 100)
        scanner = ModelFileScanner()
        findings = scanner.scan(tmp_path)
        assert findings[0].format == "onnx"
        assert findings[0].severity == Severity.LOW

    def test_scan_file_nonexistent(self, tmp_path: Path):
        scanner = ModelFileScanner()
        result = scanner.scan_file(tmp_path / "nonexistent.pkl")
        assert result is None

    def test_scan_file_unknown_extension(self, tmp_path: Path):
        f = tmp_path / "model.xyz"
        f.write_bytes(b"\x00" * 10)
        scanner = ModelFileScanner()
        result = scanner.scan_file(f)
        assert result is None

    def test_finding_has_sha256(self, project_with_pickle_model: Path):
        scanner = ModelFileScanner()
        findings = scanner.scan(project_with_pickle_model)
        assert len(findings[0].sha256) == 64
        assert all(c in "0123456789abcdef" for c in findings[0].sha256)

    def test_finding_has_size(self, project_with_pickle_model: Path):
        scanner = ModelFileScanner()
        findings = scanner.scan(project_with_pickle_model)
        assert findings[0].size_bytes > 0
