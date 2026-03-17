"""Tests for the CLI interface."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from aicerberus.cli import main, _result_to_dict, _filter_by_severity
from aicerberus.models import (
    CVEInfo,
    DependencyFinding,
    LicenseFinding,
    ModelFileFinding,
    RiskType,
    ScanResult,
    Severity,
)


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def clean_result(tmp_path: Path) -> ScanResult:
    return ScanResult(target_path=tmp_path)


@pytest.fixture()
def vulnerable_result(tmp_path: Path) -> ScanResult:
    result = ScanResult(target_path=tmp_path)
    result.dependency_findings = [
        DependencyFinding(
            package="torch",
            version="1.9.0",
            ecosystem="PyPI",
            source_file="requirements.txt",
            cves=[CVEInfo("CVE-2021-1234", Severity.HIGH, 7.5, "RCE in torch")],
        )
    ]
    return result


class TestCliScanCommand:
    def test_scan_clean_project_exit_0(self, runner: CliRunner, tmp_path: Path):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = ScanResult(target_path=tmp_path)
            mock_engine_cls.return_value = mock_engine
            result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_vulnerable_exit_1(self, runner: CliRunner, tmp_path: Path, vulnerable_result):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = vulnerable_result
            mock_engine_cls.return_value = mock_engine
            result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 1

    def test_scan_default_path_is_cwd(self, runner: CliRunner, tmp_path: Path):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
                mock_engine = MagicMock()
                mock_engine.scan.return_value = ScanResult(target_path=Path(".").resolve())
                mock_engine_cls.return_value = mock_engine
                result = runner.invoke(main, ["scan"])
        # Should run without error
        assert result.exit_code in (0, 1)

    def test_scan_json_format(self, runner: CliRunner, tmp_path: Path, vulnerable_result):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = vulnerable_result
            mock_engine_cls.return_value = mock_engine
            result = runner.invoke(main, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "dependency_findings" in data
        assert data["summary"]["total_cves"] == 1

    def test_scan_sbom_format(self, runner: CliRunner, tmp_path: Path, clean_result):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = clean_result
            mock_engine_cls.return_value = mock_engine
            result = runner.invoke(main, ["scan", str(tmp_path), "--format", "sbom"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["bomFormat"] == "CycloneDX"

    def test_scan_severity_filter(self, runner: CliRunner, tmp_path: Path, vulnerable_result):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = vulnerable_result
            mock_engine_cls.return_value = mock_engine
            # Filter to critical only — HIGH should be excluded
            result = runner.invoke(main, ["scan", str(tmp_path), "--severity", "critical"])
        assert result.exit_code == 0  # filtered result is clean

    def test_scan_fix_flag(self, runner: CliRunner, tmp_path: Path, vulnerable_result):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = vulnerable_result
            mock_engine_cls.return_value = mock_engine
            result = runner.invoke(main, ["scan", str(tmp_path), "--fix"])
        assert result.exit_code == 1
        assert "Fix" in result.output or "Upgrade" in result.output or "recommendation" in result.output.lower()

    def test_scan_write_json_to_file(self, runner: CliRunner, tmp_path: Path, clean_result):
        output_file = tmp_path / "report.json"
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = clean_result
            mock_engine_cls.return_value = mock_engine
            result = runner.invoke(
                main,
                ["scan", str(tmp_path), "--format", "json", "-o", str(output_file)],
            )
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "summary" in data

    def test_scan_skip_deps(self, runner: CliRunner, tmp_path: Path):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = ScanResult(target_path=tmp_path)
            mock_engine_cls.return_value = mock_engine
            runner.invoke(main, ["scan", str(tmp_path), "--skip-deps"])
            call_kwargs = mock_engine.scan.call_args[1]
            assert call_kwargs["skip_deps"] is True

    def test_scan_skip_models(self, runner: CliRunner, tmp_path: Path):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = ScanResult(target_path=tmp_path)
            mock_engine_cls.return_value = mock_engine
            runner.invoke(main, ["scan", str(tmp_path), "--skip-models"])
            call_kwargs = mock_engine.scan.call_args[1]
            assert call_kwargs["skip_models"] is True

    def test_scan_no_hf_api_flag(self, runner: CliRunner, tmp_path: Path):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = ScanResult(target_path=tmp_path)
            mock_engine_cls.return_value = mock_engine
            runner.invoke(main, ["scan", str(tmp_path), "--no-hf-api"])
            init_kwargs = mock_engine_cls.call_args[1]
            assert init_kwargs["check_hf_api"] is False

    def test_scan_hf_api_enabled_by_default(self, runner: CliRunner, tmp_path: Path):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = ScanResult(target_path=tmp_path)
            mock_engine_cls.return_value = mock_engine
            runner.invoke(main, ["scan", str(tmp_path)])
            init_kwargs = mock_engine_cls.call_args[1]
            assert init_kwargs["check_hf_api"] is True

    def test_version_flag(self, runner: CliRunner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_scan_quiet_flag(self, runner: CliRunner, tmp_path: Path, clean_result):
        with patch("aicerberus.cli.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = clean_result
            mock_engine_cls.return_value = mock_engine
            result = runner.invoke(main, ["scan", str(tmp_path), "--quiet"])
        # Quiet mode should produce less output
        assert result.exit_code == 0


class TestFilterBySeverity:
    def test_filter_keeps_high_when_min_is_high(self):
        result = ScanResult(target_path=Path("/p"))
        result.dependency_findings = [
            DependencyFinding("a", "1.0", "PyPI", "req.txt", cves=[
                CVEInfo("CVE-1", Severity.HIGH, 7.5, "high"),
                CVEInfo("CVE-2", Severity.LOW, 2.0, "low"),
            ])
        ]
        filtered = _filter_by_severity(result, "HIGH")
        assert len(filtered.dependency_findings) == 1
        assert len(filtered.dependency_findings[0].cves) == 1
        assert filtered.dependency_findings[0].cves[0].cve_id == "CVE-1"

    def test_filter_removes_all_below_critical(self):
        result = ScanResult(target_path=Path("/p"))
        result.dependency_findings = [
            DependencyFinding("a", "1.0", "PyPI", "req.txt", cves=[
                CVEInfo("CVE-1", Severity.HIGH, 7.5, "high"),
            ])
        ]
        filtered = _filter_by_severity(result, "CRITICAL")
        assert len(filtered.dependency_findings) == 0

    def test_filter_model_findings(self):
        result = ScanResult(target_path=Path("/p"))
        result.model_findings = [
            ModelFileFinding(
                path=Path("m.pkl"), format="pickle", size_bytes=100, sha256="x",
                risk_type=RiskType.UNSAFE_SERIALIZATION, severity=Severity.LOW,
                description="d", recommendation="r",
            )
        ]
        filtered = _filter_by_severity(result, "HIGH")
        assert len(filtered.model_findings) == 0


class TestResultToDict:
    def test_structure(self):
        result = ScanResult(target_path=Path("/p"))
        result.dependency_findings = [
            DependencyFinding("torch", "1.9.0", "PyPI", "req.txt", cves=[
                CVEInfo("CVE-2021-1", Severity.HIGH, 7.5, "RCE"),
            ])
        ]
        d = _result_to_dict(result)
        assert "target" in d
        assert "summary" in d
        assert d["summary"]["total_cves"] == 1
        assert d["summary"]["max_severity"] == "HIGH"
        assert len(d["dependency_findings"]) == 1
        cve = d["dependency_findings"][0]["cves"][0]
        assert cve["id"] == "CVE-2021-1"
        assert cve["severity"] == "HIGH"
