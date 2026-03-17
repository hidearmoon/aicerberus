"""Tests for the license scanner."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aicerberus.models import Severity
from aicerberus.scanners.license import (
    LicenseScanner,
    _lookup_license_risk,
    _normalise_license,
)


class TestNormaliseLicense:
    def test_lowercase(self):
        assert _normalise_license("MIT") == "mit"

    def test_strip_spaces(self):
        assert _normalise_license("  Apache-2.0  ") == "apache-2.0"

    def test_space_to_dash(self):
        assert _normalise_license("CC BY NC 4.0") == "cc-by-nc-4.0"

    def test_underscore_to_dash(self):
        assert _normalise_license("cc_by_nc_4.0") == "cc-by-nc-4.0"


class TestLookupLicenseRisk:
    def test_permissive_returns_none(self):
        assert _lookup_license_risk("MIT") is None
        assert _lookup_license_risk("Apache-2.0") is None
        assert _lookup_license_risk("BSD-3-Clause") is None

    def test_openrail_is_high(self):
        risk = _lookup_license_risk("OpenRAIL")
        assert risk is not None
        assert risk[1] == Severity.HIGH

    def test_cc_by_nc_is_high(self):
        risk = _lookup_license_risk("CC-BY-NC-4.0")
        assert risk is not None
        assert risk[1] == Severity.HIGH
        assert "NON_COMMERCIAL" in risk[0]

    def test_agpl_is_high(self):
        risk = _lookup_license_risk("AGPL-3.0")
        assert risk is not None
        assert risk[1] == Severity.HIGH

    def test_gpl_is_high(self):
        risk = _lookup_license_risk("GPL-3.0")
        assert risk is not None
        assert risk[1] == Severity.HIGH

    def test_llama2_is_high(self):
        risk = _lookup_license_risk("llama2")
        assert risk is not None
        assert risk[1] == Severity.HIGH

    def test_unknown_license_is_medium(self):
        risk = _lookup_license_risk("some-weird-custom-license-v99")
        assert risk is not None
        assert risk[1] == Severity.MEDIUM

    def test_research_only_is_critical(self):
        risk = _lookup_license_risk("research-only")
        assert risk is not None
        assert risk[1] == Severity.CRITICAL


class TestLicenseScannerLocal:
    def test_scan_restricted_hf_config(self, project_with_hf_config: Path):
        scanner = LicenseScanner()
        findings = scanner.scan(project_with_hf_config)
        assert len(findings) >= 1
        assert any(f.license_id == "cc-by-nc-4.0" for f in findings)

    def test_scan_permissive_hf_config(self, project_with_permissive_hf_config: Path):
        scanner = LicenseScanner()
        findings = scanner.scan(project_with_permissive_hf_config)
        # Apache-2.0 is permissive, no finding from config.json
        license_findings_from_config = [f for f in findings if f.source == "local"]
        assert len(license_findings_from_config) == 0

    def test_scan_empty_dir(self, tmp_project: Path):
        scanner = LicenseScanner()
        findings = scanner.scan(tmp_project)
        assert findings == []

    def test_check_local_model_card_no_license(self, tmp_path: Path):
        config = tmp_path / "config.json"
        config.write_text('{"model_type": "bert"}', encoding="utf-8")
        scanner = LicenseScanner()
        result = scanner.check_local_model_card(config)
        assert result is None

    def test_check_local_model_card_invalid_json(self, tmp_path: Path):
        config = tmp_path / "config.json"
        config.write_text("{not valid json", encoding="utf-8")
        scanner = LicenseScanner()
        result = scanner.check_local_model_card(config)
        assert result is None

    def test_pyproject_gpl_license(self, tmp_path: Path):
        ppt = tmp_path / "pyproject.toml"
        ppt.write_text(
            '[project]\nname = "mylib"\nversion = "1.0"\n'
            '[project.license]\ntext = "GPL-3.0"\n',
            encoding="utf-8",
        )
        scanner = LicenseScanner()
        findings = scanner.scan(tmp_path)
        gpl_findings = [f for f in findings if "gpl" in f.license_id.lower()]
        assert len(gpl_findings) >= 1

    def test_pyproject_mit_license(self, tmp_path: Path):
        ppt = tmp_path / "pyproject.toml"
        ppt.write_text(
            '[project]\nname = "mylib"\n[project.license]\ntext = "MIT"\n',
            encoding="utf-8",
        )
        scanner = LicenseScanner()
        findings = scanner.scan(tmp_path)
        pypi_findings = [f for f in findings if f.source == "pypi"]
        assert len(pypi_findings) == 0

    def test_openrail_license_source_local(self, tmp_path: Path):
        config = tmp_path / "config.json"
        config.write_text('{"license": "openrail"}', encoding="utf-8")
        scanner = LicenseScanner()
        finding = scanner.check_local_model_card(config)
        assert finding is not None
        assert finding.source == "local"
        assert finding.severity == Severity.HIGH


class TestLicenseScannerHF:
    @patch("aicerberus.scanners.license.httpx.Client")
    def test_check_hf_model_success(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "cardData": {"license": "cc-by-nc-4.0"},
            "tags": [],
        }
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        finding = scanner.check_hf_model("bert-base-uncased")
        assert finding is not None
        assert finding.license_id == "cc-by-nc-4.0"
        assert finding.source == "huggingface"

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_check_hf_model_permissive(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "cardData": {"license": "apache-2.0"},
            "tags": [],
        }
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        finding = scanner.check_hf_model("some/model")
        assert finding is None

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_check_hf_model_not_found(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        finding = scanner.check_hf_model("non/existent-model")
        assert finding is None

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_check_hf_model_network_error(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = Exception("network error")
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        finding = scanner.check_hf_model("some/model")
        assert finding is None

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_check_hf_model_license_from_tags(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "cardData": {},
            "tags": ["license:agpl-3.0", "task:text-generation"],
            "license": "",
        }
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        finding = scanner.check_hf_model("some/model")
        assert finding is not None
        assert finding.license_id == "agpl-3.0"
