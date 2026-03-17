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


class TestDiscoverHFModelIds:
    """Tests for _discover_hf_model_ids()."""

    def test_from_pretrained_in_python_file(self, tmp_path: Path):
        src = tmp_path / "train.py"
        src.write_text(
            'model = AutoModel.from_pretrained("facebook/opt-125m")\n',
            encoding="utf-8",
        )
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "facebook/opt-125m" in ids

    def test_pipeline_model_arg(self, tmp_path: Path):
        src = tmp_path / "infer.py"
        src.write_text(
            'pipe = pipeline("text-generation", model="gpt2")\n',
            encoding="utf-8",
        )
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "gpt2" in ids

    def test_model_id_assignment(self, tmp_path: Path):
        src = tmp_path / "config.py"
        src.write_text('model_id = "mistralai/Mistral-7B-v0.1"\n', encoding="utf-8")
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "mistralai/Mistral-7B-v0.1" in ids

    def test_base_model_assignment(self, tmp_path: Path):
        src = tmp_path / "finetune.py"
        src.write_text('base_model = "meta-llama/Llama-2-7b-hf"\n', encoding="utf-8")
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "meta-llama/Llama-2-7b-hf" in ids

    def test_yaml_model_id(self, tmp_path: Path):
        cfg = tmp_path / "train_config.yaml"
        cfg.write_text("model_id: stabilityai/stable-diffusion-2\nepochs: 10\n", encoding="utf-8")
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "stabilityai/stable-diffusion-2" in ids

    def test_yaml_base_model(self, tmp_path: Path):
        cfg = tmp_path / "lora.yml"
        cfg.write_text("base_model: 'meta-llama/Llama-2-13b-hf'\n", encoding="utf-8")
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "meta-llama/Llama-2-13b-hf" in ids

    def test_json_model_id(self, tmp_path: Path):
        cfg = tmp_path / "settings.json"
        cfg.write_text('{"model_id": "openai-community/gpt2", "batch_size": 8}', encoding="utf-8")
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "openai-community/gpt2" in ids

    def test_skips_local_paths(self, tmp_path: Path):
        src = tmp_path / "load.py"
        src.write_text(
            'model = AutoModel.from_pretrained("/local/path/to/model")\n'
            'model2 = AutoModel.from_pretrained("./relative/model")\n',
            encoding="utf-8",
        )
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert not any(mid.startswith(("/", ".")) for mid in ids)

    def test_skips_git_dir(self, tmp_path: Path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        hidden = git_dir / "hook.py"
        hidden.write_text('from_pretrained("should/not-appear")\n', encoding="utf-8")
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "should/not-appear" not in ids

    def test_empty_project(self, tmp_path: Path):
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert ids == set()

    def test_multiple_models_in_one_file(self, tmp_path: Path):
        src = tmp_path / "multi.py"
        src.write_text(
            'tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")\n'
            'model = AutoModel.from_pretrained("distilbert-base-uncased")\n',
            encoding="utf-8",
        )
        scanner = LicenseScanner()
        ids = scanner._discover_hf_model_ids(tmp_path)
        assert "bert-base-uncased" in ids
        assert "distilbert-base-uncased" in ids


class TestScanHFIntegration:
    """Tests for HF API integration inside scan()."""

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_scan_calls_hf_api_for_discovered_model(self, mock_client_cls, tmp_path: Path):
        """scan() should query HF API for model IDs found in source code."""
        src = tmp_path / "train.py"
        src.write_text('model = AutoModel.from_pretrained("facebook/opt-125m")\n', encoding="utf-8")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"cardData": {"license": "cc-by-nc-4.0"}, "tags": []}
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        findings = scanner.scan(tmp_path)

        hf_findings = [f for f in findings if f.source == "huggingface"]
        assert len(hf_findings) == 1
        assert hf_findings[0].package_or_model == "facebook/opt-125m"
        assert hf_findings[0].license_id == "cc-by-nc-4.0"

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_scan_deduplicates_local_and_hf(self, mock_client_cls, tmp_path: Path):
        """Model found in local config.json should not trigger duplicate HF API call."""
        # Local config.json with a model path that matches a source reference
        model_dir = tmp_path / "my_model"
        model_dir.mkdir()
        (model_dir / "config.json").write_text('{"license": "cc-by-nc-4.0"}', encoding="utf-8")

        # Python file referencing the same local dir (won't match HF ID pattern)
        src = tmp_path / "load.py"
        src.write_text('model = AutoModel.from_pretrained("./my_model")\n', encoding="utf-8")

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        findings = scanner.scan(tmp_path)

        # Local finding from config.json, no HF API call for local path
        local_findings = [f for f in findings if f.source == "local"]
        assert len(local_findings) == 1
        mock_client.get.assert_not_called()

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_scan_hf_api_permissive_no_finding(self, mock_client_cls, tmp_path: Path):
        """Permissive HF license should not produce a finding."""
        src = tmp_path / "app.py"
        src.write_text('model = AutoModel.from_pretrained("bert-base-uncased")\n', encoding="utf-8")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"cardData": {"license": "apache-2.0"}, "tags": []}
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        findings = scanner.scan(tmp_path)

        assert all(f.source != "huggingface" for f in findings)

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_scan_hf_api_network_error_does_not_crash(self, mock_client_cls, tmp_path: Path):
        """Network errors during HF API lookup should be silently swallowed."""
        src = tmp_path / "app.py"
        src.write_text('model_id = "some/model"\n', encoding="utf-8")

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = Exception("connection refused")
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        findings = scanner.scan(tmp_path)  # must not raise
        assert isinstance(findings, list)

    @patch("aicerberus.scanners.license.httpx.Client")
    def test_scan_yaml_hf_model_discovered(self, mock_client_cls, tmp_path: Path):
        """Model IDs in YAML config files are picked up and queried."""
        cfg = tmp_path / "training.yaml"
        cfg.write_text("base_model: meta-llama/Llama-2-7b-hf\nepochs: 3\n", encoding="utf-8")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "cardData": {"license": "llama2"},
            "tags": [],
        }
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = LicenseScanner()
        findings = scanner.scan(tmp_path)

        hf_findings = [f for f in findings if f.source == "huggingface"]
        assert len(hf_findings) == 1
        assert hf_findings[0].package_or_model == "meta-llama/Llama-2-7b-hf"
        assert hf_findings[0].severity == Severity.HIGH
