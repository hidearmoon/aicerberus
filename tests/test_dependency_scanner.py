"""Tests for the dependency scanner."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aicerberus.models import Severity
from aicerberus.scanners.dependency import (
    DependencyScanner,
    _is_ai_ml_package,
    _parse_osv_response,
    _parse_pipfile,
    _parse_pyproject_toml,
    _parse_requirements_txt,
)


# ── Parser unit tests ─────────────────────────────────────────────────────────

class TestParseRequirementsTxt:
    def test_pinned_version(self):
        result = _parse_requirements_txt("torch==1.9.0\n", "req.txt")
        assert ("torch", "1.9.0", "req.txt") in result

    def test_ge_version(self):
        result = _parse_requirements_txt("numpy>=1.21.0\n", "req.txt")
        assert result[0][0] == "numpy"
        assert result[0][1] == "1.21.0"

    def test_extras(self):
        result = _parse_requirements_txt("ray[serve]==2.5.0\n", "req.txt")
        assert result[0][0] == "ray"
        assert result[0][1] == "2.5.0"

    def test_no_version(self):
        result = _parse_requirements_txt("transformers\n", "req.txt")
        assert result[0][0] == "transformers"
        assert result[0][1] == ""

    def test_skip_comments(self):
        result = _parse_requirements_txt("# this is a comment\ntorch==1.0\n", "req.txt")
        assert len(result) == 1

    def test_skip_dash_r(self):
        result = _parse_requirements_txt("-r base.txt\ntorch==1.0\n", "req.txt")
        assert len(result) == 1

    def test_empty(self):
        assert _parse_requirements_txt("", "req.txt") == []

    def test_multiple_packages(self):
        content = "torch==1.9.0\ntransformers==4.20.0\nflask==2.0.0\n"
        result = _parse_requirements_txt(content, "req.txt")
        names = [r[0] for r in result]
        assert "torch" in names
        assert "transformers" in names
        assert "flask" in names


class TestParsePyprojectToml:
    def test_pep621_deps(self):
        toml = b'[project]\ndependencies = ["torch>=1.9", "openai==1.0"]\n'
        result = _parse_pyproject_toml(toml, "pyproject.toml")
        names = [r[0] for r in result]
        assert "torch" in names
        assert "openai" in names

    def test_poetry_deps(self):
        toml = (
            b"[tool.poetry.dependencies]\n"
            b'python = "^3.9"\n'
            b'langchain = "^0.1.0"\n'
        )
        result = _parse_pyproject_toml(toml, "pyproject.toml")
        names = [r[0] for r in result]
        assert "langchain" in names
        assert "python" not in names

    def test_invalid_toml(self):
        result = _parse_pyproject_toml(b"not valid toml {{", "pyproject.toml")
        assert result == []

    def test_empty_toml(self):
        result = _parse_pyproject_toml(b"", "pyproject.toml")
        assert result == []


class TestParsePipfile:
    def test_packages(self):
        content = '[packages]\ntorch = "*"\ntransformers = ">=4.0"\n'
        result = _parse_pipfile(content, "Pipfile")
        names = [r[0] for r in result]
        assert "torch" in names
        assert "transformers" in names

    def test_dev_packages_ignored_for_ai(self):
        content = '[dev-packages]\njupyter = "*"\n[packages]\ntorch = "1.9"\n'
        result = _parse_pipfile(content, "Pipfile")
        names = [r[0] for r in result]
        assert "torch" in names

    def test_invalid_pipfile(self):
        result = _parse_pipfile("{{invalid", "Pipfile")
        assert result == []


class TestIsAiMlPackage:
    def test_known_packages(self):
        for pkg in ["torch", "tensorflow", "transformers", "openai", "langchain"]:
            assert _is_ai_ml_package(pkg), f"{pkg} should be AI/ML"

    def test_non_ai_packages(self):
        for pkg in ["flask", "requests", "boto3", "django", "sqlalchemy"]:
            assert not _is_ai_ml_package(pkg), f"{pkg} should not be AI/ML"

    def test_fuzzy_match(self):
        assert _is_ai_ml_package("my-gpt-wrapper")
        assert _is_ai_ml_package("custom-langchain-ext")

    def test_underscore_normalization(self):
        assert _is_ai_ml_package("hugging_face_hub")


class TestParseOsvResponse:
    def test_empty_vulns(self):
        finding = _parse_osv_response("torch", "1.9.0", "req.txt", [])
        assert finding.package == "torch"
        assert finding.cves == []

    def test_cve_extraction(self):
        vulns = [
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "aliases": ["CVE-2021-12345"],
                "summary": "Remote code execution",
                "severity": [{"type": "CVSS_V3", "score": "8.5"}],
                "affected": [{"ranges": [{"events": [{"fixed": "2.0.0"}]}]}],
                "references": [{"url": "https://example.com/advisory"}],
            }
        ]
        finding = _parse_osv_response("torch", "1.9.0", "req.txt", vulns)
        assert len(finding.cves) == 1
        cve = finding.cves[0]
        assert cve.cve_id == "CVE-2021-12345"
        assert cve.cvss_score == 8.5
        assert cve.severity == Severity.HIGH
        assert cve.fixed_version == "2.0.0"

    def test_database_specific_severity(self):
        vulns = [
            {
                "id": "GHSA-abcd",
                "aliases": [],
                "summary": "Issue",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [],
                "references": [],
            }
        ]
        finding = _parse_osv_response("pkg", "1.0", "req.txt", vulns)
        assert finding.cves[0].severity == Severity.CRITICAL


class TestDependencyScannerIntegration:
    def test_find_dependency_files(self, project_with_requirements: Path):
        scanner = DependencyScanner()
        files = scanner.find_dependency_files(project_with_requirements)
        names = [f.name for f in files]
        assert "requirements.txt" in names

    def test_parse_and_filter_ai_deps(self, project_with_requirements: Path):
        scanner = DependencyScanner()
        manifest = project_with_requirements / "requirements.txt"
        deps = scanner.parse_dependencies(manifest)
        ai_deps = scanner.filter_ai_dependencies(deps)
        names = [d[0] for d in ai_deps]
        assert "torch" in names
        assert "transformers" in names
        # requests is not AI/ML
        assert "requests" not in names

    def test_scan_empty_dir(self, tmp_project: Path):
        scanner = DependencyScanner()
        findings = scanner.scan(tmp_project)
        assert findings == []

    @patch("aicerberus.scanners.dependency.httpx.Client")
    def test_query_osv_batch_http_error(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = Exception("connection refused")
        mock_client_cls.return_value = mock_client

        scanner = DependencyScanner()
        result = scanner.query_osv_batch([("torch", "1.9.0")])
        assert result == {}

    @patch("aicerberus.scanners.dependency.httpx.Client")
    def test_query_osv_batch_success(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "results": [{"vulns": [{"id": "CVE-2021-1", "aliases": [], "summary": "x", "affected": []}]}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        scanner = DependencyScanner()
        result = scanner.query_osv_batch([("torch", "1.9.0")])
        assert ("torch", "1.9.0") in result

    def test_query_osv_batch_empty(self):
        scanner = DependencyScanner()
        result = scanner.query_osv_batch([])
        assert result == {}
