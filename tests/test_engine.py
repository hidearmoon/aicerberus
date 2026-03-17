"""Tests for the ScanEngine orchestrator."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aicerberus.engine import ScanEngine
from aicerberus.models import ScanResult


class TestScanEngine:
    def test_scan_returns_scan_result(self, tmp_project: Path):
        with patch("aicerberus.engine.DependencyScanner") as dep_cls, \
             patch("aicerberus.engine.ModelFileScanner") as model_cls, \
             patch("aicerberus.engine.LicenseScanner") as lic_cls:

            dep_cls.return_value.scan.return_value = []
            model_cls.return_value.scan.return_value = []
            lic_cls.return_value.scan.return_value = []

            engine = ScanEngine()
            result = engine.scan(tmp_project)

        assert isinstance(result, ScanResult)
        assert result.target_path == tmp_project

    def test_skip_deps(self, tmp_project: Path):
        with patch("aicerberus.engine.DependencyScanner") as dep_cls, \
             patch("aicerberus.engine.ModelFileScanner") as model_cls, \
             patch("aicerberus.engine.LicenseScanner") as lic_cls:

            dep_cls.return_value.scan.return_value = []
            model_cls.return_value.scan.return_value = []
            lic_cls.return_value.scan.return_value = []

            engine = ScanEngine()
            engine.scan(tmp_project, skip_deps=True)

        dep_cls.return_value.scan.assert_not_called()

    def test_skip_models(self, tmp_project: Path):
        with patch("aicerberus.engine.DependencyScanner") as dep_cls, \
             patch("aicerberus.engine.ModelFileScanner") as model_cls, \
             patch("aicerberus.engine.LicenseScanner") as lic_cls:

            dep_cls.return_value.scan.return_value = []
            model_cls.return_value.scan.return_value = []
            lic_cls.return_value.scan.return_value = []

            engine = ScanEngine()
            engine.scan(tmp_project, skip_models=True)

        model_cls.return_value.scan.assert_not_called()

    def test_skip_licenses(self, tmp_project: Path):
        with patch("aicerberus.engine.DependencyScanner") as dep_cls, \
             patch("aicerberus.engine.ModelFileScanner") as model_cls, \
             patch("aicerberus.engine.LicenseScanner") as lic_cls:

            dep_cls.return_value.scan.return_value = []
            model_cls.return_value.scan.return_value = []
            lic_cls.return_value.scan.return_value = []

            engine = ScanEngine()
            engine.scan(tmp_project, skip_licenses=True)

        lic_cls.return_value.scan.assert_not_called()

    def test_progress_callback_called(self, tmp_project: Path):
        with patch("aicerberus.engine.DependencyScanner") as dep_cls, \
             patch("aicerberus.engine.ModelFileScanner") as model_cls, \
             patch("aicerberus.engine.LicenseScanner") as lic_cls:

            dep_cls.return_value.scan.return_value = []
            model_cls.return_value.scan.return_value = []
            lic_cls.return_value.scan.return_value = []

            messages: list[str] = []
            engine = ScanEngine(progress_callback=messages.append)
            engine.scan(tmp_project)

        assert len(messages) == 3  # one per scanner

    def test_generate_sbom(self, tmp_project: Path):
        with patch("aicerberus.engine.DependencyScanner") as dep_cls, \
             patch("aicerberus.engine.ModelFileScanner") as model_cls, \
             patch("aicerberus.engine.LicenseScanner") as lic_cls:

            dep_cls.return_value.scan.return_value = []
            model_cls.return_value.scan.return_value = []
            lic_cls.return_value.scan.return_value = []

            engine = ScanEngine()
            result = engine.scan(tmp_project)
            sbom = engine.generate_sbom(result)

        assert sbom["bomFormat"] == "CycloneDX"
        assert "metadata" in sbom

    def test_check_hf_api_false_passed_to_license_scanner(self, tmp_project: Path):
        """ScanEngine(check_hf_api=False) passes check_hf_api=False to LicenseScanner.scan()."""
        with patch("aicerberus.engine.DependencyScanner") as dep_cls, \
             patch("aicerberus.engine.ModelFileScanner") as model_cls, \
             patch("aicerberus.engine.LicenseScanner") as lic_cls:

            dep_cls.return_value.scan.return_value = []
            model_cls.return_value.scan.return_value = []
            lic_cls.return_value.scan.return_value = []

            engine = ScanEngine(check_hf_api=False)
            engine.scan(tmp_project)

        lic_cls.return_value.scan.assert_called_once_with(tmp_project, check_hf_api=False)
