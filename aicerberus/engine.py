"""Scan orchestration engine — coordinates all scanners."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from aicerberus.models import ScanResult
from aicerberus.scanners.dependency import DependencyScanner
from aicerberus.scanners.license import LicenseScanner
from aicerberus.scanners.model_file import ModelFileScanner
from aicerberus.scanners.sbom import SBOMGenerator


class ScanEngine:
    """Orchestrates all AICerberus scanners."""

    def __init__(
        self,
        osv_timeout: float = 30.0,
        hf_api_token: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        self._dep_scanner = DependencyScanner(timeout=osv_timeout)
        self._model_scanner = ModelFileScanner()
        self._license_scanner = LicenseScanner(hf_api_token=hf_api_token)
        self._sbom_gen = SBOMGenerator()
        self._progress = progress_callback or (lambda _: None)

    def scan(
        self,
        path: Path,
        *,
        skip_deps: bool = False,
        skip_models: bool = False,
        skip_licenses: bool = False,
    ) -> ScanResult:
        """Run a full scan of *path* and return aggregated results."""
        result = ScanResult(target_path=path)

        if not skip_deps:
            self._progress("Scanning AI/ML dependencies…")
            try:
                result.dependency_findings = self._dep_scanner.scan(path)
            except Exception as exc:  # pragma: no cover
                result.scan_errors.append(f"Dependency scan error: {exc}")

        if not skip_models:
            self._progress("Scanning model files…")
            try:
                result.model_findings = self._model_scanner.scan(path)
            except Exception as exc:  # pragma: no cover
                result.scan_errors.append(f"Model scan error: {exc}")

        if not skip_licenses:
            self._progress("Checking license compliance…")
            try:
                result.license_findings = self._license_scanner.scan(path)
            except Exception as exc:  # pragma: no cover
                result.scan_errors.append(f"License scan error: {exc}")

        return result

    def generate_sbom(self, result: ScanResult) -> dict:
        """Generate CycloneDX SBOM from a ScanResult."""
        return self._sbom_gen.generate(result)
