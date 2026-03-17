"""Tests for aicerberus.models."""
from __future__ import annotations

from pathlib import Path

import pytest

from aicerberus.models import (
    CVEInfo,
    DependencyFinding,
    LicenseFinding,
    ModelFileFinding,
    RiskType,
    ScanResult,
    Severity,
)


class TestSeverity:
    def test_from_cvss_critical(self):
        assert Severity.from_cvss(9.5) == Severity.CRITICAL

    def test_from_cvss_high(self):
        assert Severity.from_cvss(8.0) == Severity.HIGH

    def test_from_cvss_medium(self):
        assert Severity.from_cvss(5.0) == Severity.MEDIUM

    def test_from_cvss_low(self):
        assert Severity.from_cvss(2.0) == Severity.LOW

    def test_from_cvss_unknown_zero(self):
        assert Severity.from_cvss(0.0) == Severity.UNKNOWN

    def test_rank_ordering(self):
        assert Severity.CRITICAL.rank > Severity.HIGH.rank
        assert Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank > Severity.LOW.rank
        assert Severity.LOW.rank > Severity.UNKNOWN.rank

    def test_is_str(self):
        assert Severity.CRITICAL == "CRITICAL"


class TestDependencyFinding:
    def test_max_severity_no_cves(self):
        d = DependencyFinding("pkg", "1.0", "PyPI", "req.txt")
        assert d.max_severity == Severity.UNKNOWN

    def test_max_severity_mixed(self):
        d = DependencyFinding(
            "pkg", "1.0", "PyPI", "req.txt",
            cves=[
                CVEInfo("CVE-2021-1", Severity.LOW, 2.0, "low"),
                CVEInfo("CVE-2021-2", Severity.CRITICAL, 9.5, "crit"),
            ],
        )
        assert d.max_severity == Severity.CRITICAL

    def test_is_vulnerable_false(self):
        d = DependencyFinding("pkg", "1.0", "PyPI", "req.txt")
        assert d.is_vulnerable is False

    def test_is_vulnerable_true(self):
        d = DependencyFinding(
            "pkg", "1.0", "PyPI", "req.txt",
            cves=[CVEInfo("CVE-2021-1", Severity.HIGH, 7.5, "high")],
        )
        assert d.is_vulnerable is True


class TestScanResult:
    def _make_result(self) -> ScanResult:
        return ScanResult(target_path=Path("/tmp/project"))

    def test_total_vulnerabilities_empty(self):
        r = self._make_result()
        assert r.total_vulnerabilities == 0

    def test_total_vulnerabilities(self):
        r = self._make_result()
        r.dependency_findings = [
            DependencyFinding("a", "1.0", "PyPI", "req.txt", cves=[
                CVEInfo("CVE-1", Severity.HIGH, 7.5, "x"),
                CVEInfo("CVE-2", Severity.MEDIUM, 5.0, "y"),
            ]),
        ]
        assert r.total_vulnerabilities == 2

    def test_has_critical_false(self):
        r = self._make_result()
        r.dependency_findings = [
            DependencyFinding("a", "1.0", "PyPI", "req.txt", cves=[
                CVEInfo("CVE-1", Severity.HIGH, 7.5, "x"),
            ]),
        ]
        assert r.has_critical is False

    def test_has_critical_true_dep(self):
        r = self._make_result()
        r.dependency_findings = [
            DependencyFinding("a", "1.0", "PyPI", "req.txt", cves=[
                CVEInfo("CVE-1", Severity.CRITICAL, 9.8, "x"),
            ]),
        ]
        assert r.has_critical is True

    def test_exit_code_clean(self):
        r = self._make_result()
        assert r.exit_code == 0

    def test_exit_code_findings(self):
        r = self._make_result()
        r.dependency_findings = [
            DependencyFinding("a", "1.0", "PyPI", "req.txt", cves=[
                CVEInfo("CVE-1", Severity.HIGH, 7.5, "x"),
            ]),
        ]
        assert r.exit_code == 1

    def test_max_severity_empty(self):
        r = self._make_result()
        assert r.max_severity == Severity.UNKNOWN

    def test_max_severity_with_findings(self):
        r = self._make_result()
        r.model_findings = [
            ModelFileFinding(
                path=Path("model.pkl"),
                format="pickle",
                size_bytes=100,
                sha256="abc",
                risk_type=RiskType.MALICIOUS_PAYLOAD,
                severity=Severity.CRITICAL,
                description="bad",
                recommendation="fix",
            )
        ]
        assert r.max_severity == Severity.CRITICAL
