"""Core data models for AICerberus."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.UNKNOWN

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}[self.value]


class RiskType(str, Enum):
    CVE = "CVE"
    UNSAFE_SERIALIZATION = "UNSAFE_SERIALIZATION"
    MALICIOUS_PAYLOAD = "MALICIOUS_PAYLOAD"
    LICENSE_RESTRICTION = "LICENSE_RESTRICTION"
    INTEGRITY = "INTEGRITY"


@dataclass
class CVEInfo:
    """Details about a specific CVE."""
    cve_id: str
    severity: Severity
    cvss_score: float | None
    summary: str
    fixed_version: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class DependencyFinding:
    """A finding for an AI/ML dependency package."""
    package: str
    version: str
    ecosystem: str
    source_file: str
    cves: list[CVEInfo] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.cves:
            return Severity.UNKNOWN
        return max(self.cves, key=lambda c: c.severity.rank).severity

    @property
    def is_vulnerable(self) -> bool:
        return len(self.cves) > 0


@dataclass
class ModelFileFinding:
    """A finding for a model file."""
    path: Path
    format: str
    size_bytes: int
    sha256: str
    risk_type: RiskType
    severity: Severity
    description: str
    recommendation: str
    opcodes_found: list[str] = field(default_factory=list)


@dataclass
class LicenseFinding:
    """A finding for license compliance."""
    package_or_model: str
    license_id: str
    restriction_type: str
    severity: Severity
    description: str
    source: str  # "pypi", "huggingface", "local"


@dataclass
class ScanResult:
    """Aggregated result of a full scan."""
    target_path: Path
    dependency_findings: list[DependencyFinding] = field(default_factory=list)
    model_findings: list[ModelFileFinding] = field(default_factory=list)
    license_findings: list[LicenseFinding] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(d.cves) for d in self.dependency_findings)

    @property
    def has_critical(self) -> bool:
        for d in self.dependency_findings:
            if d.max_severity == Severity.CRITICAL:
                return True
        for m in self.model_findings:
            if m.severity == Severity.CRITICAL:
                return True
        return False

    @property
    def max_severity(self) -> Severity:
        all_severities: list[Severity] = []
        for d in self.dependency_findings:
            all_severities.append(d.max_severity)
        for m in self.model_findings:
            all_severities.append(m.severity)
        for lf in self.license_findings:
            all_severities.append(lf.severity)
        if not all_severities:
            return Severity.UNKNOWN
        return max(all_severities, key=lambda s: s.rank)

    @property
    def exit_code(self) -> int:
        """0 = clean, 1 = findings present."""
        if self.dependency_findings or self.model_findings or self.license_findings:
            return 1
        return 0
