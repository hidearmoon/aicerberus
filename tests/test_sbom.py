"""Tests for the SBOM generator."""
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
from aicerberus.scanners.sbom import SBOMGenerator


def _make_dep_finding(
    pkg: str = "torch",
    ver: str = "1.9.0",
    cves: int = 1,
) -> DependencyFinding:
    return DependencyFinding(
        package=pkg,
        version=ver,
        ecosystem="PyPI",
        source_file="requirements.txt",
        cves=[
            CVEInfo(
                cve_id=f"CVE-2021-{i+1000}",
                severity=Severity.HIGH,
                cvss_score=7.5,
                summary="Test vulnerability",
                fixed_version="2.0.0",
                references=["https://example.com/advisory"],
            )
            for i in range(cves)
        ],
    )


def _make_model_finding() -> ModelFileFinding:
    return ModelFileFinding(
        path=Path("model.pkl"),
        format="pickle",
        size_bytes=1024,
        sha256="a" * 64,
        risk_type=RiskType.UNSAFE_SERIALIZATION,
        severity=Severity.HIGH,
        description="Unsafe pickle",
        recommendation="Use safetensors",
    )


def _make_license_finding() -> LicenseFinding:
    return LicenseFinding(
        package_or_model="some-model",
        license_id="cc-by-nc-4.0",
        restriction_type="NON_COMMERCIAL",
        severity=Severity.HIGH,
        description="Non-commercial license",
        source="local",
    )


class TestSBOMGenerator:
    def test_generate_empty_result(self):
        result = ScanResult(target_path=Path("/project"))
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert "serialNumber" in sbom
        assert sbom["serialNumber"].startswith("urn:uuid:")
        assert "metadata" in sbom
        assert "components" in sbom
        assert sbom["components"] == []

    def test_generate_with_dependencies(self):
        result = ScanResult(target_path=Path("/project"))
        result.dependency_findings = [_make_dep_finding("torch", "1.9.0", cves=2)]
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        assert len(sbom["components"]) == 1
        comp = sbom["components"][0]
        assert comp["name"] == "torch"
        assert comp["version"] == "1.9.0"
        assert "purl" in comp
        assert comp["purl"].startswith("pkg:pypi/torch")

    def test_generate_with_model_files(self):
        result = ScanResult(target_path=Path("/project"))
        result.model_findings = [_make_model_finding()]
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        assert len(sbom["components"]) == 1
        comp = sbom["components"][0]
        assert comp["type"] == "file"
        assert comp["name"] == "model.pkl"
        assert len(comp["hashes"]) == 1
        assert comp["hashes"][0]["alg"] == "SHA-256"

    def test_generate_vulnerabilities(self):
        result = ScanResult(target_path=Path("/project"))
        result.dependency_findings = [_make_dep_finding("torch", "1.9.0", cves=1)]
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        assert "vulnerabilities" in sbom
        assert len(sbom["vulnerabilities"]) == 1
        vuln = sbom["vulnerabilities"][0]
        assert vuln["id"].startswith("CVE-")
        assert vuln["ratings"][0]["severity"] == "high"
        assert "recommendation" in vuln

    def test_generate_no_vulnerabilities_key_when_empty(self):
        result = ScanResult(target_path=Path("/project"))
        result.model_findings = [_make_model_finding()]
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        # No CVEs → no vulnerabilities key
        assert "vulnerabilities" not in sbom

    def test_generate_metadata_contains_tool_info(self):
        result = ScanResult(target_path=Path("/project"))
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        tool = sbom["metadata"]["tools"][0]
        assert tool["name"] == "AICerberus"
        assert tool["vendor"] == "OpenForge AI"
        assert "version" in tool

    def test_generate_metadata_properties(self):
        result = ScanResult(target_path=Path("/project"))
        result.dependency_findings = [_make_dep_finding()]
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
        assert "cerberus:total_vulnerabilities" in props
        assert props["cerberus:total_vulnerabilities"] == "1"

    def test_generate_unique_serial_numbers(self):
        result = ScanResult(target_path=Path("/project"))
        gen = SBOMGenerator()
        sbom1 = gen.generate(result)
        sbom2 = gen.generate(result)
        assert sbom1["serialNumber"] != sbom2["serialNumber"]

    def test_generate_duplicate_deps_deduped(self):
        result = ScanResult(target_path=Path("/project"))
        result.dependency_findings = [
            _make_dep_finding("torch", "1.9.0"),
            _make_dep_finding("torch", "1.9.0"),  # duplicate
        ]
        gen = SBOMGenerator()
        sbom = gen.generate(result)
        # Should deduplicate by pkg+version
        torch_comps = [c for c in sbom["components"] if c["name"] == "torch"]
        assert len(torch_comps) == 1

    def test_model_component_with_opcodes(self):
        finding = _make_model_finding()
        finding.opcodes_found = ["GLOBAL:os system", "CALL:os system"]
        result = ScanResult(target_path=Path("/project"))
        result.model_findings = [finding]
        gen = SBOMGenerator()
        sbom = gen.generate(result)

        props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
        assert "cerberus:dangerous_opcodes" in props

    def test_purl_no_version(self):
        result = ScanResult(target_path=Path("/project"))
        finding = DependencyFinding("torch", "", "PyPI", "req.txt")
        result.dependency_findings = [finding]
        gen = SBOMGenerator()
        sbom = gen.generate(result)
        purl = sbom["components"][0]["purl"]
        assert purl == "pkg:pypi/torch"
