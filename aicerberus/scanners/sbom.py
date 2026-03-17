"""CycloneDX AI SBOM generator."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from aicerberus import __version__
from aicerberus.models import ScanResult


def _component_ref(name: str) -> str:
    """Generate a stable BOM reference from a name."""
    slug = name.replace("/", "-").replace(" ", "-").replace(":", "-").lower()
    return f"pkg:{slug}"


class SBOMGenerator:
    """Generates CycloneDX v1.5 SBOM in JSON format."""

    SPEC_VERSION = "1.5"
    SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.5.schema.json"

    def generate(self, result: ScanResult) -> dict[str, Any]:
        """Build a CycloneDX SBOM dict from a ScanResult."""
        metadata = self._build_metadata(result)
        components = self._build_components(result)
        vulnerabilities = self._build_vulnerabilities(result)

        bom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": self.SPEC_VERSION,
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "$schema": self.SCHEMA_URL,
            "metadata": metadata,
            "components": components,
        }
        if vulnerabilities:
            bom["vulnerabilities"] = vulnerabilities

        return bom

    # ── Internal builders ─────────────────────────────────────────────────────

    def _build_metadata(self, result: ScanResult) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "OpenForge AI",
                    "name": "AICerberus",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": result.target_path.name or "project",
                "version": "unknown",
                "description": "Scanned AI/ML project",
            },
            "properties": [
                {"name": "cerberus:target_path", "value": str(result.target_path)},
                {
                    "name": "cerberus:total_vulnerabilities",
                    "value": str(result.total_vulnerabilities),
                },
                {"name": "cerberus:model_files_found", "value": str(len(result.model_findings))},
                {"name": "cerberus:license_findings", "value": str(len(result.license_findings))},
            ],
        }

    def _build_components(self, result: ScanResult) -> list[dict[str, Any]]:
        components: list[dict[str, Any]] = []

        # Dependency components
        seen_pkgs: set[str] = set()
        for finding in result.dependency_findings:
            key = f"{finding.package}@{finding.version}"
            if key in seen_pkgs:
                continue
            seen_pkgs.add(key)

            comp: dict[str, Any] = {
                "type": "library",
                "name": finding.package,
                "version": finding.version,
                "purl": f"pkg:pypi/{finding.package}@{finding.version}" if finding.version else f"pkg:pypi/{finding.package}",
                "bom-ref": _component_ref(f"pypi-{finding.package}-{finding.version}"),
                "properties": [
                    {"name": "cerberus:source_file", "value": finding.source_file},
                    {"name": "cerberus:ai_ml_package", "value": "true"},
                ],
            }
            components.append(comp)

        # Model file components
        for finding in result.model_findings:
            comp = {
                "type": "file",
                "name": finding.path.name,
                "version": "unknown",
                "bom-ref": _component_ref(f"model-{finding.path.name}-{finding.sha256[:8]}"),
                "hashes": [{"alg": "SHA-256", "content": finding.sha256}],
                "properties": [
                    {"name": "cerberus:model_format", "value": finding.format},
                    {"name": "cerberus:file_path", "value": str(finding.path)},
                    {
                        "name": "cerberus:risk_type",
                        "value": finding.risk_type.value,
                    },
                    {"name": "cerberus:severity", "value": finding.severity.value},
                ],
            }
            if finding.opcodes_found:
                comp["properties"].append(
                    {
                        "name": "cerberus:dangerous_opcodes",
                        "value": ", ".join(finding.opcodes_found[:5]),
                    }
                )
            components.append(comp)

        return components

    def _build_vulnerabilities(self, result: ScanResult) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []

        for finding in result.dependency_findings:
            bom_ref = _component_ref(f"pypi-{finding.package}-{finding.version}")
            for cve in finding.cves:
                vuln: dict[str, Any] = {
                    "id": cve.cve_id,
                    "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{cve.cve_id}"},
                    "ratings": [
                        {
                            "source": {"name": "OSV"},
                            "severity": cve.severity.value.lower(),
                        }
                    ],
                    "description": cve.summary,
                    "affects": [{"ref": bom_ref}],
                }
                if cve.cvss_score is not None:
                    vuln["ratings"][0]["score"] = cve.cvss_score
                if cve.fixed_version:
                    vuln["recommendation"] = f"Upgrade to version {cve.fixed_version} or later."
                if cve.references:
                    vuln["references"] = [{"id": url, "source": {"url": url}} for url in cve.references]
                vulns.append(vuln)

        return vulns
