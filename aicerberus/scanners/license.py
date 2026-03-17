"""License compliance scanner for AI/ML packages and model files."""
from __future__ import annotations

import itertools
import json
import logging
import re
import sys
from pathlib import Path

import httpx

from aicerberus.models import LicenseFinding, Severity

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

logger = logging.getLogger(__name__)

# ─── License risk database ────────────────────────────────────────────────────
# Maps license SPDX ID (or common name) → (restriction_type, severity, description)
LICENSE_RISKS: dict[str, tuple[str, Severity, str]] = {
    # AI-specific restrictive licenses
    "openrail": (
        "AI_USE_RESTRICTION",
        Severity.HIGH,
        "OpenRAIL license restricts certain harmful uses of the model. "
        "Commercial use may be allowed but requires compliance with use restrictions.",
    ),
    "openrail++": (
        "AI_USE_RESTRICTION",
        Severity.HIGH,
        "OpenRAIL++ adds additional use restrictions on top of base OpenRAIL.",
    ),
    "bigscience-openrail-m": (
        "AI_USE_RESTRICTION",
        Severity.HIGH,
        "BigScience OpenRAIL-M restricts harmful AI use cases and requires attribution.",
    ),
    "creativeml-openrail-m": (
        "AI_USE_RESTRICTION",
        Severity.HIGH,
        "CreativeML OpenRAIL-M (used by Stable Diffusion) restricts commercial use and harmful content.",
    ),
    "llama2": (
        "COMMERCIAL_RESTRICTION",
        Severity.HIGH,
        "Meta Llama 2 license requires separate commercial license for products "
        "with >700M monthly active users and restricts competing model training.",
    ),
    "llama3": (
        "COMMERCIAL_RESTRICTION",
        Severity.MEDIUM,
        "Meta Llama 3 license permits commercial use but prohibits training competing LLMs "
        "and has acceptable use policy requirements.",
    ),
    "gemma": (
        "COMMERCIAL_RESTRICTION",
        Severity.MEDIUM,
        "Google Gemma Terms of Use restrict use in certain competitive AI applications.",
    ),
    # Creative Commons restrictive variants
    "cc-by-nc-4.0": (
        "NON_COMMERCIAL",
        Severity.HIGH,
        "CC BY-NC 4.0 prohibits commercial use. Do not use in commercial products.",
    ),
    "cc-by-nc-3.0": (
        "NON_COMMERCIAL",
        Severity.HIGH,
        "CC BY-NC 3.0 prohibits commercial use.",
    ),
    "cc-by-nc-sa-4.0": (
        "NON_COMMERCIAL",
        Severity.HIGH,
        "CC BY-NC-SA 4.0 prohibits commercial use and requires ShareAlike.",
    ),
    "cc-by-nc-nd-4.0": (
        "NON_COMMERCIAL",
        Severity.HIGH,
        "CC BY-NC-ND 4.0 prohibits commercial use, derivatives, and redistribution.",
    ),
    "cc-by-nd-4.0": (
        "NO_DERIVATIVES",
        Severity.MEDIUM,
        "CC BY-ND 4.0 prohibits creating derivative works.",
    ),
    # Copyleft licenses (relevant for AI tooling)
    "agpl-3.0": (
        "STRONG_COPYLEFT",
        Severity.HIGH,
        "AGPL-3.0 requires publishing source code of network-facing applications. "
        "This is highly restrictive for SaaS/API products.",
    ),
    "gpl-3.0": (
        "STRONG_COPYLEFT",
        Severity.HIGH,
        "GPL-3.0 requires derivative works to be GPL-licensed. "
        "Incompatible with proprietary products.",
    ),
    "gpl-2.0": (
        "STRONG_COPYLEFT",
        Severity.HIGH,
        "GPL-2.0 is a copyleft license that propagates to derivative works.",
    ),
    "lgpl-3.0": (
        "WEAK_COPYLEFT",
        Severity.MEDIUM,
        "LGPL-3.0 allows linking in proprietary software but requires modifications "
        "to the LGPL library itself to remain open source.",
    ),
    # Research-only licenses
    "research-only": (
        "RESEARCH_ONLY",
        Severity.CRITICAL,
        "This model is licensed for research use only and cannot be used commercially.",
    ),
    "non-commercial": (
        "NON_COMMERCIAL",
        Severity.HIGH,
        "Non-commercial license: use in commercial products is prohibited.",
    ),
    # Proprietary
    "proprietary": (
        "PROPRIETARY",
        Severity.MEDIUM,
        "Proprietary license — review terms carefully before use.",
    ),
    "other": (
        "UNKNOWN_LICENSE",
        Severity.MEDIUM,
        "Non-standard or unrecognized license — manual review required.",
    ),
}

# Permissive licenses (safe to use, no finding generated)
PERMISSIVE_LICENSES: frozenset[str] = frozenset(
    {
        "mit", "apache-2.0", "apache-1.1", "bsd-2-clause", "bsd-3-clause",
        "isc", "cc0-1.0", "cc-by-4.0", "cc-by-sa-4.0", "unlicense",
        "wtfpl", "mpl-2.0", "epl-2.0", "cddl-1.0",
        "llama3.1", "llama3.2",  # treated as permissive (community license)
    }
)

HF_API_BASE = "https://huggingface.co/api/models"


def _normalise_license(raw: str) -> str:
    """Lowercase and strip whitespace/punctuation from a license string."""
    return raw.lower().strip().replace(" ", "-").replace("_", "-")


def _lookup_license_risk(
    license_id: str,
) -> tuple[str, Severity, str] | None:
    """Return (restriction_type, severity, description) or None if permissive/safe."""
    norm = _normalise_license(license_id)
    if norm in PERMISSIVE_LICENSES:
        return None
    # Direct match
    if norm in LICENSE_RISKS:
        return LICENSE_RISKS[norm]
    # Prefix match (e.g. "openrail-m" → "openrail")
    for key, val in LICENSE_RISKS.items():
        if norm.startswith(key) or key in norm:
            return val
    # Unknown license is medium risk
    return ("UNKNOWN_LICENSE", Severity.MEDIUM, f"Unrecognised license '{license_id}' — review before use.")


class LicenseScanner:
    """Checks AI/ML package and model licenses for compliance issues."""

    def __init__(self, hf_api_token: str | None = None, timeout: float = 15.0) -> None:
        self._hf_token = hf_api_token
        self._timeout = timeout

    # ── HuggingFace model card lookup ─────────────────────────────────────────

    def _hf_headers(self) -> dict[str, str]:
        if self._hf_token:
            return {"Authorization": f"Bearer {self._hf_token}"}
        return {}

    def check_hf_model(self, model_id: str) -> LicenseFinding | None:
        """Query HuggingFace API for model license info."""
        url = f"{HF_API_BASE}/{model_id}"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(url, headers=self._hf_headers())
                if resp.status_code != 200:
                    return None
                data = resp.json()
        except Exception as exc:
            logger.warning("HuggingFace API request failed for %s: %s", model_id, exc)
            return None

        license_id: str = ""
        # cardData.license takes priority
        card_data = data.get("cardData") or {}
        if isinstance(card_data, dict):
            license_id = card_data.get("license", "")
        if not license_id:
            license_id = data.get("license", "")
        if not license_id:
            tags = data.get("tags", [])
            for tag in tags:
                if tag.startswith("license:"):
                    license_id = tag.split(":", 1)[1]
                    break

        if not license_id:
            return None

        risk = _lookup_license_risk(license_id)
        if risk is None:
            return None  # Permissive, no finding

        restriction_type, severity, description = risk
        return LicenseFinding(
            package_or_model=model_id,
            license_id=license_id,
            restriction_type=restriction_type,
            severity=severity,
            description=description,
            source="huggingface",
        )

    # ── Local config.json / model card ───────────────────────────────────────

    def check_local_model_card(self, config_path: Path) -> LicenseFinding | None:
        """Check a local HuggingFace config.json or README for license info."""
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to read model card %s: %s", config_path, exc)
            return None

        license_id = data.get("license", "")
        if not license_id:
            return None

        risk = _lookup_license_risk(license_id)
        if risk is None:
            return None

        restriction_type, severity, description = risk
        return LicenseFinding(
            package_or_model=str(config_path.parent),
            license_id=license_id,
            restriction_type=restriction_type,
            severity=severity,
            description=description,
            source="local",
        )

    # ── pyproject.toml / requirements check ──────────────────────────────────

    def _find_package_licenses_pyproject(self, manifest: Path) -> list[LicenseFinding]:
        """Extract license metadata from pyproject.toml."""
        findings: list[LicenseFinding] = []
        try:
            data = tomllib.loads(manifest.read_bytes().decode())
        except Exception as exc:
            logger.warning("Failed to parse pyproject.toml %s: %s", manifest, exc)
            return findings

        project = data.get("project", {})
        license_field = project.get("license", {})
        if isinstance(license_field, dict):
            license_text = license_field.get("text", "")
        elif isinstance(license_field, str):
            license_text = license_field
        else:
            license_text = ""

        if license_text:
            risk = _lookup_license_risk(license_text)
            if risk:
                restriction_type, severity, description = risk
                pkg_name = project.get("name", str(manifest))
                findings.append(
                    LicenseFinding(
                        package_or_model=pkg_name,
                        license_id=license_text,
                        restriction_type=restriction_type,
                        severity=severity,
                        description=description,
                        source="pypi",
                    )
                )
        return findings

    # ── HuggingFace model ID discovery ───────────────────────────────────────

    # HF model ID: "owner/model-name" or bare "model-name"
    # Valid chars: letters, digits, hyphens, underscores, dots (max 96 chars per segment)
    _HF_ID_RE = r'[A-Za-z0-9][\w\-\.]{0,95}(?:/[\w\-\.]{1,96})?'

    # Patterns that appear in Python source files
    _PY_PATTERNS: list[str] = [
        r'from_pretrained\s*\(\s*[\'"](' + _HF_ID_RE + r')[\'"]\s*[,\)]',
        r'pipeline\s*\([^)]*\bmodel\s*=\s*[\'"](' + _HF_ID_RE + r')[\'"]',
        r'\bmodel_id\s*=\s*[\'"](' + _HF_ID_RE + r')[\'"]',
        r'\bmodel_name\s*=\s*[\'"](' + _HF_ID_RE + r')[\'"]',
        r'\bbase_model\s*=\s*[\'"](' + _HF_ID_RE + r')[\'"]',
    ]

    # Patterns that appear in YAML / JSON config files
    _YAML_PATTERN = r'(?:model_id|model_name|base_model|model)\s*:\s*[\'"]?(' + _HF_ID_RE + r')[\'"]?'
    _JSON_PATTERN = r'"(?:model_id|model_name|base_model)"\s*:\s*"(' + _HF_ID_RE + r')"'

    _SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", ".tox", ".venv", "venv"})

    def _should_skip(self, file_path: Path) -> bool:
        return bool(self._SKIP_DIRS.intersection(file_path.parts))

    def _discover_hf_model_ids(self, path: Path) -> set[str]:
        """Discover HuggingFace model IDs referenced anywhere in the project tree.

        Scans Python source files (from_pretrained, pipeline, model_id=...),
        YAML/YML configs, and JSON files for model references and returns
        candidate model IDs suitable for HuggingFace API lookup.
        """
        model_ids: set[str] = set()

        py_regexes = [re.compile(p) for p in self._PY_PATTERNS]
        yaml_regex = re.compile(self._YAML_PATTERN, re.IGNORECASE)
        json_regex = re.compile(self._JSON_PATTERN)

        # Python source files
        for py_file in path.rglob("*.py"):
            if self._should_skip(py_file):
                continue
            try:
                text = py_file.read_text(encoding="utf-8", errors="ignore")
                for rx in py_regexes:
                    for m in rx.finditer(text):
                        model_ids.add(m.group(1))
            except OSError:
                continue

        # YAML / YML config files
        for yaml_file in itertools.chain(path.rglob("*.yaml"), path.rglob("*.yml")):
            if self._should_skip(yaml_file):
                continue
            try:
                text = yaml_file.read_text(encoding="utf-8", errors="ignore")
                for m in yaml_regex.finditer(text):
                    model_ids.add(m.group(1))
            except OSError:
                continue

        # JSON files (non-config.json — config.json is handled by check_local_model_card)
        for json_file in path.rglob("*.json"):
            if json_file.name == "config.json" or self._should_skip(json_file):
                continue
            try:
                text = json_file.read_text(encoding="utf-8", errors="ignore")
                for m in json_regex.finditer(text):
                    model_ids.add(m.group(1))
            except OSError:
                continue

        # Filter out obvious non-HF values (local paths, URLs, empty strings)
        return {
            mid for mid in model_ids
            if mid and not mid.startswith(("/", ".", "http://", "https://"))
        }

    # ── Main scan entrypoint ──────────────────────────────────────────────────

    def scan(self, path: Path) -> list[LicenseFinding]:
        """Scan all license-bearing artifacts under path."""
        findings: list[LicenseFinding] = []

        # 1. Local HuggingFace config.json files
        for config in path.rglob("config.json"):
            if any(p in config.parts for p in (".git", "__pycache__", "node_modules")):
                continue
            finding = self.check_local_model_card(config)
            if finding:
                findings.append(finding)

        # 2. pyproject.toml project license
        for pyproject in path.rglob("pyproject.toml"):
            findings.extend(self._find_package_licenses_pyproject(pyproject))

        # 3. HuggingFace API lookup for auto-discovered model IDs
        #    Deduplicates against model IDs already found via local config.json.
        already_found: set[str] = {
            f.package_or_model for f in findings if f.source in ("huggingface", "local")
        }
        for model_id in sorted(self._discover_hf_model_ids(path)):
            if model_id in already_found:
                continue
            finding = self.check_hf_model(model_id)
            if finding:
                findings.append(finding)
                already_found.add(model_id)

        return findings
