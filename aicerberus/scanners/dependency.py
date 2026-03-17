"""Dependency scanner: parse AI/ML dependencies and query OSV for CVEs."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import httpx

from aicerberus.models import CVEInfo, DependencyFinding, Severity

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

# Known AI/ML packages to flag for deeper scanning
AI_ML_PACKAGES = frozenset(
    {
        # Deep learning frameworks
        "torch", "torchvision", "torchaudio", "tensorflow", "tensorflow-gpu",
        "tensorflow-cpu", "keras", "jax", "jaxlib", "paddle", "paddlepaddle",
        "mxnet", "theano", "caffe", "caffe2",
        # Model serving / inference
        "onnxruntime", "onnxruntime-gpu", "onnx", "triton", "tensorrt",
        "openvino", "tflite-runtime",
        # LLM / generative AI
        "transformers", "diffusers", "accelerate", "peft", "trl",
        "openai", "anthropic", "cohere", "google-generativeai", "mistralai",
        "langchain", "langchain-core", "langchain-community", "langchain-openai",
        "llama-index", "llama-cpp-python", "llamaindex",
        "autogen", "crewai", "litellm", "instructor",
        # Vector stores / embedding
        "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
        "faiss-cpu", "faiss-gpu", "sentence-transformers",
        # MLOps / experiment tracking
        "mlflow", "wandb", "neptune", "clearml", "bentoml",
        "ray", "ray[serve]", "seldon-core", "kfserving",
        # Data / feature
        "numpy", "pandas", "scikit-learn", "scipy", "xgboost", "lightgbm",
        "catboost", "statsmodels",
        # HuggingFace ecosystem
        "huggingface-hub", "datasets", "tokenizers", "timm", "evaluate",
        # Security-relevant
        "joblib", "dill", "cloudpickle",
    }
)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _parse_requirements_txt(content: str, source_file: str) -> list[tuple[str, str, str]]:
    """Parse requirements.txt into (package, version, source) tuples."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle extras: package[extra]==version
        match = re.match(
            r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?(?:==|>=|<=|~=|!=)([^\s,;]+)", line
        )
        if match:
            pkg = match.group(1).lower().replace("-", "-")
            ver = match.group(2).strip()
            results.append((pkg, ver, source_file))
        else:
            # No version pinned
            pkg_match = re.match(r"^([A-Za-z0-9_.-]+)", line)
            if pkg_match:
                results.append((pkg_match.group(1).lower(), "", source_file))
    return results


def _parse_pyproject_toml(content: bytes, source_file: str) -> list[tuple[str, str, str]]:
    """Parse pyproject.toml dependencies."""
    results = []
    try:
        data = tomllib.loads(content.decode())
    except Exception:
        return results

    # PEP 621 style
    deps = data.get("project", {}).get("dependencies", [])
    # Poetry style
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})

    for dep in deps:
        m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?(?:==|>=|<=|~=|!=)?([^\s,;]*)", dep)
        if m:
            pkg = m.group(1).lower()
            ver = re.sub(r"^[>=<~!]+", "", m.group(2).strip())
            results.append((pkg, ver, source_file))

    for pkg, ver_spec in poetry_deps.items():
        if pkg.lower() == "python":
            continue
        if isinstance(ver_spec, str):
            ver = ver_spec.lstrip("^~>=<!")
        elif isinstance(ver_spec, dict):
            ver = ver_spec.get("version", "").lstrip("^~>=<!")
        else:
            ver = ""
        results.append((pkg.lower(), ver, source_file))

    return results


def _parse_pipfile(content: str, source_file: str) -> list[tuple[str, str, str]]:
    """Parse Pipfile (TOML format)."""
    results = []
    try:
        data = tomllib.loads(content if isinstance(content, str) else content.decode())
    except Exception:
        return results
    for section in ("packages", "dev-packages"):
        for pkg, ver_spec in data.get(section, {}).items():
            if isinstance(ver_spec, str):
                ver = re.sub(r"^[\^~>=<! =*]+", "", ver_spec)
            else:
                ver = ""
            results.append((pkg.lower(), ver, source_file))
    return results


def _is_ai_ml_package(name: str) -> bool:
    """Check if a package name is AI/ML related."""
    name_lower = name.lower().replace("_", "-")
    if name_lower in AI_ML_PACKAGES:
        return True
    # Fuzzy match for common AI prefixes/suffixes
    ai_keywords = [
        "torch", "tensorflow", "tf-", "keras", "llm", "gpt", "bert",
        "langchain", "openai", "anthropic", "hugging", "transformers",
        "onnx", "triton", "diffuser", "embedding", "vector",
    ]
    return any(kw in name_lower for kw in ai_keywords)


def _parse_osv_response(
    pkg: str, ver: str, source_file: str, vulns: list[dict]
) -> DependencyFinding:
    """Convert OSV API response into a DependencyFinding."""
    cves: list[CVEInfo] = []
    for vuln in vulns:
        vuln_id = vuln.get("id", "")
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        # Extract CVSS
        cvss_score: float | None = None
        severity = Severity.UNKNOWN
        for sev_entry in vuln.get("severity", []):
            if sev_entry.get("type") == "CVSS_V3":
                score_str = sev_entry.get("score", "")
                try:
                    cvss_score = float(score_str.split("/")[0]) if "/" in score_str else float(score_str)
                except (ValueError, AttributeError):
                    pass
        # Fallback: database_specific.severity
        db_sev = vuln.get("database_specific", {}).get("severity", "")
        if db_sev:
            try:
                severity = Severity(db_sev.upper())
            except ValueError:
                pass
        if cvss_score is not None and severity == Severity.UNKNOWN:
            severity = Severity.from_cvss(cvss_score)

        # Fix version
        fixed_version: str | None = None
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed_version = ev["fixed"]
                        break

        summary = vuln.get("summary", vuln.get("details", "")[:200])
        refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

        cves.append(
            CVEInfo(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss_score,
                summary=summary,
                fixed_version=fixed_version,
                references=refs[:3],
            )
        )

    return DependencyFinding(
        package=pkg,
        version=ver,
        ecosystem="PyPI",
        source_file=source_file,
        cves=cves,
    )


class DependencyScanner:
    """Scans AI/ML dependencies for known CVEs via OSV API."""

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def find_dependency_files(self, path: Path) -> list[Path]:
        """Find all dependency manifest files under path."""
        patterns = [
            "requirements*.txt",
            "pyproject.toml",
            "Pipfile",
            "setup.py",
            "setup.cfg",
        ]
        found: list[Path] = []
        for pattern in patterns:
            found.extend(path.rglob(pattern))
        return sorted(set(found))

    def parse_dependencies(self, manifest: Path) -> list[tuple[str, str, str]]:
        """Parse a manifest file and return (pkg, version, source) tuples."""
        name = manifest.name.lower()
        try:
            if name.endswith(".txt"):
                return _parse_requirements_txt(manifest.read_text(encoding="utf-8"), str(manifest))
            elif name == "pyproject.toml":
                return _parse_pyproject_toml(manifest.read_bytes(), str(manifest))
            elif name == "pipfile":
                return _parse_pipfile(manifest.read_text(encoding="utf-8"), str(manifest))
        except Exception:
            pass
        return []

    def filter_ai_dependencies(
        self, deps: list[tuple[str, str, str]]
    ) -> list[tuple[str, str, str]]:
        """Keep only AI/ML relevant packages."""
        return [(p, v, s) for p, v, s in deps if _is_ai_ml_package(p)]

    def query_osv_batch(
        self, packages: list[tuple[str, str]]
    ) -> dict[tuple[str, str], list[dict]]:
        """Query OSV API in batch. Returns {(pkg,ver): [vuln,...]}."""
        if not packages:
            return {}

        queries = []
        for pkg, ver in packages:
            q: dict = {"package": {"name": pkg, "ecosystem": "PyPI"}}
            if ver:
                q["version"] = ver
            queries.append(q)

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(OSV_BATCH_URL, json={"queries": queries})
                resp.raise_for_status()
                results = resp.json().get("results", [])
        except Exception:
            return {}

        output: dict[tuple[str, str], list[dict]] = {}
        for i, res in enumerate(results):
            pkg, ver = packages[i]
            output[(pkg, ver)] = res.get("vulns", [])
        return output

    def scan(self, path: Path) -> list[DependencyFinding]:
        """Full dependency scan of a project directory."""
        manifests = self.find_dependency_files(path)
        all_deps: list[tuple[str, str, str]] = []
        for manifest in manifests:
            all_deps.extend(self.parse_dependencies(manifest))

        ai_deps = self.filter_ai_dependencies(all_deps)

        # De-duplicate by (pkg, ver) for OSV query
        seen: dict[tuple[str, str], str] = {}
        for pkg, ver, src in ai_deps:
            key = (pkg, ver)
            if key not in seen:
                seen[key] = src

        osv_results = self.query_osv_batch(list(seen.keys()))

        findings: list[DependencyFinding] = []
        for (pkg, ver), src in seen.items():
            vulns = osv_results.get((pkg, ver), [])
            if vulns:
                findings.append(_parse_osv_response(pkg, ver, src, vulns))

        return findings
