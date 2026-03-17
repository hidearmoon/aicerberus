# AICerberus 🐺

**AI supply chain security scanner** — one command to scan all AI/ML dependencies and model files for CVEs, pickle exploits, and license risks.

[![CI](https://github.com/hidearmoon/aicerberus/actions/workflows/ci.yml/badge.svg)](https://github.com/hidearmoon/aicerberus/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/aicerberus.svg)](https://pypi.org/project/aicerberus/)
[![Python](https://img.shields.io/pypi/pyversions/aicerberus.svg)](https://pypi.org/project/aicerberus/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/hidearmoon/aicerberus?style=social)](https://github.com/hidearmoon/aicerberus)

> 🌐 [中文文档](README_zh.md)

---

## What is AICerberus?

AICerberus is the **"Trivy for AI supply chains"** — a CLI tool that scans your project for security risks that existing SCA tools (Snyk, Trivy, Grype) **completely miss**:

| Risk Category | Traditional SCA | AICerberus |
|---|---|---|
| PyPI CVE scanning | ✅ | ✅ |
| Pickle deserialization attacks | ❌ | ✅ |
| PyTorch model file analysis | ❌ | ✅ |
| AI-specific licenses (OpenRAIL, Llama) | ❌ | ✅ |
| HuggingFace model card risks | ❌ | ✅ |
| CycloneDX AI SBOM generation | ❌ | ✅ |

---

## Quick Start

```bash
pip install aicerberus
cerberus scan .
```

That's it. AICerberus will scan your current directory and report all findings.

---

## Features

- **🔍 Dependency CVE Scanning** — Queries the [OSV database](https://osv.dev) for known vulnerabilities in 50+ AI/ML packages (PyTorch, TensorFlow, LangChain, Transformers, etc.)
- **☣️ Model File Analysis** — Safely disassembles pickle opcodes (without executing them) to detect malicious payloads like `os.system`, `subprocess.Popen`, `eval`/`exec`
- **📜 License Compliance** — Detects restrictive AI licenses: OpenRAIL variants, Llama 2/3, Gemma (commercial prohibitions), CC-BY-NC (non-commercial), AGPL/GPL (copyleft)
- **📦 AI SBOM Generation** — Outputs a [CycloneDX v1.5](https://cyclonedx.org) SBOM with all AI components, CVE cross-references, and model file hashes
- **🚀 Fast & Local** — No data leaves your machine (except OSV/HuggingFace API queries for vulnerability lookups)

---

## Installation

```bash
# PyPI (recommended)
pip install aicerberus

# From source
git clone https://github.com/hidearmoon/aicerberus
cd aicerberus
pip install -e .
```

---

## Usage

### Basic scan

```bash
cerberus scan /path/to/your/project
```

### Filter by severity

```bash
cerberus scan . --severity high
```

### Show remediation recommendations

```bash
cerberus scan . --fix
```

### Export as JSON

```bash
cerberus scan . --format json --output report.json
```

### Generate AI SBOM (CycloneDX)

```bash
cerberus scan . --format sbom --output sbom.json
```

### Skip specific scanners

```bash
cerberus scan . --skip-deps --skip-licenses   # model files only
```

### With HuggingFace token (for private model cards)

```bash
cerberus scan . --hf-token $HF_TOKEN
# or set env var: export HF_TOKEN=hf_...
```

---

## Output Example

```
╭─────────────────────────────────────────╮
│  AICerberus v0.1.0  AI Supply Chain...  │
╰─────────────────────────────────────────╯

  AI/ML Dependency Vulnerabilities
  ┌─────────────┬─────────┬──────────────┬──────────┬──────┬─────────────────────┐
  │ Package     │ Version │ CVE          │ Severity │ CVSS │ Summary             │
  ├─────────────┼─────────┼──────────────┼──────────┼──────┼─────────────────────┤
  │ torch       │ 1.9.0   │ CVE-2022-... │ 🔴 HIGH  │ 7.8  │ Arbitrary code ...  │
  └─────────────┴─────────┴──────────────┴──────────┴──────┴─────────────────────┘

  Model File Risks
  ┌─────────────┬────────┬──────────────────┬─────────────────────┐
  │ File        │ Format │ Severity         │ Risk                │
  ├─────────────┼────────┼──────────────────┼─────────────────────┤
  │ model.pkl   │ pickle │ 🔴 CRITICAL      │ MALICIOUS_PAYLOAD   │
  │             │        │ ⚠ Dangerous:     │ GLOBAL:os system    │
  └─────────────┴────────┴──────────────────┴─────────────────────┘

╭─ AICerberus v0.1.0 — Scan Summary ──────────╮
│  🔴 Overall severity: CRITICAL               │
│  CVEs found:           2                     │
│  Model file risks:     1                     │
│  License issues:       1                     │
╰──────────────────────────────────────────────╯
```

---

## Supported File Formats

| Format | Extension | Analysis |
|--------|-----------|---------|
| Pickle | `.pkl`, `.pickle` | Full opcode disassembly |
| PyTorch | `.pt`, `.pth`, `.bin` | ZIP extraction + pickle analysis |
| Joblib | `.joblib` | Unsafe serialization flag |
| SafeTensors | `.safetensors` | Safe format (low risk) |
| ONNX | `.onnx` | Safe format (low risk) |
| HDF5 | `.h5`, `.hdf5` | Structural risk flag |
| TensorFlow SavedModel | `.pb` | Structural risk flag |

---

## Supported Dependency Files

- `requirements.txt` / `requirements-*.txt`
- `pyproject.toml` (PEP 621 + Poetry)
- `Pipfile`
- `setup.py`, `setup.cfg`

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No risks found |
| `1` | One or more risks found |
| `2` | Scan error |

---

## CI Integration

```yaml
# .github/workflows/ai-security.yml
- name: AI Supply Chain Scan
  run: |
    pip install aicerberus
    cerberus scan . --severity high
```

---

## Why Not Just Use Trivy / Snyk?

Existing SCA tools were designed before the AI/ML era. They:

1. **Don't analyze model files** — a malicious `.pkl` file can execute arbitrary code on `pickle.load()`, but Trivy/Snyk don't scan these
2. **Don't understand AI licenses** — OpenRAIL, Llama 2 Community License, Gemma Terms all have use restrictions that standard SPDX checks miss
3. **Don't cover AI-specific CVEs well** — many ML framework CVEs are underreported in NVD/GHSA but present in OSV

AICerberus fills this gap.

---

## Contributing

```bash
git clone https://github.com/hidearmoon/aicerberus
cd aicerberus
pip install -e ".[dev]"
pytest tests/
```

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

*Built by [OpenForge AI](https://github.com/hidearmoon) — focused on AI security, observability, and toolchain.*
