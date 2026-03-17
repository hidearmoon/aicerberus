# AICerberus 🐺

**AI 供应链安全扫描器** —— 一条命令扫描项目中所有 AI/ML 依赖和模型文件，检测 CVE 漏洞、pickle 投毒、许可证风险，并输出 AI SBOM。

[![CI](https://github.com/hidearmoon/aicerberus/actions/workflows/ci.yml/badge.svg)](https://github.com/hidearmoon/aicerberus/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/aicerberus.svg)](https://pypi.org/project/aicerberus/)
[![Python](https://img.shields.io/pypi/pyversions/aicerberus.svg)](https://pypi.org/project/aicerberus/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/hidearmoon/aicerberus?style=social)](https://github.com/hidearmoon/aicerberus)

> 🌐 [English Documentation](README.md)

---

## AICerberus 是什么？

AICerberus 是 **"AI 供应链的 Trivy"** —— 一个 CLI 工具，专门扫描现有 SCA 工具（Snyk、Trivy、Grype）**完全不覆盖**的 AI 安全风险：

| 风险类型 | 传统 SCA 工具 | AICerberus |
|---|---|---|
| PyPI CVE 扫描 | ✅ | ✅ |
| Pickle 反序列化攻击 | ❌ | ✅ |
| PyTorch 模型文件分析 | ❌ | ✅ |
| AI 特有许可证（OpenRAIL、Llama） | ❌ | ✅ |
| HuggingFace 模型卡风险 | ❌ | ✅ |
| CycloneDX AI SBOM 生成 | ❌ | ✅ |

---

## 30 秒快速开始

```bash
pip install aicerberus
cerberus scan .
```

就这么简单。AICerberus 会扫描当前目录并输出所有发现的风险。

---

## 核心功能

- **🔍 依赖 CVE 扫描** — 查询 [OSV 数据库](https://osv.dev) 检测 50+ 个 AI/ML 包的已知漏洞（PyTorch、TensorFlow、LangChain、Transformers 等）
- **☣️ 模型文件分析** — 安全反汇编 pickle 字节码（不执行代码），检测恶意载荷如 `os.system`、`subprocess.Popen`、`eval`/`exec`
- **📜 许可证合规** — 检测限制性 AI 许可证：OpenRAIL 变体、Llama 2/3、Gemma（商业限制）、CC-BY-NC（非商业）、AGPL/GPL（Copyleft 传染）
- **📦 AI SBOM 生成** — 输出 [CycloneDX v1.5](https://cyclonedx.org) 格式的 SBOM，包含所有 AI 组件、CVE 交叉引用和模型文件哈希
- **🚀 快速且本地化** — 除 OSV/HuggingFace API 查询外，数据不离开本机

---

## 安装

```bash
# PyPI（推荐）
pip install aicerberus

# 从源码安装
git clone https://github.com/hidearmoon/aicerberus
cd aicerberus
pip install -e .
```

---

## 使用方法

### 基本扫描

```bash
cerberus scan /path/to/your/project
```

### 按严重程度过滤

```bash
cerberus scan . --severity high
```

### 显示修复建议

```bash
cerberus scan . --fix
```

### 导出 JSON 报告

```bash
cerberus scan . --format json --output report.json
```

### 生成 AI SBOM（CycloneDX 格式）

```bash
cerberus scan . --format sbom --output sbom.json
```

### 跳过特定扫描器

```bash
cerberus scan . --skip-deps --skip-licenses   # 仅扫描模型文件
```

### 使用 HuggingFace Token（访问私有模型卡）

```bash
cerberus scan . --hf-token $HF_TOKEN
# 或设置环境变量：export HF_TOKEN=hf_...
```

### 离线 / 内网环境

```bash
cerberus scan . --no-hf-api   # 跳过所有 HuggingFace API 请求
```

---

## 输出示例

```
╭─────────────────────────────────────────╮
│  AICerberus v0.1.0  AI 供应链安全扫描  │
╰─────────────────────────────────────────╯

  AI/ML 依赖漏洞
  ┌─────────────┬─────────┬──────────────┬──────────┬──────┬─────────────────────┐
  │ 包名        │ 版本    │ CVE          │ 严重程度 │ CVSS │ 摘要                │
  ├─────────────┼─────────┼──────────────┼──────────┼──────┼─────────────────────┤
  │ torch       │ 1.9.0   │ CVE-2022-... │ 🔴 HIGH  │ 7.8  │ 任意代码执行 ...    │
  └─────────────┴─────────┴──────────────┴──────────┴──────┴─────────────────────┘

  模型文件风险
  ┌─────────────┬────────┬──────────────────┬─────────────────────┐
  │ 文件        │ 格式   │ 严重程度         │ 风险类型            │
  ├─────────────┼────────┼──────────────────┼─────────────────────┤
  │ model.pkl   │ pickle │ 🔴 CRITICAL      │ MALICIOUS_PAYLOAD   │
  │             │        │ ⚠ 危险操码:      │ GLOBAL:os system    │
  └─────────────┴────────┴──────────────────┴─────────────────────┘

╭─ AICerberus v0.1.0 — 扫描摘要 ──────────╮
│  🔴 最高严重程度：CRITICAL               │
│  发现 CVE：            2                 │
│  模型文件风险：        1                 │
│  许可证问题：          1                 │
╰──────────────────────────────────────────╯
```

---

## 支持的模型文件格式

| 格式 | 扩展名 | 分析方式 |
|------|--------|---------|
| Pickle | `.pkl`, `.pickle` | 完整字节码反汇编 |
| PyTorch | `.pt`, `.pth`, `.bin` | ZIP 解包 + pickle 分析 |
| Joblib | `.joblib` | 不安全序列化标记 |
| SafeTensors | `.safetensors` | 安全格式（低风险）|
| ONNX | `.onnx` | 安全格式（低风险）|
| HDF5 | `.h5`, `.hdf5` | 结构性风险标记 |
| TensorFlow SavedModel | `.pb` | 结构性风险标记 |

---

## 支持的依赖文件

- `requirements.txt` / `requirements-*.txt`
- `pyproject.toml`（PEP 621 + Poetry）
- `Pipfile`
- `setup.py`、`setup.cfg`

---

## 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 未发现风险 |
| `1` | 发现一个或多个风险 |
| `2` | 扫描出错 |

---

## CI 集成

```yaml
# .github/workflows/ai-security.yml
- name: AI 供应链安全扫描
  run: |
    pip install aicerberus
    cerberus scan . --severity high
```

---

## 为什么不用 Trivy / Snyk？

现有 SCA 工具是在 AI/ML 时代之前设计的，存在以下盲区：

1. **不分析模型文件** —— 恶意 `.pkl` 文件在 `pickle.load()` 时可执行任意代码，Trivy/Snyk 无法检测
2. **不理解 AI 许可证** —— OpenRAIL、Llama 2 社区许可证、Gemma 条款都有使用限制，标准 SPDX 检查无法覆盖
3. **AI 特有 CVE 覆盖不足** —— 许多 ML 框架的 CVE 在 NVD/GHSA 中报告不完整，但在 OSV 中存在

AICerberus 填补了这个空白。

---

## 参与贡献

```bash
git clone https://github.com/hidearmoon/aicerberus
cd aicerberus
pip install -e ".[dev]"
pytest tests/
```

欢迎 PR！详情参见 [CONTRIBUTING.md](CONTRIBUTING.md)。

---

## 许可证

Apache 2.0 — 详见 [LICENSE](LICENSE)

---

*由 [OpenForge AI](https://github.com/hidearmoon) 构建 —— 专注 AI 安全、可观测性与工具链。*
