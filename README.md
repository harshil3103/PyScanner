
<div align="center">
  <h1>🛡️ PyScanner</h1>
  <p><strong>The AI-Powered Security Review Assistant for Python</strong></p>
  
  [![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
  [![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
  [![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](docker/)

  <br>

  **PyScanner** is a hybrid Static Application Security Testing (SAST) tool that acts like a senior security engineer sitting right next to you. It combines the speed of traditional rule-based scanning with the reasoning power of local and cloud Large Language Models (LLMs) to eliminate false positives and provide actionable, context-aware remediation.

</div>

---

## 📑 Table of Contents

- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🚀 Quick Start](#-quick-start)
- [🔧 Installation](#-installation)
- [💻 Usage](#-usage)
- [🐳 Docker](#-docker)
- [🤖 LLM Providers](#-llm-providers)
- [🛡️ Vulnerabilities Covered](#️-vulnerabilities-covered)
- [📁 Project Structure](#-project-structure)
- [🧪 Testing](#-testing)
- [🤝 Contributing](#-contributing)
- [📝 License](#-license)

---

## ✨ Features

| Feature | Description |
|---|---|
| ⚡ **Blazing Fast Rule Engine** | Scans your codebase in milliseconds using an AST-based analyzer across 12 vulnerability rule modules |
| 🧠 **Multi-Tier AI Analysis** | 3-tier pipeline: deterministic SAST → local SLM triage → cloud/local LLM deep analysis |
| 🎯 **Zero False Positives Goal** | Local SLMs (via Ollama) automatically suppress high-confidence false positives before they reach your report |
| 🛠️ **Auto-Remediation (`--fix`)** | Provides exact safe replacement code with OWASP-aligned explanations for every finding |
| 🔌 **Multi-Provider LLM Support** | Pluggable architecture: **Ollama** (local/free), **Gemini**, **OpenAI**, **Anthropic** (cloud) |
| 📊 **Rich Export Formats** | HTML dashboards, Markdown, CSV, JSON, and SARIF for CI/CD integration |
| 💯 **Security Scoring** | Calculates a 0–100 security grade based on severity, confidence, and blast radius |
| 📈 **History & Trends** | SQLite-backed scan history tracks your security posture over time |
| 🔄 **Shadow Rule Learning** | Automatically learns from LLM-confirmed findings to propose new detection rules |
| 🔐 **Secure Key Management** | API keys are encrypted via Fernet and stored outside the project directory |

---

## 🏗️ Architecture

PyScanner implements a cascading **3-Tier AI Pipeline** that balances speed, cost, and accuracy:

```
┌──────────────────────────────────────────────────────────────────────┐
│                        SOURCE CODE INPUT                            │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│  📥 INGESTION & SLICING                                             │
│  • Discover .py files recursively                                   │
│  • Parse ASTs (stdlib ast + libcst)                                 │
│  • Build minimal context-rich "code slices" per finding             │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│  ⚡ TIER 1: SAST ENGINE (Deterministic)                             │
│  • 12 rule modules × pattern matching on AST                        │
│  • Instant detection of injection, XSS, SQLi, secrets, etc.        │
│  • Produces RawFindings with CWE IDs and evidence                   │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│  🤖 TIER 2: SLM TRIAGE (Local Ollama)                               │
│  • Routes each finding + code slice to local llama3.2               │
│  • Verdict: true_positive / false_positive / uncertain              │
│  • High-confidence false positives (≥85%) → SUPPRESSED              │
└──────────────────┬───────────────────────────────────────────────────┘
                   │ (only "uncertain" findings)
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│  🧠 TIER 3: LLM DEEP ANALYSIS (Cloud or Local)                      │
│  • Sends uncertain findings to Gemini / GPT-4o / Claude / Ollama    │
│  • Returns structured JSON: severity, CWE, explanation, fix code    │
│  • Exponential backoff retry for rate-limited APIs                   │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│  📊 ENRICHMENT & REPORTING                                          │
│  • OWASP categorization, severity labeling, remediation catalog     │
│  • Security score calculation (0–100)                               │
│  • Export: HTML | Markdown | CSV | JSON | SARIF                     │
│  • Persist to SQLite for history & feedback tracking                │
└──────────────────────────────────────────────────────────────────────┘
```

### Why 3 Tiers?

| Tier | Speed | Cost | Accuracy | Purpose |
|---|---|---|---|---|
| **SAST Rules** | ~ms | Free | High recall, moderate precision | Catch everything fast |
| **Local SLM** | ~2s/finding | Free | Good precision | Filter out obvious false positives |
| **Cloud LLM** | ~3s/finding | ~$0.004/call | Excellent precision | Deep analysis of ambiguous cases |

---

## 🚀 Quick Start

```bash
# Clone & install
git clone https://github.com/harshil3103/PyScanner.git
cd PyScanner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Run your first scan (offline, no AI)
pyscanner scan ./my_project

# Run with local AI (requires Ollama)
pyscanner scan ./my_project --llm --provider ollama --fix --format html
open pyscanner-report.html
```

---

## 🔧 Installation

### Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| **Python** | 3.10+ | Core runtime |
| **Ollama** *(optional)* | Latest | Local AI triage & analysis |

### Step-by-Step

1. **Clone the repository:**
   ```bash
   git clone https://github.com/harshil3103/PyScanner.git
   cd PyScanner
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate        # macOS/Linux
   # .venv\Scripts\activate         # Windows
   ```

3. **Install PyScanner:**
   ```bash
   pip install -e .          # Standard install
   pip install -e ".[dev]"   # With test/lint tools (pytest, ruff)
   pip install -e ".[all]"   # Everything including MCP server
   ```

4. **Set up Ollama (recommended):**
   ```bash
   # Install Ollama from https://ollama.com
   ollama pull llama3.2
   ollama serve              # Starts the local API on port 11434
   ```

5. **Configure cloud API keys (optional):**

   PyScanner uses an encrypted secret store at `~/.config/pyscanner/secrets.json`. Keys never touch your project directory:
   ```bash
   # Or set via environment variables
   export GEMINI_API_KEY="your-key-here"
   export OPENAI_API_KEY="your-key-here"
   export ANTHROPIC_API_KEY="your-key-here"
   ```

---

## 💻 Usage

### CLI Commands

#### `pyscanner scan` — Run a security scan

```bash
pyscanner scan <TARGET> [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `<TARGET>` | *(required)* | File or directory to scan |
| `--format` | `text` | Output format: `text`, `html`, `markdown`, `csv`, `json`, `sarif` |
| `--llm` | `false` | Enable cloud/local LLM for deep analysis |
| `--provider` | `None` | LLM provider: `ollama`, `gemini`, `openai`, `anthropic` |
| `--fix` | `false` | Generate auto-remediation code (requires `--llm`) |
| `--db` | `None` | SQLite path for persisting scan history |
| `--offline` | `true` | Disable all network calls (auto-disabled with `--llm`) |
| `--no-slm` | `false` | Skip local SLM triage |

**Examples:**

```bash
# Basic offline scan with terminal dashboard
pyscanner scan ./src

# Full AI scan with Ollama (free, no internet needed)
pyscanner scan ./src --llm --provider ollama --fix --format html --db scans.db

# Cloud AI scan with Gemini
pyscanner scan ./src --llm --provider gemini --fix --format html --db scans.db

# Export SARIF for GitHub Code Scanning
pyscanner scan ./src --format sarif

# Export CSV for spreadsheet analysis
pyscanner scan ./src --format csv
```

#### `pyscanner history` — View scan trends

```bash
pyscanner history --db scans.db --limit 10
```

Displays a rich table of past scans with scores, dates, and finding counts.

#### `pyscanner feedback` — Mark false positives

```bash
pyscanner feedback <SCAN_ID> <FILE_PATH> <LINE> --note "This is expected" --db scans.db
```

Marks a specific finding as a false positive for future reference.

#### `pyscanner mcp` — Start MCP server

```bash
pip install -e ".[mcp]"
pyscanner mcp
```

Runs a [Model Context Protocol](https://modelcontextprotocol.io/) stdio server for IDE integration.

---

## 🐳 Docker

PyScanner ships with Docker support for containerized scanning:

```bash
# Build and run a scan
cd PyScanner
docker compose -f docker/compose.yml run scanner scan /work/src --format json

# With local Ollama sidecar
docker compose -f docker/compose.yml --profile local-llm up
```

**Dockerfile** builds a lightweight `python:3.11-slim` image with PyScanner pre-installed.

---

## 🤖 LLM Providers

PyScanner supports a pluggable provider architecture. All providers implement the same `LlmProvider` protocol:

| Provider | Type | Cost | Rate Limits | Best For |
|---|---|---|---|---|
| **Ollama** | Local | Free | None | Development, offline use, unlimited scans |
| **Gemini** | Cloud | Free tier / Paid | 15 RPM (free) | Fast cloud analysis with auto-retry |
| **OpenAI** | Cloud | Paid | Generous | Highest accuracy (GPT-4o) |
| **Anthropic** | Cloud | Paid | Generous | Detailed explanations (Claude 3.5) |

### Adding a New Provider

1. Create `src/pyscanner/llm/providers/your_provider.py`
2. Implement the `complete_json(system, user, *, schema_hint)` method
3. Register it in `src/pyscanner/llm/providers/base.py`
4. Add the provider name to the `Literal` type in `src/pyscanner/config/settings.py`

---

## 🛡️ Vulnerabilities Covered

PyScanner detects **14+ vulnerability categories** across 12 rule modules:

| Category | Rule Module | CWE | Examples |
|---|---|---|---|
| **Code Injection** | `injection.py` | CWE-94 | `eval()`, `exec()` |
| **Command Injection** | `subprocess_rules.py` | CWE-78 | `os.system()`, `shell=True` |
| **SQL Injection** | `sql_injection.py` | CWE-89 | String-formatted queries |
| **XSS** | `xss.py` | CWE-79 | `Markup()`, `render_template_string()`, `mark_safe()` |
| **Path Traversal** | `path_traversal.py` | CWE-22 | Unsanitized `open()`, `os.path.join()` |
| **Insecure Deserialization** | `deserialization.py` | CWE-502 | `pickle.loads()`, `yaml.load()` |
| **Hardcoded Secrets** | `secrets.py` | CWE-798 | API keys, passwords, private keys |
| **Weak Cryptography** | `crypto.py` | CWE-327 | MD5/SHA1 hashing, `random` for security |
| **Disabled SSL** | `ssl_tls.py` | CWE-295 | `verify=False` |
| **File Upload** | `file_upload.py` | CWE-434 | Unrestricted uploads, missing validation |
| **Misconfiguration** | `misconfiguration.py` | CWE-16 | `DEBUG=True`, wildcard CORS, weak `SECRET_KEY` |
| **Supply Chain** | `supply_chain.py` | CWE-1357 | Typosquatting, known malicious packages |

---

## 📁 Project Structure

```
PyScanner/
├── src/pyscanner/
│   ├── cli/                    # Typer CLI commands (scan, history, feedback, mcp)
│   ├── config/                 # ScanConfig & Settings (Pydantic models)
│   ├── core/                   # Pipeline orchestrator, scoring, remediation catalog
│   ├── ingestion/              # File discovery, AST parsing, manifest extraction
│   ├── learning/               # Shadow rule generation & promotion policy
│   ├── llm/
│   │   ├── providers/          # Pluggable LLM backends
│   │   │   ├── ollama_provider.py
│   │   │   ├── gemini_provider.py
│   │   │   ├── openai_provider.py
│   │   │   ├── anthropic_provider.py
│   │   │   └── base.py         # Provider protocol & factory
│   │   ├── runner.py           # LLM orchestrator with rate limiting
│   │   └── schemas.py          # Pydantic models for LLM responses
│   ├── mcp/                    # Model Context Protocol server
│   ├── models/                 # Core data models (SecurityFinding, ScanReport)
│   ├── persistence/            # SQLite store for scan history & feedback
│   ├── reporting/              # HTML, Markdown, CSV, JSON, SARIF exporters
│   ├── sast/
│   │   ├── engine.py           # SAST rule dispatcher
│   │   └── rules/              # 12 vulnerability detection modules
│   ├── security/               # Fernet-encrypted secret store, redaction
│   ├── slicer/                 # Code slice builder (context extraction)
│   ├── telemetry/              # OpenTelemetry tracing
│   └── triage/                 # SLM routing, prompts, verdict logic
├── tests/                      # 8 test modules covering SAST rules
├── docker/
│   ├── Dockerfile
│   └── compose.yml
├── pyproject.toml
└── README.md
```

---

## 🧪 Testing

PyScanner includes unit tests for SAST rule modules:

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=pyscanner

# Run a specific test module
pytest tests/test_sql_injection.py -v
```

### Test Coverage

| Test Module | Rules Tested |
|---|---|
| `test_sql_injection.py` | SQL injection patterns |
| `test_xss.py` | XSS via Markup, template strings, mark_safe |
| `test_path_traversal.py` | Path traversal & unsafe open() |
| `test_subprocess_rules.py` | Shell injection via subprocess |
| `test_file_upload.py` | Unrestricted file uploads |
| `test_misconfiguration.py` | DEBUG, CORS, SECRET_KEY |
| `test_supply_chain.py` | Typosquatting detection |
| `test_slice.py` | Code slice builder |

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest`
5. Submit a Pull Request

### Adding a New SAST Rule

1. Create a rule module in `src/pyscanner/sast/rules/`
2. Register it in `src/pyscanner/sast/engine.py`
3. Add remediation guidance in `src/pyscanner/core/remediation.py`
4. Add severity mapping in `src/pyscanner/core/pipeline.py`
5. Write tests in `tests/`

---

## 📝 License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <p>Built with ❤️ by <a href="https://github.com/harshil3103">Harshil</a></p>
  <p>
    <sub>PyScanner — Because your code deserves a security review, even at 3 AM.</sub>
  </p>
</div>
