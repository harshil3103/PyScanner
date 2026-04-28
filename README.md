
<div align="center">
  <h1>🛡️ PyScanner</h1>
  <p><strong>The AI-Powered Security Review Assistant for Python</strong></p>
  
  [![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Security Score](https://img.shields.io/badge/Security-A%2B-success.svg)](#)
</div>

<br>

**PyScanner** is a hybrid Static Application Security Testing (SAST) tool that acts like a senior security engineer sitting right next to you. It combines the speed of traditional rule-based scanning with the reasoning power of local and cloud Large Language Models (LLMs) to eliminate false positives and provide actionable, context-aware remediation.

## ✨ Features

*   **⚡ Blazing Fast Rule Engine:** Scans your codebase in milliseconds using an AST-based analyzer to catch the 14 most critical vulnerability categories (SQLi, XSS, Path Traversal, Insecure Deserialization, etc.).
*   **🤖 AI Triage (Zero False Positives):** Uses local SLMs (via Ollama) and Cloud LLMs (OpenAI, Anthropic) to review suspicious code. If the AI determines a finding is safe, it automatically suppresses it.
*   **💯 Project Security Scoring:** Calculates a 0-100 grade for your repository based on vulnerability severity, confidence, and blast radius.
*   **🛠️ Actionable Auto-Fixes:** Doesn't just tell you *what* is wrong; tells you *why* it matters and provides the exact safe replacement code to fix it.
*   **📊 Beautiful Dashboards:** Generates stunning terminal UIs, Dark-mode HTML reports, CSVs for spreadsheets, and Markdown for GitHub PRs.
*   **📈 History & Feedback Tracking:** Local SQLite database tracks your security score trends over time and remembers your manually marked false-positives.

---

## 🚀 Quick Start

### 1. Installation

Clone the repository and install it in editable mode:

```bash
git clone https://github.com/yourusername/PyScanner.git
cd PyScanner
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

*(Optional) Install Ollama to enable local AI triage without leaving your machine.*

### 2. Run your first scan

Scan a file or directory and view the interactive terminal dashboard:

```bash
pyscanner scan ./my_python_project --db local.db
```

### 3. Generate a Web Report

Need to share the results with your team? Export a sleek, interactive HTML dashboard:

```bash
pyscanner scan ./my_python_project --format html
open pyscanner-report.html
```

### 4. Check your Security Trends

View your previous scans to see if your security score is improving:

```bash
pyscanner history --db local.db
```

---

## 🧠 How It Works (The Pipeline)

PyScanner operates in a 4-stage pipeline:

1.  **Ingestion & Slicing:** Discovers `.py` files and uses an AST Graph to build minimal, context-rich "code slices" around suspicious function calls.
2.  **Detection:** A deterministic SAST engine runs lightning-fast checks against the AST to find potential vulnerabilities.
3.  **AI Triage:** The findings and their code slices are sent to an LLM. The AI acts as a judge, discarding false positives and confirming true threats.
4.  **Enrichment & Reporting:** Confirmed findings are enriched with OWASP categories, severity labels, and remediation code before being compiled into the final Security Score and Report.

![Pipeline Diagram Placeholder](docs/assets/pipeline.png)

---

## 🛡️ Vulnerabilities Covered

PyScanner currently detects the following vulnerability classes out of the box:

*   **Injection:** Arbitrary Code Execution (`eval`/`exec`), OS Command Injection, SQL Injection.
*   **Data Integrity:** Insecure Deserialization (`pickle`), Unsafe YAML Loading.
*   **Access Control:** Directory / Path Traversal.
*   **Web Flaws:** Cross-Site Scripting (XSS), Insecure File Uploads.
*   **Cryptography:** Weak Hashing (MD5/SHA1), Predictable Randomness, Disabled SSL Verification.
*   **Misconfiguration:** Hardcoded Secrets, `DEBUG=True` in production, Wildcard CORS.
*   **Supply Chain:** Typosquatting and known malicious package detection.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. If you are adding a new SAST rule, be sure to update `src/pyscanner/core/remediation.py` with the appropriate fix guidance.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.
