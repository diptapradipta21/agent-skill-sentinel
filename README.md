# 🛡️ Agent Skill Sentinel

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](https://opensource.org/licenses/MIT)
[![Zero-Token Security](https://img.shields.io/badge/LLM%20Cost-%240.00%20(Zero--Token)-green)](https://github.com/diptapradipta21/agent-skill-sentinel)

**Agent Skill Sentinel** is an open-source static security scanner and guardrail designed for AI Agent toolsets, MCP servers, and `SKILL.md` skill definitions (Hermes Agent, Claude Code, Cursor, Copilot, AutoGPT).

It inspects agent skill definitions and tool execution scripts for **Prompt Injections**, **Malicious Reverse Shells**, **Credential Exfiltration**, and **Destructive Commands** without consuming any LLM tokens.

---

## ⚡ Why Skill Sentinel?

Autonomous AI coding agents and MCP toolchains routinely ingest custom prompts and scripts from external repos. An unvetted skill can silently inject instructions, exfiltrate API keys, or execute destructive shell commands (`rm -rf /`, reverse TCP sockets, webhook dumping).

**Skill Sentinel runs locally in milliseconds**, providing deterministic security gates for agent runtime environments and CI/CD pipelines.

---

## 🔍 Core Security Detection Vectors

| Rule ID | Category | Severity | Description |
| :--- | :--- | :--- | :--- |
| `SKL-INJ-001` | Prompt Injection | **CRITICAL** | System constraint bypass (`ignore previous instructions`, jailbreak markers). |
| `SKL-SH-001` | Reverse Shell | **CRITICAL** | Reverse TCP sockets, netcat pipes (`/dev/tcp`, `mkfifo`, raw socket connects). |
| `SKL-DYN-001` | Dynamic Exec | **CRITICAL** | Arbitrary runtime evaluation (`eval()`, `exec()`, `__import__("os").system`). |
| `SKL-OBF-001` | Obfuscation | **HIGH** | Piped shell decoding (base64 decode pipeline, xxd, openssl). |
| `SKL-SEC-001` | Credential Leak | **CRITICAL** | Live hardcoded API keys (`ghp_`, `sk-ant-`, `sk-proj-`, SSH Private Keys). |
| `SKL-SEC-002` | Identity Access | **CRITICAL** | SSH identity theft attempts (`id_rsa`, `id_ed25519` exfiltration). |
| `SKL-SH-002` | Destructive Ops | **HIGH** | Recursive deletion of root/home (`rm -rf /`, disk wipe `dd`, fork bombs). |
| `SKL-EXF-001` | Exfiltration | **HIGH** | Unauthorized webhooks (`webhook.site`, `pipedream`, `requestbin`). |
| `SKL-ESC-001` | Sandbox Escape | **HIGH** | Sudoers tampering, unauthorized `chmod 777`, privilege escalation. |
| `SKL-HAR-001` | Env Harvesting | **MEDIUM** | Dumping runtime environment variables (`cat .env`, `printenv >`). |

---

## 🚀 Installation & Quick Start

### 1. Direct CLI Usage
```bash
# Clone the repository
git clone https://github.com/diptapradipta21/agent-skill-sentinel.git
cd agent-skill-sentinel

# Make executable
chmod +x src/sentinel.py
```

### 2. Scan a Single SKILL.md
```bash
python3 src/sentinel.py /path/to/SKILL.md
```

### 3. Scan Entire Skills Directory
```bash
python3 src/sentinel.py /path/to/skills/ --fail-on-high
```

### 4. Advanced Filtering & Exclusions
```bash
# Filter by minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
python3 src/sentinel.py ./skills/ --min-severity HIGH

# Ignore specific benign rules
python3 src/sentinel.py ./skills/ --ignore-rule SKL-HAR-001,SKL-OBF-001

# Skip extra vendor directories (automatically skips .git, node_modules, venv)
python3 src/sentinel.py ./skills/ --exclude-dir vendor,tmp_cache
```

### 5. Self-Check & Test Suite
Run the built-in test suite (zero external dependencies):
```bash
python3 tests/test_sentinel.py
```

### 6. Machine-Readable JSON Output (For Agent Tooling & MCP)
```bash
python3 src/sentinel.py /path/to/skills/ --json
```

---

## 🧪 Real-World Example Output

```text
    ╔═══════════════════════════════════════════════════════╗
    ║        🛡️  A G E N T   S K I L L   S E N T I N E L     ║
    ║   Zero-Token Security Guardrail for AI Agent Skills  ║
    ╚═══════════════════════════════════════════════════════╝
    v0.1.1 · Maintainer: @diptapradipta21

[*] Scanning target: /opt/data/skills/panggung-merah

✅ AUDIT PASSED: No security risks or prompt injections detected in target skills.
```

---

## 🛡️ CI/CD Integration (GitHub Actions)

Add this check to your repository to prevent risky skills from merging into production:

```yaml
name: Agent Skill Security Audit

on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Skill Sentinel Scanner
        run: |
          python3 src/sentinel.py ./skills/ --fail-on-high
```

---

## 📄 License
MIT License. Created & maintained by [Fajar Indra Pradipta Gajah](https://github.com/diptapradipta21).
Contributions welcome!
