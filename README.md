# ZeroDay AI 🔍⚡

### *"An autonomous vulnerability research assistant built to support, not replace, modern security tooling."*

---

## 🚀 Overview

ZeroDay AI is a local-first security research assistant that combines traditional security tools with language model reasoning.

Instead of relying only on signatures or predefined patterns, it aims to analyze context, behavior, and logic to help surface potential vulnerabilities.

> "Good tools find known bugs. Great workflows help uncover the unknown."

---

## ✨ Philosophy

* Respect existing tools ;; build on top of them
* Keep everything local ;; privacy matters
* Focus on reasoning ;; not just detection
* Stay practical ;; useful for real workflows

---

## ⚙️ Features

* 🧠 Context-aware analysis using local LLMs
* 🔎 Integration with tools like Bandit & Semgrep
* 🔑 Secrets detection (tokens, API keys, credentials)
* 📦 Dependency vulnerability correlation (CVEs)
* 💣 Adaptive fuzzing based on live responses
* 🌐 Network scanning & service fingerprinting
* 🧬 Exploratory research mode for edge-case discovery

---

## 🛠️ Setup

```bash
python install.py
```

> Installs dependencies ;; prepares environment ;; initializes components

---

## 🧠 Model Setup (Ollama)

ZeroDay AI uses a local model for reasoning:

```bash
# https://ollama.com
ollama pull deepseek-coder-v2
```

---

## ▶️ Run

```bash
python main.py
```

> Follow the CLI prompts to start a scan

---

## 📊 Dashboard

```bash
python main.py dashboard
```

* View findings
* Explore severity breakdowns
* Inspect generated PoCs

Access:

```
http://localhost:8000
```

---

## 🛡️ Coverage

* Web ;; SQLi, XSS, SSRF, CSRF, SSTI, XXE, LFI/RFI
* Auth ;; IDOR/BOLA, privilege escalation, bypass
* System ;; memory issues, command injection
* Logic ;; race conditions, TOCTOU, workflow flaws

---

## 📁 Structure

```text
zeroday/
├── main.py
├── install.py
├── config.yaml
├── core/
├── agents/
├── cli/
├── api/
└── knowledge/
```

---

## 🚧 Project Status

> "Work in progress — evolving with every iteration."

ZeroDay AI is still under active development.

* Some features may be incomplete or experimental
* Behavior may change between updates
* Results may not always be consistent or fully accurate

If something does not work as expected, it is likely part of ongoing development rather than a final limitation.

Feedback, issues, and contributions are welcome.

---

## ⚖️ Disclaimer

> "Use responsibly."

This project is intended for **authorized security testing only**.

* Always have permission
* Follow applicable laws
* Respect systems and data

The authors assume no liability for misuse.

---
