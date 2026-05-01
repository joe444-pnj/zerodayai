# ZERODAY AI
<p align="center">
  <img src="./assets/logo.png" alt="ZeroDay AI Logo" width="200"/>
</p>

<p align="center">
  <strong>Autonomous Vulnerability Research Powered by Reasoning</strong>
</p>

---

**Autonomous Vulnerability Research Powered by Reasoning**

The ZeroDay AI project is a comprehensive vulnerability assessment tool designed to identify potential security threats in web applications and services. It leverages a combination of static analysis, fuzzing, and large language models to uncover security vulnerabilities autonomously.

## 🚀 Features

- **Static Analysis**: Performs in-depth analysis of code to identify potential vulnerabilities and security weaknesses using industry-leading tools (Bandit, Semgrep).
- **Fuzzing**: Tests the runtime behavior of web applications and services to identify potential vulnerabilities through HTTP fuzzing.
- **Large Language Models (LLMs)**: Utilizes LLMs to analyze static analysis results and code context to generate strategic security hypotheses.
- **Interactive Menu**: Provides an interactive menu for users to launch scans, fetch CVE data, check environment readiness, launch the web dashboard, and display scan history.
- **Web Dashboard**: Offers a built-in web dashboard for visualizing scan results and managing vulnerability assessments.
- **Configurable**: Allows users to configure settings for various components, such as scanning, static analysis, and reporting.
- **Autonomous Research**: Reasoning-based approach to vulnerability discovery without manual intervention.

## 🛠️ Tech Stack

- **Frontend**: FastAPI, Uvicorn, Jinja2
- **Backend**: Python, Click, Rich, Asyncio, Pathlib, Sys
- **Database**: SQLAlchemy, Aiosqlite
- **AI Tools**: Large Language Models (LLMs), Ollama
- **Security Scanners**: Bandit, Semgrep
- **Dependencies**: yaml, dotenv, dataclasses, pathlib, re, typing, urllib.parse

## 📦 Installation

### Prerequisites

- Python 3.8+
- pip 20.0+
- Aiosqlite 0.17.0+
- FastAPI 0.92.0+
- Uvicorn 0.17.6+
- Jinja2 3.0.3+
- Click 8.1.3+
- Rich 12.5.1+
- Ollama (for LLM capabilities)
- Bandit and Semgrep (for static analysis)

### Installation Steps

1. Clone the repository: 
   ```bash
   git clone https://github.com/joe444-pnj/zerodayai
   ```

2. Navigate to the project directory: 
   ```bash
   cd zerodayai
   ```

3. Install dependencies: 
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables: 
   ```bash
   cp .env.example .env
   ```

5. Initialize the database: 
   ```bash
   python core/database.py init_db
   ```

## 💻 Usage

1. Launch the interactive menu: 
   ```bash
   python main.py
   ```

2. Select an option from the menu to:
   - Launch a vulnerability scan
   - Fetch CVE data
   - Check environment readiness
   - Launch the web dashboard
   - Display scan history
   - Configure settings

## 📂 Project Structure

```
.
├── agents/
│   ├── base.py
│   ├── llm/
│   │   ├── llm_planner.py
│   │   └── ollama_client.py
│   ├── static/
│   │   ├── static_agent.py
│   │   ├── bandit_runner.py
│   │   └── semgrep_runner.py
│   └── fuzzer/
│       ├── fuzzer_agent.py
│       └── http_fuzzer.py
├── api/
│   └── server.py
├── core/
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── orchestrator.py
│   └── utils/
│       ├── json_sanitizer.py
│       └── url.py
├── assets/
│   └── logo.png
├── main.py
├── config.yaml
├── .env.example
├── requirements.txt
└── README.md
```

## 🔍 How It Works

ZeroDay AI operates through an intelligent orchestration system:

1. **Analysis Planning**: The LLM planner strategizes the best approach for vulnerability discovery
2. **Static Analysis**: Bandit and Semgrep scan the codebase for known vulnerability patterns
3. **Fuzzing**: HTTP fuzzer tests the running application with various payloads
4. **Hypothesis Generation**: LLMs analyze results and generate security hypotheses
5. **Reporting**: Results are aggregated and presented through the web dashboard

## 🤝 Contributing

Contributions are welcome! Please submit a pull request with your changes and a brief description of what you've added or fixed.

## 📝 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is designed for authorized security testing and vulnerability assessment only. Unauthorized access to computer systems is illegal. Always ensure you have proper authorization before conducting any security assessments.
