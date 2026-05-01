# 🧠 ZeroDay AI Project
The ZeroDay AI project is a comprehensive vulnerability assessment tool designed to identify potential security threats in web applications and services. It leverages a combination of static analysis, fuzzing, and large language models (LLMs) to provide a thorough and accurate assessment of an application's security posture. The project aims to provide a robust and scalable solution for developers and security professionals to identify and mitigate potential vulnerabilities.

## 🚀 Features
- **Static Analysis**: Performs in-depth analysis of code to identify potential vulnerabilities and security weaknesses.
- **Fuzzing**: Tests the runtime behavior of web applications and services to identify potential vulnerabilities.
- **Large Language Models (LLMs)**: Utilizes LLMs to analyze static analysis results and code context to generate strategic security hypotheses.
- **Interactive Menu**: Provides an interactive menu for users to launch scans, fetch CVE data, check environment readiness, launch the web dashboard, and display scan history.
- **Web Dashboard**: Offers a built-in web dashboard for visualizing scan results and managing vulnerability assessments.
- **Configurable**: Allows users to configure settings for various components, such as scanning, static analysis, and reporting.

## 🛠️ Tech Stack
- **Frontend**: FastAPI, Uvicorn, Jinja2
- **Backend**: Python, Click, Rich, Asyncio, Pathlib, Sys
- **Database**: SQLAlchemy, Aiosqlite
- **AI Tools**: Large Language Models (LLMs), Ollama
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
- Asyncio 3.4.3+
- Pathlib 1.0.1+
- Sys 3.4.3+
- yaml 6.0+
- dotenv 0.20.0+
- dataclasses 0.8+
- pathlib 1.0.1+
- re 2.2.1+
- typing 3.10.10+
- urllib.parse 3.4.3+

### Installation
1. Clone the repository: `git clone https://github.com/your-repo/ZeroDay-AI.git`
2. Navigate to the project directory: `cd ZeroDay-AI`
3. Install dependencies: `pip install -r requirements.txt`
4. Configure environment variables: `cp .env.example .env`
5. Initialize the database: `python core/database.py init_db`

## 💻 Usage
1. Launch the interactive menu: `python main.py`
2. Select an option from the menu to launch a scan, fetch CVE data, check environment readiness, launch the web dashboard, or display scan history.

## 📂 Project Structure
```markdown
.
├── agents
│   ├── base.py
│   ├── llm
│   │   ├── llm_planner.py
│   │   └── ollama_client.py
│   ├── static
│   │   ├── static_agent.py
│   │   ├── bandit_runner.py
│   │   └── semgrep_runner.py
│   └── fuzzer
│       ├── fuzzer_agent.py
│       └── http_fuzzer.py
├── api
│   └── server.py
├── core
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── orchestrator.py
│   └── utils
│       ├── json_sanitizer.py
│       └── url.py
├── main.py
├── config.yaml
├── .env
├── .env.example
├── requirements.txt
└── README.md
```


## 🤝 Contributing
Contributions are welcome! Please submit a pull request with your changes and a brief description of what you've added or fixed.

## 📝 License
This project is licensed under the MIT License.
## 💖 Thanks Message
This project was made possible by the contributions of many individuals. Thank you to everyone who has helped make this project a success! 
This is written by readme.ai [readme.ai](https://readme-generator-phi.vercel.app/)
