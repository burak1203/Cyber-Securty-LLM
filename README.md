# CyberSecurity-LLM: Enterprise Network Threat Analyzer

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Docker](https://img.shields.io/badge/docker-containerized-2496ED)
![License](https://img.shields.io/badge/license-MIT-green)

CyberSecurity-LLM is a B2B-grade Security Operations Center (SOC) tool designed to monitor enterprise network traffic in real-time, execute Deep Packet Inspection (DPI), and analyze detected threats using isolated, on-premise Large Language Models (Local LLMs). 

Built with **Zero-Data-Leakage** as its core principle, this architecture ensures that sensitive network logs are never exposed to third-party cloud APIs. All AI inferences run securely on local infrastructure.

## 🚀 Enterprise Architecture & Features

- **Strict Data Contracts & Guardrails (Pydantic):** LLM outputs are strictly validated against pre-defined JSON schemas. Hallucinations or unstructured autonomous decisions are aggressively rejected, ensuring deterministic execution boundaries.
- **Asynchronous Queue Architecture (Zero Bottleneck):** Engineered a multi-threaded, Producer-Consumer pipeline. Capable of handling high-load gigabit traffic without causing I/O or CPU bottlenecks during packet sniffing.
- **Deterministic DPI Engine:** Signature-based threat detection capable of intercepting SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, and Path Traversal attacks directly from packet payloads.
- **MVC Architecture & Isolation:** Clean separation of concerns. The View (Jinja2/HTML) is fully isolated from the Controller logic, providing a scalable and maintainable codebase.
- **CI/CD & Regression Testing:** Automated CI/CD pipelines via **GitHub Actions**. Deep Packet Inspection signatures are validated through rigorous **Pytest** regression suites to prevent False Positives in benign traffic.

## 🛠️ Technology Stack

- **Backend:** Python, Flask (MVC), Pydantic (Data Validation)
- **Networking & DPI:** PyShark / Tshark
- **AI / MLOps:** Ollama (Local AI Engine), Prompt Engineering
- **DevOps:** Docker, Docker Compose, GitHub Actions, Pytest

## 📦 Getting Started (Deployment)

The project is fully containerized and requires no local Python dependencies or Tshark configurations on the host machine.

1. **Prepare the Local LLM Server:**
   Ensure [Ollama](https://ollama.com/) is installed and the base model is pulled:
   ```bash
   ollama run mistral
   ```

2. **Clone The Repository:**
   ```bash
   git clone https://github.com/burak1203/cyber-securty-llm.git
   cd cyber-securty-llm
   ```

3. **Deploy via Docker Compose:**
   ```bash
   docker-compose build --no-cache
   docker-compose up -d
   ```

4. **Access the SOC Dashboard:**
   Navigate to `http://localhost:5000` in your web browser.

## 🛡️ Security Notes

- The Docker container requires NET_ADMIN and NET_RAW privileges to listen to the host network interface at the kernel level.
- To prevent "Alert Fatigue", standard volumetric traffic across internal IP spaces is logged for auditing but bypasses the LLM engine, preserving compute resources.

## 📝 License

Distributed under the MIT License. See 'LICENSE' for more information.

## Images

<img width="1920" height="1038" alt="resim" src="https://github.com/user-attachments/assets/f721ff61-fc7c-437c-b7c6-d1a460bab5d4" />

- I attempted an SQL injection attack from my own mobile device against the HTTP port I had opened.
