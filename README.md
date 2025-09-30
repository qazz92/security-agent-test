# 🛡️ AI Security Agent Portfolio

AI-powered security vulnerability scanner with automated remediation using CrewAI multi-agent system.

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone <repo-url>
cd security-agent-portfolio

# 2. Copy environment variables
cp .env.example .env

# 3. Add your API keys to .env
# - OPENROUTER_API_KEY (required)
# - GITHUB_TOKEN (required for PR automation)

# 4. Start all services with Docker Compose
docker-compose up -d
```

**That's it!** 🎉 Access the application at http://localhost:8501

## 📋 What's Included

- **Security Agent**: Multi-agent AI system for vulnerability analysis
- **Langfuse Dashboard**: LLM tracing and observability (http://localhost:3001)
- **Demo Vulnerable App**: Sample application for testing (`demo/hello-world-vulnerable/`)

## 🔑 Demo Credentials

### Langfuse Dashboard (http://localhost:3001)

**Demo API Keys (Pre-configured)**:
```bash
LANGFUSE_PUBLIC_KEY=pk-lf-demo-portfolio-public-key-1234567890
LANGFUSE_SECRET_KEY=sk-lf-demo-portfolio-secret-key-1234567890abcdef
```

These keys are automatically created on first startup and already configured in `.env`.

To access the Langfuse web dashboard:
1. Open http://localhost:3001
2. Login with demo credentials:
   - **Email**: `demo@example.com`
   - **Password**: `demo1234`
3. View LLM traces in real-time

**Note**: Both the demo account and API keys are automatically created on first startup.

## 🏗️ Architecture

### Multi-Agent System (CrewAI)

```
Security Analyst → Trivy Scanner
       ↓
Semgrep Specialist → SAST Analysis
       ↓
Triage Specialist → Risk Prioritization
       ↓
Remediation Engineer → Auto-Fix & PR
```

### Dual Model Strategy (Cost Optimization)

- **Thinking Model** (`qwen3-next-80b-thinking`): Complex analysis, decision-making
- **Instruct Model** (`qwen3-next-80b-instruct`): Tool calling, formatting

## 📊 LLM Observability

All LLM calls are automatically traced to Langfuse:
- Token usage per agent
- Cost tracking
- Latency monitoring
- Tool call analysis

**OpenRouter + Langfuse**: Yes, fully supported! OpenRouter is OpenAI-compatible, so all API calls are traced through Langfuse callbacks.

## 🔧 Configuration

### Required Environment Variables

```bash
# OpenRouter API (LLM Provider)
OPENROUTER_API_KEY=sk-or-v1-...

# GitHub (for PR automation)
GITHUB_TOKEN=ghp_...
GITHUB_REPO_URL=https://github.com/username/repo

# Langfuse (auto-configured)
LANGFUSE_PUBLIC_KEY=pk-lf-demo-portfolio-public-key-1234567890
LANGFUSE_SECRET_KEY=sk-lf-demo-portfolio-secret-key-1234567890abcdef
LANGFUSE_HOST=http://localhost:3001
```

### Optional Configuration

```bash
# Model Selection
MODEL_THINKING=qwen/qwen3-next-80b-a3b-thinking
MODEL_INSTRUCT=qwen/qwen3-next-80b-a3b-instruct

# LLM Parameters
TEMPERATURE=0.3
MAX_TOKENS=4096
```

## 🎯 Usage

### 1. Web UI (Streamlit)

Access http://localhost:8501

- Upload project or GitHub URL
- Select scan type (Full/Quick)
- View results and auto-generated fixes
- Create GitHub PR with one click

### 2. CLI

```bash
# Run scan
python -m src.main scan --repo-url https://github.com/user/repo

# Generate report
python -m src.main report --format json
```

### 3. Demo Scan

Test with the included vulnerable app:

```bash
# Scan demo app
docker-compose run security-agent python -m src.main scan --path /app/demo/hello-world-vulnerable
```

## 📦 Services

| Service | URL | Description |
|---------|-----|-------------|
| Security Agent | http://localhost:8501 | Main application UI |
| Langfuse | http://localhost:3001 | LLM tracing dashboard |
| PostgreSQL | localhost:5433 | Langfuse database |

## 🧪 Demo Vulnerable Application

Located in `demo/hello-world-vulnerable/`:
- 20+ intentional security vulnerabilities
- SQL Injection, XSS, Command Injection
- Perfect for testing the security agent

```bash
# Run vulnerable app
cd demo/hello-world-vulnerable
python app.py

# Scan it
# Use the Streamlit UI and enter: /app/demo/hello-world-vulnerable
```

## 🛠️ Development

### Local Development (without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Run Streamlit app
streamlit run streamlit_app.py

# Run tests
pytest tests/
```

### Project Structure

```
security-agent-portfolio/
├── src/
│   ├── agents/          # CrewAI agents
│   │   ├── security_crew.py      # Multi-agent orchestration
│   │   └── ...
│   ├── tools/           # Security scanning tools
│   │   ├── trivy_tools.py        # Container/dependency scanning
│   │   ├── semgrep_tools.py      # SAST code analysis
│   │   └── github_tools.py       # PR automation
│   ├── prompts/         # Agent system prompts
│   └── models/          # LLM configuration
├── demo/                # Demo vulnerable apps
├── results/             # Scan results & reports
├── docker-compose.yml   # Service orchestration
└── streamlit_app.py     # Web UI
```

## 🐛 Troubleshooting

### Langfuse not tracking

```bash
# Check if Langfuse is running
docker logs langfuse-server

# Verify API keys in database
docker exec langfuse-db psql -U postgres -d langfuse -c "SELECT public_key FROM api_keys;"

# Restart security-agent
docker-compose restart security-agent
```

### Port conflicts

Edit `docker-compose.yml` and change port mappings:
```yaml
ports:
  - "8502:8501"  # Change left side (host port)
```

## 📚 Technology Stack

- **AI Framework**: CrewAI, LangChain
- **LLM Provider**: OpenRouter (OpenAI-compatible)
- **Security Tools**: Trivy, Semgrep
- **Observability**: Langfuse
- **Web UI**: Streamlit
- **Orchestration**: Docker Compose

## 🤝 Contributing

This is a portfolio project for demonstration purposes. The demo vulnerable application should never be deployed in production.

## 📄 License

MIT License

---

**Portfolio Project**

🌐 Access: http://localhost:8501
📊 Traces: http://localhost:3001
