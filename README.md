# 🛡️ AI Security Agent Portfolio

> DevSecOps 실무 경험을 최신 AI 기술(CrewAI, LangChain)로 재구성한 **Agentic Workflow 보안 자동화 시스템**

---

## 💡 지원 동기

8년간의 엔지니어 여정을 통해 저는 기술의 진화를 직접 체감하며 성장해왔습니다. Backend 개발자로 시작한 3년, 그리고 DevOps 엔지니어로 전환하여 보낸 4년이 넘는 시간 동안, 저는 항상 더 나은 방법을 찾고 새로운 기술을 적용하는 것에 열정을 가져왔습니다.

최근 DevSecOps 프로젝트에서 LLM을 활용하면서 저는 개발의 미래를 엿봤습니다. SDLC 전 구간에 보안 도구를 통합하는 과정에서 AWS Bedrock을 활용해 고위험 취약점을 자동으로 필터링하고 PR을 생성하는 시스템을 구축했는데, 이때 "앞으로의 개발은 이렇게 AI와 함께하는 것이구나!"라는 강렬한 깨달음을 얻었습니다. 동시에 "어떻게 하면 이걸 더 멋지게, 더 잘 할 수 있을까?"라는 질문이 저를 사로잡았습니다.

이 호기심은 저를 본격적인 실험으로 이끌었습니다. LLM이 정확히 어떻게 동작하는지, 실제로 어떻게 서빙되는지 직접 경험해보고 싶었습니다. 그래서 vLLM 기반으로 Qwen Coder 30B 모델을 4비트 양자화하여 직접 띄워보며 사내 LLM 서빙 시스템 PoC를 진행했습니다. 모델을 직접 다뤄보니 LLM의 가능성과 한계, 그리고 실제 운영에서 고려해야 할 점들이 훨씬 명확해졌습니다.

하지만 여기서 멈추지 않았습니다. "만약 LLM이 단순히 취약점을 필터링하는 도구를 넘어, Agent로서 자율적으로 판단하고 실행한다면?" 이 질문에 답을 찾고 싶었습니다. 개인 시간을 투자해 CrewAI와 LangChain을 활용한 Agentic Workflow 포트폴리오를 제작했고, Agent가 복잡한 워크플로우를 스스로 제어하고, Langfuse로 전체 과정을 추적하며, Dual Model Strategy로 비용을 최적화하는 시스템을 구현했습니다.

이 경험을 통해 저는 확신했습니다 - AI는 단순한 도구가 아니라 워크플로우를 근본적으로 재정의하는 전환점이라는 것을. 그리고 이제 이 비전을 개인 프로젝트가 아닌, 실제 조직에 적용하여 진짜 변화를 만들어내고 싶습니다.

AI Transformation Team이 추구하는 Agentic System 구축과 AI 기반 업무 환경 혁신은 제가 꿈꾸던 미래와 정확히 일치합니다. Backend에서 DevOps로, 그리고 이제 AI 엔지니어링으로 자연스럽게 진화해온 제 경험이 크래프톤의 AI 전환 여정에 실질적인 가치를 더할 수 있다고 확신합니다. 특히 대규모 Agent 실행 인프라 구축과 전사적 AI 플랫폼 개발은 제가 가진 모든 역량이 시너지를 발휘할 수 있는 영역입니다.

무엇보다 AI Transformation Team과 함께라면, 단순히 기술을 따라가는 것이 아니라 게임 산업에서 AI 혁신을 주도하는 선두 주자가 될 수 있다고 믿습니다. 이 여정에 제 열정과 경험을 더하고 싶습니다.

---

## 📌 프로젝트 개요

실무에서 구축한 **DevSecOps 파이프라인**(GitHub Actions → Trivy → Lambda → AWS Bedrock → Security Hub)의 한계를 극복하기 위해, **CrewAI 멀티 에이전트 시스템**과 **LangChain Tool Calling**을 활용하여 완전히 새롭게 설계한 보안 자동화 포트폴리오입니다.

### 🎯 핵심 차별점

| 구분 | 실무 프로젝트 (2025) | 본 포트폴리오 |
|------|---------------------|----------------|
| **워크플로우 제어** | Node.js Lambda 코드가 순차 실행 | **에이전트 자율 실행** (CrewAI) |
| **LLM 역할** | 검증 + 우선순위화만 | **전체 워크플로우 주도** |
| **컨텍스트 공유** | 수동 전달 (매번 전체 전달) | **자동 전달** (에이전트 간) |
| **하드코딩** | 취약점 분류 300+ 줄 if/elif | **LLM 기반 분류** (0줄) |
| **확장성** | 새 도구 추가 시 2시간 | **30분** (Tool 추가만) |
| **Observability** | 없음 | **Langfuse 트레이싱** |

### 🏆 기술 스택

**AI/ML**:
- CrewAI (Multi-agent orchestration)
- LangChain (Tool Calling, Prompt Templates)
- OpenRouter (70+ LLM models)
- Langfuse (LLM observability)

**Security Tools**:
- Trivy (Container/dependency vulnerability scanner)
- Semgrep (SAST - Static Application Security Testing)

**Infrastructure**:
- Docker Compose (Service orchestration)
- PostgreSQL (Langfuse database)
- Streamlit (Web UI)



---

## 🚀 Quick Start

### 1. 사전 준비

```bash
# OpenRouter API Key 발급 (필수)
# https://openrouter.ai 에서 가입 및 API Key 생성

# GitHub Personal Access Token 발급 (PR 자동화 사용 시)
# https://github.com/settings/tokens
```

### 2. 프로젝트 실행

```bash
# 1. Repository Clone
git clone <repo-url>
cd security-agent-portfolio

# 2. 환경 변수 설정
cp .env.example .env

# 3. API Key 입력 (.env 파일 수정)
# OPENROUTER_API_KEY=sk-or-v1-...
# GITHUB_TOKEN=ghp_... (선택사항)

# 4. Docker Compose 실행
docker-compose up -d
```

**That's it!** 🎉

- **Security Agent UI**: http://localhost:8501
- **Langfuse Dashboard**: http://localhost:3001 (demo@example.com / demo1234)

### 3. 데모 스캔 실행

```bash
# Streamlit UI에서:
# 1. Project Path 입력: /app/demo/hello-world-vulnerable
# 2. "Run Security Scan" 클릭
# 3. 결과 확인 및 PR 템플릿 생성
```

---

## 🤖 Agentic Workflow 아키텍처

### Multi-Agent System (CrewAI)

```
┌─────────────────────────────────────────────────────┐
│          Security Orchestrator (전체 조율)           │
└────────────────┬────────────────────────────────────┘
                 │
     ┌───────────┴───────────┐
     ▼                       ▼
┌──────────────┐    ┌──────────────────┐
│Security      │    │Semgrep           │
│Analyst       │    │Specialist        │
│              │    │                  │
│Tools:        │    │Tools:            │
│- Trivy       │    │- Semgrep         │
│              │    │- Config List     │
│Model:        │    │                  │
│Instruct      │    │Model: Instruct   │
└──────┬───────┘    └──────────┬───────┘
       │                       │
       └───────────┬───────────┘
                   ▼
          ┌─────────────────┐
          │Triage           │
          │Specialist       │
          │                 │
          │Tools:           │
          │- Priority Calc  │
          │- Impact Assess  │
          │                 │
          │Model: Thinking  │ ← 복잡한 추론
          └────────┬────────┘
                   ▼
        ┌────────────────────┐
        │Remediation         │
        │Engineer            │
        │                    │
        │Tools:              │
        │- Fix Code Gen      │
        │- PR Template       │
        │                    │
        │Model: Instruct     │
        └────────────────────┘
```

### 실무 프로젝트 vs 포트폴리오 비교

**실무 프로젝트 (Node.js + AWS Bedrock)**:
```javascript
// Node.js Lambda 코드가 워크플로우 제어 (의사코드)
exports.handler = async (event) => {
  // 1. SARIF 파싱 (하드코딩 300줄)
  const vulnerabilities = classifyFromSARIF(sarif);

  // 2. AWS Bedrock: 온도 교차 검증
  const verified = await crossValidate(vulnerabilities);

  // 3. AWS Bedrock: 우선순위화
  const prioritized = await prioritize(verified);

  // 4. Security Hub 전송
  await sendToSecurityHub(prioritized);
};
```

**포트폴리오 (CrewAI + LangChain)**:
```python
# CrewAI가 에이전트 간 자동 조율
crew = Crew(
    agents=[analyst, semgrep, triage, remediation],
    tasks=[task1, task2, task3, task4],
    process=Process.SEQUENTIAL  # 순차 실행, 자동 컨텍스트 전달
)

# LLM이 전체 워크플로우 주도
result = crew.kickoff()
```

---

## 🔧 핵심 기술 구현

### 1. LLM 기반 취약점 분류 (하드코딩 제거)

**실무 방식**: 300줄 if/elif 체인
```javascript
// SARIF 파싱 후 하드코딩 분류 (의사코드)
if (ruleId.includes('sql')) return 'SQL_INJECTION';
if (ruleId.includes('xss')) return 'XSS';
// ... 50+ 취약점 타입
```

**포트폴리오 방식**: LLM 프롬프트 엔지니어링
```python
# 50줄 프롬프트로 대체
prompt = ChatPromptTemplate.from_messages([
    ("system", """Classify into EXACT types:
    - SQL_INJECTION, XSS, COMMAND_INJECTION, ...
    Return ONLY the type."""),
    ("user", "Rule ID: {rule_id}\nMessage: {message}")
])
```

**개선 효과**:
- ✅ 300줄 코드 → 50줄 프롬프트
- ✅ 새로운 Semgrep 룰 자동 대응
- ✅ rule_id + message 컨텍스트 기반 정확도 향상

### 2. Dual Model Strategy (비용 최적화)

```python
# src/utils/model_selector.py
class TaskComplexity(Enum):
    # Thinking Model (복잡한 추론)
    RISK_ASSESSMENT = "risk_assessment"
    VULNERABILITY_TRIAGE = "vulnerability_triage"

    # Instruct Model (단순 실행)
    TOOL_CALLING = "tool_calling"
    DATA_FORMATTING = "data_formatting"

# 작업별 모델 자동 선택
triage_llm = model_selector.get_llm(
    TaskComplexity.RISK_ASSESSMENT  # → Thinking Model
)
```

**비용 절감 효과**:
```
단일 모델: 1,000,000 tokens × $0.0020 = $2,000/월

Dual Strategy:
- Thinking: 200K tokens × $0.0020 = $400
- Instruct: 800K tokens × $0.0010 = $800
→ Total: $1,200/월 (40% 절감)
```

### 3. Langfuse Observability

```python
# 모든 LLM 호출 자동 추적
import litellm
litellm.success_callback = ["langfuse"]
litellm.failure_callback = ["langfuse"]
```

**Langfuse 대시보드에서 확인**:
- 📊 에이전트별 LLM 호출 횟수
- 💰 토큰 사용량 및 비용
- ⏱️ 레이턴시
- 🔍 프롬프트/응답 내용

---

## 📊 실무 적용 시나리오

### Input: Flask 취약점 스캔

```bash
Project: /app/demo/hello-world-vulnerable
Files: app.py, requirements.txt
```

### Workflow Execution

**Step 1**: Security Analyst (Trivy)
```
[Tool Call] scan_with_trivy
→ requests==2.25.1 (CVE-2023-xxxxx) HIGH
→ flask==1.1.2 (CVE-2022-xxxxx) MEDIUM
```

**Step 2**: Semgrep Specialist (SAST)
```
[Tool Call] scan_with_semgrep
→ app.py:57 - python.flask.security.injection.tainted-sql-string

[LLM Classification]
→ SQL_INJECTION (하드코딩 없이 LLM이 분류)
```

**Step 3**: Triage Specialist (리스크 평가)
```
[Thinking Model - Complex Reasoning]
→ SQL Injection: Score 95/100 (Critical)
→ CVE-2023-xxxxx: Score 85/100 (High)
```

**Step 4**: Remediation Engineer (수정 생성)
```
[Tool Call] generate_fix_code
→ Parameterized query 생성

[Tool Call] create_github_pr
→ PR 템플릿 파일 생성: /app/results/pr_template_20250101.md
```

### Output: PR Template 자동 생성

```markdown
# Security Fixes - SQL Injection & Dependencies

## 🐛 Vulnerabilities Fixed
- SQL Injection (app.py:57) - CRITICAL
- requests CVE-2023-xxxxx - HIGH

## 🔧 Changes
- Use parameterized queries with SQLAlchemy
- Update requests to 2.31.0

## 🤖 Generated by AI Security Agent
```

---

## 🔑 환경 변수 설정

### 필수 설정

```bash
# .env 파일
OPENROUTER_API_KEY=sk-or-v1-...  # OpenRouter API Key
GITHUB_TOKEN=ghp_...              # GitHub Personal Access Token (PR 자동화)
```

### 선택 설정

```bash
# 모델 선택
MODEL_THINKING=qwen/qwen3-next-80b-a3b-thinking
MODEL_INSTRUCT=qwen/qwen3-next-80b-a3b-instruct

# Langfuse (자동 설정됨)
LANGFUSE_PUBLIC_KEY=pk-lf-demo-portfolio-public-key-1234567890
LANGFUSE_SECRET_KEY=sk-lf-demo-portfolio-secret-key-1234567890abcdef
LANGFUSE_HOST=http://localhost:3001
```

---

## 📦 서비스 구성

| Service | URL | Description |
|---------|-----|-------------|
| **Security Agent** | http://localhost:8501 | Streamlit Web UI |
| **Langfuse** | http://localhost:3001 | LLM Tracing Dashboard |
| **PostgreSQL** | localhost:5433 | Langfuse Database |

### Langfuse 대시보드 로그인

```
Email: demo@example.com
Password: demo1234
```

---

## 🛠️ 프로젝트 구조

```
security-agent-portfolio/
├── src/
│   ├── agents/
│   │   ├── security_crew.py          # CrewAI 멀티 에이전트 오케스트레이션
│   │   └── orchestrator_agent.py     # 전체 워크플로우 조율
│   ├── tools/
│   │   ├── scanner_tools.py          # Trivy 스캔 도구
│   │   ├── semgrep_tools.py          # Semgrep SAST (LLM 기반 분류)
│   │   ├── analysis_tools.py         # 우선순위 계산
│   │   ├── fix_tools_v2.py           # 수정 코드 생성 (LLM 기반)
│   │   └── github_tools.py           # PR 템플릿 생성
│   ├── prompts/
│   │   └── crew_agents/              # 에이전트별 프롬프트
│   ├── utils/
│   │   ├── model_selector.py         # Dual Model Strategy
│   │   └── prompt_manager.py         # 프롬프트 로딩
│   └── models/
│       └── llm_config.py             # LLM 설정
├── demo/
│   └── hello-world-vulnerable/       # 취약점 테스트용 Flask 앱
├── results/                          # 스캔 결과 및 PR 템플릿
├── docker-compose.yml
├── streamlit_app.py
└── requirements.txt
```

---

## 🧪 데모 취약점 애플리케이션

`demo/hello-world-vulnerable/`: 20+ 의도적 취약점 포함

- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Insecure Deserialization

```bash
# 데모 앱 스캔
# Streamlit UI에서 Project Path: /app/demo/hello-world-vulnerable
```

---

## 📚 관련 문서

- **[PORTFOLIO.md](PORTFOLIO.md)**: 프로젝트 상세 설명 (기술 구현, 아키텍처, 실무 비교)
- **[MOTIVATION.md](MOTIVATION.md)**: 제작 배경 및 지원 동기 (DevOps 경험, 학습 내용)

---

## 🐛 Troubleshooting

### Langfuse 추적 안 됨

```bash
# Langfuse 로그 확인
docker logs langfuse-server

# Security Agent 재시작
docker-compose restart security-agent
```

### 포트 충돌

```yaml
# docker-compose.yml 수정
ports:
  - "8502:8501"  # 왼쪽(호스트 포트) 변경
```

### OpenRouter API 오류

```bash
# API Key 확인
echo $OPENROUTER_API_KEY

# 크레딧 확인: https://openrouter.ai/credits
```

---

## 💡 로컬 개발 (Docker 없이)

```bash
# 의존성 설치
pip install -r requirements.txt

# Streamlit 실행
streamlit run streamlit_app.py

# 테스트 실행
pytest tests/
```

---

## 🎓 학습 포인트

이 프로젝트를 통해 배운 내용:

✅ **Agentic Workflow 설계**
- 작업을 전문 에이전트로 분할하는 기준
- 에이전트 간 컨텍스트 자동 전달 (CrewAI)
- Tool Calling 구현 (LangChain BaseTool)

✅ **LLM 프로덕션 적용**
- 프롬프트 엔지니어링 (Format 명시, Few-shot)
- 하드코딩 제거, LLM 기반 의사결정
- 비용 최적화 (Dual Model Strategy)

✅ **Observability**
- LLM 호출 추적 (Langfuse)
- 토큰 사용량 및 비용 모니터링
- 프롬프트 개선을 위한 A/B 테스트

✅ **실무 vs 최신 AI 기술 비교**
- Node.js 코드 제어 → 에이전트 자율 실행
- 하드코딩 → 프롬프트 엔지니어링
- 수동 컨텍스트 전달 → 자동 컨텍스트 공유

---

## 👨‍💻 Author Background

**DevOps Engineer → AI Security Portfolio**

실무 경험:
- **AWS EKS** 프로덕션 Kubernetes 클러스터 운영
- **IaC (Terraform)** 인프라 자동화 및 형상 관리
- **MSA** 마이크로서비스 아키텍처 기반 멀티 서비스 배포
- **AWS Cloud** (Lambda, EventBridge, S3, RDS, VPC 등) 통합 운영
- **DevSecOps** GitHub Actions → Trivy → Lambda → Bedrock → Security Hub 파이프라인 구축

이 포트폴리오:
- 실무 프로젝트의 한계(Node.js 코드 제어, 하드코딩 300줄, 컨텍스트 수동 전달)를 극복
- 최신 AI 기술(CrewAI, LangChain, Tool Calling, Agentic Workflow)로 재설계
- 확장 가능하고 유지보수가 쉬운 시스템 구현

---

## 🤝 Contributing

이 프로젝트는 포트폴리오 목적으로 제작되었습니다. 데모 취약점 애플리케이션은 절대 프로덕션 환경에 배포하지 마세요.

---

**🌐 Quick Access**
- Security Agent UI: http://localhost:8501
- Langfuse Dashboard: http://localhost:3001

**🛡️ AI Security Agent Portfolio** - Agentic Workflow로 재구성한 DevSecOps 자동화 시스템