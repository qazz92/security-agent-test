# Prompt Management System

프롬프트를 MD 파일로 관리하여 유지보수성을 향상시키는 시스템입니다.

## 📁 디렉토리 구조

```
src/prompts/
├── README.md                        # 이 파일
├── security_agent/
│   ├── system.md                    # Security Agent 시스템 프롬프트
│   └── user.md                      # Security Agent 사용자 프롬프트 (템플릿)
└── remediation_agent/
    ├── system.md                    # Remediation Agent 시스템 프롬프트
    └── user.md                      # Remediation Agent 사용자 프롬프트 (템플릿)
```

## 🎯 설계 원칙

1. **코드와 프롬프트 분리**: 프롬프트 수정 시 Python 코드 변경 불필요
2. **버전 관리**: Frontmatter에 버전 정보 기록
3. **변수 지원**: Jinja2 템플릿으로 동적 콘텐츠 생성
4. **폴백 메커니즘**: 프롬프트 로드 실패 시 안전한 기본값 사용
5. **핫 리로드**: 개발 중 캐시 비활성화로 즉시 반영

## 📝 프롬프트 파일 형식

### Frontmatter (YAML)

```markdown
---
version: 1.0
agent: security_agent
role: system
description: Security analysis agent system prompt
variables:
  - project_path
  - user_query
updated: 2025-09-30
---

# 실제 프롬프트 내용 시작
You are a security engineer...
```

### 변수 치환 (Jinja2)

```markdown
Analyze project at: {{ project_path }}
User requested: {{ user_query }}

Total vulnerabilities: {{ vulnerability_count }}
```

## 🔧 사용법

### 1. PromptManager 직접 사용

```python
from src.utils.prompt_manager import PromptManager

# 인스턴스 생성
manager = PromptManager()

# 시스템 프롬프트 로드 (변수 없음)
system_prompt = manager.load_prompt('security_agent', 'system')

# 사용자 프롬프트 로드 (변수 포함)
user_prompt = manager.load_prompt(
    'security_agent',
    'user',
    variables={
        'project_path': '/path/to/project',
        'user_query': 'Find SQL injection vulnerabilities'
    }
)
```

### 2. 편의 함수 사용 (권장)

```python
from src.utils.prompt_manager import load_prompt

# 싱글톤 인스턴스 자동 사용
prompt = load_prompt(
    'remediation_agent',
    'user',
    variables={
        'vulnerability_count': 12,
        'github_repo_url': 'https://github.com/user/repo'
    }
)
```

### 3. Agent에서 사용 (실제 예시)

```python
from src.utils.prompt_manager import load_prompt, PromptLoadError

try:
    system_prompt = load_prompt('security_agent', 'system')
    logger.info("✅ Loaded system prompt from MD file")
except PromptLoadError as e:
    logger.error(f"❌ Failed to load prompt: {e}")
    # 폴백: 하드코딩된 기본 프롬프트 사용
    system_prompt = "You are a security engineer..."
```

## 🛠️ 고급 기능

### 캐시 관리

```python
from src.utils.prompt_manager import get_prompt_manager

manager = get_prompt_manager()

# 캐시 초기화 (프롬프트 파일 수정 후)
manager.clear_cache()

# 캐시 비활성화 (개발 중 즉시 반영)
manager.disable_cache()

# 캐시 활성화 (프로덕션 환경)
manager.enable_cache()
```

### 메타데이터 조회

```python
metadata = manager.get_prompt_metadata('security_agent', 'system')
print(f"Version: {metadata['version']}")
print(f"Updated: {metadata['updated']}")
print(f"Variables: {metadata.get('variables', [])}")
```

### 프롬프트 목록 조회

```python
# 전체 프롬프트 목록
all_prompts = manager.list_prompts()

# 특정 에이전트의 프롬프트만
security_prompts = manager.list_prompts('security_agent')

for prompt in security_prompts:
    print(f"{prompt['agent']}/{prompt['type']} - {prompt['size']} bytes")
```

## 📋 프롬프트 작성 가이드

### 1. System Prompt (시스템 프롬프트)

**목적**: 에이전트의 역할, 책임, 행동 지침 정의

**특징**:
- 변수 없음 (정적)
- 에이전트 초기화 시 1회 로드
- 에이전트의 "정체성" 정의

**작성 팁**:
```markdown
---
version: 1.0
agent: my_agent
role: system
---

You are a [ROLE] specialized in [DOMAIN].

Your responsibilities:
1. [RESPONSIBILITY_1]
2. [RESPONSIBILITY_2]

Workflow:
1. [STEP_1]
2. [STEP_2]

Guidelines:
- [GUIDELINE_1]
- [GUIDELINE_2]
```

### 2. User Prompt (사용자 프롬프트)

**목적**: 구체적인 작업 요청 및 컨텍스트 제공

**특징**:
- Jinja2 변수 사용 가능
- 실행 시마다 동적으로 생성
- 구체적인 입력 데이터 포함

**작성 팁**:
```markdown
---
version: 1.0
agent: my_agent
role: user
variables:
  - variable_1
  - variable_2
---

Perform analysis on: {{ project_path }}

Requirements:
- Total items: {{ item_count }}
- Target: {{ target_name }}

Please complete the following tasks:
1. [TASK_1]
2. [TASK_2]
```

## 🚨 주의사항

### 1. 변수 검증

메타데이터에 `variables`를 명시하면 자동 검증:

```markdown
---
variables:
  - required_var_1
  - required_var_2
---
```

누락된 변수가 있으면 Warning 로그 발생 (실행은 계속됨)

### 2. Jinja2 문법

```markdown
# 변수
{{ variable_name }}

# 조건문
{% if condition %}
  ...
{% endif %}

# 반복문
{% for item in items %}
  - {{ item }}
{% endfor %}
```

### 3. 이스케이프

중괄호를 문자 그대로 사용하려면:

```markdown
# Jinja2 변수로 해석됨
Use {{ variable }}

# 문자 그대로 출력하려면
Use {{ '{{' }} variable {{ '}}' }}
```

## 🔄 마이그레이션 체크리스트

기존 하드코딩된 프롬프트를 MD 파일로 이전:

- [ ] 1. 에이전트별 디렉토리 생성 (`src/prompts/{agent_name}/`)
- [ ] 2. `system.md` 파일 생성 (시스템 프롬프트)
- [ ] 3. `user.md` 파일 생성 (사용자 프롬프트)
- [ ] 4. Frontmatter 작성 (버전, 변수 목록 등)
- [ ] 5. 하드코딩된 f-string을 Jinja2 템플릿으로 변환
- [ ] 6. Agent 코드에 `load_prompt()` 추가
- [ ] 7. 폴백 로직 구현 (안전성)
- [ ] 8. 로딩 로그 확인 (✅ 또는 ❌)
- [ ] 9. 기능 테스트 (정상 동작 확인)
- [ ] 10. 하드코딩된 프롬프트 제거 (선택)

## 🎓 Best Practices

### 1. 버전 관리

프롬프트 변경 시 버전 업데이트:

```markdown
---
version: 1.1  # 1.0 → 1.1
updated: 2025-10-01
changelog: Added PR creation priority
---
```

### 2. 설명 추가

복잡한 프롬프트에는 주석:

```markdown
# 🔴 CRITICAL: This step is mandatory
Do not skip this step under any circumstances.

# 📝 NOTE: Optional optimization
You may optionally perform this for better results.
```

### 3. A/B 테스트

프롬프트 실험:

```
prompts/
  remediation_agent/
    system.md           # 현재 버전
    system_v2.md        # 실험 버전
    system_baseline.md  # 백업
```

```python
# A/B 테스트
prompt_version = os.environ.get('PROMPT_VERSION', 'system')
system_prompt = load_prompt('remediation_agent', prompt_version)
```

### 4. 문서화

프롬프트 변경 시 Git commit message에 이유 명시:

```bash
git commit -m "prompts: Increase PR creation priority for remediation_agent

- Moved PR creation to top of workflow
- Made other documentation steps optional
- Reason: LLM was hitting max_iterations before creating PR"
```

## 🐛 트러블슈팅

### 문제: 프롬프트가 로드되지 않음

**증상**:
```
❌ Failed to load system prompt from MD: Prompt file not found
```

**해결**:
1. 파일 경로 확인: `src/prompts/{agent_name}/{type}.md`
2. 파일 존재 확인: `ls -la src/prompts/`
3. 디렉토리 구조 확인

### 문제: 변수 치환이 안됨

**증상**:
```
{{ variable_name }} 텍스트 그대로 출력됨
```

**해결**:
1. `variables` 딕셔너리에 해당 키 포함 확인
2. Jinja2 문법 확인 (중괄호 2개: `{{ }}`)
3. 로그에서 "Missing template variables" 확인

### 문제: 폴백 프롬프트가 사용됨

**증상**:
```
⚠️ Falling back to hardcoded system prompt
```

**해결**:
1. 원인 로그 확인 (PromptLoadError 메시지)
2. MD 파일 문법 오류 확인
3. 권한 문제 확인 (`chmod 644 *.md`)

## 📊 성능 고려사항

### 캐싱 전략

- **개발 환경**: 캐시 비활성화 (`disable_cache()`)
- **프로덕션**: 캐시 활성화 (기본값)
- **핫 리로드**: 파일 수정 시 `clear_cache()` 호출

### 메모리 사용량

- 프롬프트는 텍스트이므로 메모리 영향 미미
- 캐시에 모든 프롬프트 저장해도 < 1MB

## 🔗 관련 파일

- 구현: `src/utils/prompt_manager.py`
- 사용 예시: `src/agents/security_agent.py`
- 사용 예시: `src/agents/remediation_agent.py`

## 📖 참고 자료

- [Jinja2 문서](https://jinja.palletsprojects.com/)
- [YAML 문법](https://yaml.org/spec/1.2.2/)
- [LangChain Prompts](https://python.langchain.com/docs/modules/model_io/prompts/)

---

**마지막 업데이트**: 2025-09-30
**작성자**: Claude Code
**버전**: 1.0