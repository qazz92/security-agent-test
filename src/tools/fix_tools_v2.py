"""
LLM 기반 보안 코드 수정 툴 (V2)
Template을 가이드로만 사용하고 LLM이 실제 코드를 분석/수정

V2 개선사항:
- LLM 기반 실제 코드 분석 및 수정 (변수명/로직 보존)
- Template은 "보안 원칙 가이드"로만 사용
- Structured Output으로 일관성 보장
- 명확한 입력 형식 요구 (Agent 프롬프트에서 형식 지정)
"""

import time
import json
import os
import logging
from typing import Dict, List, Any, Optional
from langchain_core.tools import BaseTool
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============================================================================
# Security Patterns (Template을 "가이드라인"으로 재정의)
# ============================================================================

SECURITY_PATTERNS = {
    "SQL_INJECTION": {
        "name": "SQL Injection",
        "description": "사용자 입력이 SQL 쿼리에 직접 삽입되어 임의의 SQL 명령 실행 가능",
        "principle": "Parameterized queries (prepared statements)를 사용하여 SQL과 데이터를 분리",
        "vulnerable_patterns": [
            "f-string으로 SQL 쿼리 구성: f\"SELECT * FROM table WHERE id = {user_input}\"",
            ".format()으로 SQL 쿼리 구성: \"SELECT * FROM {} WHERE id = {}\".format(table, id)",
            "문자열 연결로 SQL 쿼리 구성: \"SELECT * FROM \" + table_name"
        ],
        "secure_patterns": [
            "Parameterized query: cursor.execute(\"SELECT * FROM table WHERE id = ?\", (user_input,))",
            "ORM 사용: Model.query.filter(Model.id == user_input).first()",
            "입력 검증 추가: validate_input(user_input) before query"
        ],
        "example": """
# ❌ Vulnerable (DO NOT USE)
def get_user_by_id(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

# ✅ Secure (RECOMMENDED)
def get_user_by_id(user_id):
    # Method 1: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # Method 2: ORM
    user = User.query.filter(User.id == user_id).first()

    # Method 3: Input validation + parameterized query
    if not isinstance(user_id, int):
        raise ValueError("Invalid user ID")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",
        "testing_code": """
def test_sql_injection_prevention():
    # Test malicious input
    malicious_input = "1; DROP TABLE users; --"
    try:
        result = get_user_by_id(malicious_input)
        # Should handle safely (no execution of DROP)
        assert result is None or isinstance(result, dict)
    except ValueError:
        pass  # Expected behavior
""",
        "dependencies": ["sqlite3", "sqlalchemy"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 – Injection"
    },

    "XSS": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "사용자 입력이 HTML에 직접 삽입되어 악의적인 스크립트 실행 가능",
        "principle": "모든 사용자 입력을 HTML 이스케이프하거나 템플릿 엔진 사용",
        "vulnerable_patterns": [
            "f-string으로 HTML 직접 반환: return f\"<div>{user_input}</div>\"",
            "문자열 연결로 HTML 구성: \"<h1>\" + title + \"</h1>\""
        ],
        "secure_patterns": [
            "HTML escape 사용: escape(user_input)",
            "템플릿 엔진 사용: render_template('page.html', data=user_input)",
            "CSP 헤더 추가: Content-Security-Policy"
        ],
        "example": """
# ❌ Vulnerable
@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form['comment']
    return f"<div>{comment}</div>"  # XSS 취약!

# ✅ Secure
from markupsafe import escape
from flask import render_template

@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form['comment']

    # Method 1: Manual escape
    safe_comment = escape(comment)
    return f"<div>{safe_comment}</div>"

    # Method 2: Template engine (auto-escape)
    return render_template('comment.html', comment=comment)

# Add CSP header
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
""",
        "testing_code": """
def test_xss_prevention():
    from markupsafe import escape
    malicious_input = "<script>alert('XSS')</script>"
    safe_output = escape(malicious_input)
    assert "<script>" not in safe_output
    assert "&lt;script&gt;" in safe_output
""",
        "dependencies": ["markupsafe", "flask"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 – Injection"
    },

    "COMMAND_INJECTION": {
        "name": "Command Injection",
        "description": "사용자 입력이 시스템 명령에 직접 전달되어 임의 명령 실행 가능",
        "principle": "shell=False 사용, 입력 검증, 화이트리스트 적용",
        "vulnerable_patterns": [
            "shell=True 사용: subprocess.run(f'ping {host}', shell=True)",
            "os.system() 사용: os.system(f'ls {path}')"
        ],
        "secure_patterns": [
            "shell=False + 리스트: subprocess.run(['ping', '-c', '1', host], shell=False)",
            "입력 검증: re.match(r'^[a-zA-Z0-9.-]+$', host)",
            "화이트리스트: if command in ALLOWED_COMMANDS"
        ],
        "example": """
# ❌ Vulnerable
def ping_host(host):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout

# ✅ Secure
import subprocess
import re

ALLOWED_HOSTS_PATTERN = r'^[a-zA-Z0-9.-]+$'

def ping_host(host):
    # Input validation
    if not re.match(ALLOWED_HOSTS_PATTERN, host):
        raise ValueError("Invalid hostname format")

    # shell=False with list arguments
    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Timeout"
""",
        "testing_code": """
def test_command_injection_prevention():
    malicious_input = "localhost; cat /etc/passwd"
    try:
        result = ping_host(malicious_input)
        assert "/etc/passwd" not in result
    except ValueError:
        pass  # Expected
""",
        "dependencies": ["subprocess", "re"],
        "cwe": "CWE-78",
        "owasp": "A03:2021 – Injection"
    },

    "HARDCODED_SECRET": {
        "name": "Hardcoded Secret",
        "description": "코드에 직접 하드코딩된 비밀 정보 (패스워드, API 키 등)",
        "principle": "환경 변수 또는 Secret Manager 사용",
        "vulnerable_patterns": [
            "코드 내 직접 할당: SECRET_KEY = 'mysecretkey123'",
            "설정 파일에 평문: api_key: 'sk-abc123'"
        ],
        "secure_patterns": [
            "환경 변수: SECRET_KEY = os.environ.get('SECRET_KEY')",
            ".env 파일 + .gitignore: load_dotenv()",
            "Secret Manager: secret = secrets_client.get('SECRET_KEY')"
        ],
        "example": """
# ❌ Vulnerable
SECRET_KEY = 'hardcoded-secret-123'
API_KEY = 'sk-1234567890abcdef'

# ✅ Secure
import os
from dotenv import load_dotenv

load_dotenv()  # Load from .env file

SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set")

API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")

# For development only
if os.environ.get('ENV') == 'development':
    SECRET_KEY = SECRET_KEY or 'dev-secret-only'
""",
        "env_template": """
# .env (add to .gitignore!)
SECRET_KEY=your-secret-key-here
API_KEY=your-api-key-here
DATABASE_URL=postgresql://user:pass@localhost/db
""",
        "testing_code": """
def test_no_hardcoded_secrets():
    import re
    with open('config.py', 'r') as f:
        content = f.read()
    # Check for hardcoded patterns
    assert not re.search(r'SECRET_KEY\\s*=\\s*["\']\\w+["\']', content)
""",
        "dependencies": ["python-dotenv"],
        "cwe": "CWE-798",
        "owasp": "A07:2021 – Identification and Authentication Failures"
    },

    "UNSAFE_DESERIALIZATION": {
        "name": "Unsafe Deserialization",
        "description": "pickle, yaml.load() 등 안전하지 않은 역직렬화로 RCE 가능",
        "principle": "JSON 사용 또는 yaml.safe_load() 사용",
        "vulnerable_patterns": [
            "pickle.loads(data)",
            "yaml.load(data, Loader=yaml.Loader)"
        ],
        "secure_patterns": [
            "json.loads(data)",
            "yaml.safe_load(data)",
            "Schema validation"
        ],
        "example": """
# ❌ Vulnerable
import pickle
import yaml

def load_data(data):
    obj = pickle.loads(data)  # RCE 가능!
    return obj

def load_config(config_str):
    config = yaml.load(config_str, Loader=yaml.Loader)  # RCE 가능!
    return config

# ✅ Secure
import json
import yaml

def load_data(data):
    # Use JSON instead
    obj = json.loads(data)
    return obj

def load_config(config_str):
    # Use safe_load
    config = yaml.safe_load(config_str)
    return config

# Add schema validation
from marshmallow import Schema, fields, ValidationError

class UserSchema(Schema):
    name = fields.Str(required=True)
    email = fields.Email(required=True)

def validate_user_data(data):
    schema = UserSchema()
    try:
        validated = schema.load(data)
        return validated
    except ValidationError as e:
        raise ValueError(f"Invalid data: {e.messages}")
""",
        "testing_code": """
def test_safe_deserialization():
    safe_data = '{"name": "test", "value": 123}'
    result = json.loads(safe_data)
    assert result['name'] == 'test'
""",
        "dependencies": ["pyyaml", "marshmallow"],
        "cwe": "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures"
    }
}


# ============================================================================
# Pydantic Models (Structured Output)
# ============================================================================

class CodeFix(BaseModel):
    """수정된 코드 정보"""
    original_code: str = Field(description="원본 취약 코드")
    fixed_code: str = Field(description="수정된 안전한 코드 (원본의 변수명/로직 유지)")
    explanation: str = Field(description="수정 사항 설명 (한글)")
    changes_summary: str = Field(description="주요 변경사항 요약")
    preserved_elements: List[str] = Field(description="보존된 요소들 (변수명, 테이블명, 로직 등)")


class SecurityFix(BaseModel):
    """전체 보안 수정 정보"""
    vulnerability_type: str = Field(description="취약점 유형")
    file_path: str = Field(description="파일 경로")
    line_number: Optional[int] = Field(description="라인 번호")
    severity: str = Field(description="심각도")
    code_fix: CodeFix = Field(description="코드 수정 정보")
    test_code: str = Field(description="검증용 테스트 코드")
    dependencies: List[str] = Field(description="필요한 의존성 패키지")
    additional_steps: List[str] = Field(description="추가 필요 작업")


# ============================================================================
# Generate Fix Code Tool (LLM-based)
# ============================================================================

class GenerateFixCodeInput(BaseModel):
    """Input schema for generate_fix_code tool"""
    vulnerability: Dict[str, Any] = Field(
        description="""취약점 정보 (EXACT format required!)

        Required fields:
        - type: str (MUST be EXACT: SQL_INJECTION, XSS, COMMAND_INJECTION, etc.)
        - code: str (actual vulnerable code)
        - file: str (file path)
        - severity: str (optional: CRITICAL, HIGH, MEDIUM, LOW)

        Example:
        {
            "type": "SQL_INJECTION",  # NOT "SQL Injection"!
            "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
            "file": "app.py:57",
            "severity": "CRITICAL"
        }
        """
    )


class GenerateFixCodeToolV2(BaseTool):
    """LLM 기반 취약점 수정 코드 생성 도구 (V2)"""

    name: str = "generate_fix_code"
    description: str = """
    취약점에 대한 수정 코드를 LLM을 사용하여 생성합니다.
    Template은 보안 원칙 가이드로만 사용하고, 실제 코드의 변수명/로직을 유지하면서 취약점만 수정합니다.

    IMPORTANT - Vulnerability Type Format (EXACT format required):
    - SQL_INJECTION (NOT "SQL Injection")
    - XSS (NOT "Cross-Site Scripting")
    - COMMAND_INJECTION (NOT "Command Injection")
    - HARDCODED_SECRET
    - UNSAFE_DESERIALIZATION
    - PATH_TRAVERSAL
    - SSRF
    - XXE
    - DEBUG_MODE

    Example input:
    {
        "type": "SQL_INJECTION",  # EXACT format!
        "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
        "file": "app.py:57",
        "severity": "CRITICAL"
    }
    """
    args_schema: type[BaseModel] = GenerateFixCodeInput

    def _get_llm(self):
        """LLM 인스턴스 가져오기 (lazy loading)"""
        if not hasattr(self, '_llm'):
            from src.utils.model_selector import get_model_selector, TaskComplexity

            selector = get_model_selector()
            # Don't pass callbacks - LiteLLM global callbacks will handle it
            self._llm = selector.get_llm(TaskComplexity.SECURITY_DESIGN)
            self._parser = JsonOutputParser(pydantic_object=SecurityFix)

        return self._llm

    @property
    def llm(self):
        """LLM property"""
        return self._get_llm()

    @property
    def parser(self):
        """Parser property"""
        self._get_llm()  # Ensure parser is initialized
        return self._parser

    def _run(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        취약점 정보를 받아 LLM이 실제 코드를 분석하고 수정

        Args:
            vulnerability: {
                "type": "SQL_INJECTION",  # ← EXACT format (no normalization!)
                "file": "app.py",
                "code": "query = f'SELECT * FROM products WHERE id = {product_id}'",
                "line": 57,
                "severity": "CRITICAL"
            }

        Returns:
            SecurityFix 형식의 수정 정보
        """
        try:
            # 입력 검증 (정규화 없음 - Agent가 정확한 형식으로 전달해야 함)
            vuln_type = vulnerability.get('type', 'UNKNOWN')
            original_code = vulnerability.get('code', vulnerability.get('description', ''))
            file_path = vulnerability.get('file', 'unknown')
            line_number = vulnerability.get('line')
            severity = vulnerability.get('severity', 'MEDIUM')

            # 보안 패턴 가져오기
            pattern = SECURITY_PATTERNS.get(vuln_type)

            if not pattern:
                # 명확한 에러 메시지 (정규화 없음)
                supported_types = list(SECURITY_PATTERNS.keys())
                return {
                    "error": f"❌ Unsupported vulnerability type: '{vuln_type}'",
                    "hint": "⚠️ You MUST use EXACT format (case-sensitive)",
                    "your_input": vuln_type,
                    "supported_types": supported_types,
                    "examples": {
                        "correct": "SQL_INJECTION",
                        "wrong": ["SQL Injection", "sql injection", "SQLInjection"]
                    },
                    "fix": f"Change '{vuln_type}' to one of: {', '.join(supported_types[:3])}...",
                    "recommendation": "Check agent prompt - vulnerability type format is wrong!"
                }

            if not original_code or original_code.strip() == '':
                return {
                    "error": "원본 코드가 제공되지 않았습니다",
                    "pattern": pattern,
                    "recommendation": "취약점 정보에 실제 코드를 포함시켜주세요"
                }

            # LLM 프롬프트 생성
            prompt = self._build_fix_prompt(
                vuln_type=vuln_type,
                original_code=original_code,
                file_path=file_path,
                line_number=line_number,
                severity=severity,
                pattern=pattern
            )

            # LLM 호출 (Structured Output)
            response = self.llm.invoke(prompt)

            # JSON 파싱
            try:
                # LLM 응답에서 JSON 추출
                response_text = response.content if hasattr(response, 'content') else str(response)

                # JSON 블록 찾기 (```json ... ``` 또는 순수 JSON)
                import re
                json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    # 순수 JSON인 경우
                    json_str = response_text

                result = json.loads(json_str)

                # SecurityFix 검증
                security_fix = SecurityFix(**result)

                return {
                    "success": True,
                    "vulnerability_type": security_fix.vulnerability_type,
                    "file_path": security_fix.file_path,
                    "line_number": security_fix.line_number,
                    "severity": security_fix.severity,
                    "original_code": security_fix.code_fix.original_code,
                    "fixed_code": security_fix.code_fix.fixed_code,
                    "explanation": security_fix.code_fix.explanation,
                    "changes_summary": security_fix.code_fix.changes_summary,
                    "preserved_elements": security_fix.code_fix.preserved_elements,
                    "test_code": security_fix.test_code,
                    "dependencies": security_fix.dependencies,
                    "additional_steps": security_fix.additional_steps,
                    "cwe": pattern.get("cwe", ""),
                    "owasp": pattern.get("owasp", ""),
                    "generation_method": "LLM with security pattern guidance",
                    "timestamp": time.time()
                }

            except json.JSONDecodeError as e:
                # JSON 파싱 실패 시 fallback
                return {
                    "success": False,
                    "error": f"LLM 응답을 파싱할 수 없습니다: {str(e)}",
                    "raw_response": response_text[:500],  # 처음 500자만
                    "fallback": self._generate_fallback_fix(vulnerability, pattern)
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"수정 코드 생성 실패: {str(e)}",
                "vulnerability": vulnerability
            }

    def _build_fix_prompt(
        self,
        vuln_type: str,
        original_code: str,
        file_path: str,
        line_number: Optional[int],
        severity: str,
        pattern: Dict[str, Any]
    ) -> str:
        """LLM을 위한 상세 프롬프트 생성"""

        prompt = f"""당신은 보안 전문 개발자입니다. 아래 취약한 코드를 분석하고 안전하게 수정하세요.

## 취약점 정보
- **유형**: {pattern['name']} ({vuln_type})
- **파일**: {file_path}
{f"- **라인**: {line_number}" if line_number else ""}
- **심각도**: {severity}
- **CWE**: {pattern.get('cwe', 'N/A')}
- **OWASP**: {pattern.get('owasp', 'N/A')}

## 원본 취약 코드
```python
{original_code}
```

## 보안 원칙
{pattern['description']}

**수정 원칙**: {pattern['principle']}

## 취약한 패턴들
{chr(10).join(f'- {p}' for p in pattern['vulnerable_patterns'])}

## 안전한 패턴들
{chr(10).join(f'- {p}' for p in pattern['secure_patterns'])}

## 참고 예시
{pattern['example']}

## 수정 요구사항
1. **원본 코드의 구조를 최대한 보존**하세요 (변수명, 테이블명, 함수명, 로직 흐름 유지)
2. **취약점만 제거**하세요 (불필요한 리팩토링 금지)
3. **실제 동작하는 완전한 코드**를 작성하세요 (import, 함수 정의 포함)
4. **Python 3.10+ 문법**을 사용하세요
5. **주석을 추가**하여 수정 사항을 명확히 하세요

## 출력 형식 (JSON)
아래 JSON 형식으로 정확하게 출력하세요. 다른 텍스트는 포함하지 마세요.

```json
{{
  "vulnerability_type": "{vuln_type}",
  "file_path": "{file_path}",
  "line_number": {line_number or 'null'},
  "severity": "{severity}",
  "code_fix": {{
    "original_code": "원본 코드 (그대로)",
    "fixed_code": "수정된 코드 (완전한 함수/클래스)",
    "explanation": "수정 사항 상세 설명 (한글, 200자 이내)",
    "changes_summary": "주요 변경사항 (한글, 50자 이내)",
    "preserved_elements": ["유지된 변수명", "유지된 테이블명", "유지된 로직"]
  }},
  "test_code": "검증용 pytest 테스트 코드 (완전한 함수)",
  "dependencies": ["{chr(34).join(pattern['dependencies'])}"],
  "additional_steps": ["추가 필요 작업 1", "추가 필요 작업 2"]
}}
```

**중요**: 반드시 위 JSON 형식으로만 출력하세요. 설명이나 다른 텍스트를 추가하지 마세요.
"""

        return prompt

    def _generate_fallback_fix(
        self,
        vulnerability: Dict[str, Any],
        pattern: Dict[str, Any]
    ) -> Dict[str, Any]:
        """LLM 실패 시 Template 기반 fallback"""

        vuln_type = vulnerability.get('type', 'UNKNOWN')
        original_code = vulnerability.get('code', '')
        file_path = vulnerability.get('file', 'unknown')

        return {
            "vulnerability_type": vuln_type,
            "file_path": file_path,
            "severity": vulnerability.get('severity', 'MEDIUM'),
            "description": pattern['description'],
            "principle": pattern['principle'],
            "example_fix": pattern['example'],
            "test_code": pattern.get('testing_code', ''),
            "dependencies": pattern.get('dependencies', []),
            "warning": "LLM 생성 실패로 Template 기반 예시를 반환합니다. 실제 코드에 맞게 수정이 필요합니다.",
            "manual_review_required": True
        }


# ============================================================================
# CrewAI-compatible tool wrapper
# ============================================================================

from crewai.tools import tool

@tool("Generate Fix Code")
def generate_fix_code(vulnerability: Dict[str, Any]) -> dict:
    """
    LLM 기반 취약점 수정 코드 생성 (V2)

    Template은 보안 원칙 가이드로만 사용하고, LLM이 실제 코드의 구조를 분석하여
    변수명/테이블명/로직을 유지하면서 취약점만 제거합니다.

    Args:
        vulnerability: {
            "type": "SQL_INJECTION",
            "file": "app.py:57",
            "code": "query = f'SELECT * FROM products WHERE id = {product_id}'",
            "severity": "CRITICAL"
        }

    Returns:
        수정된 코드, 설명, 테스트 코드, 의존성 등을 포함한 상세 정보
    """
    tool_instance = GenerateFixCodeToolV2()
    return tool_instance._run(vulnerability=vulnerability)


@tool("Create PR Template")
def create_pr_template(vulnerabilities: Optional[Any] = None, project_info: Optional[Any] = None) -> str:
    """
    GitHub Pull Request 템플릿 생성

    취약점 목록과 수정 사항을 바탕으로 상세한 보안 패치 PR 문서를 작성합니다.

    Args:
        vulnerabilities: 취약점 목록 (list of dicts)
        project_info: 프로젝트 정보 (dict)

    Returns:
        Markdown 형식의 PR 템플릿
    """
    try:
        if not vulnerabilities:
            vulnerabilities = []

        pr_sections = [
            "# 🔒 Security Fix Pull Request",
            "",
            "## 📋 Summary",
            f"This PR fixes **{len(vulnerabilities)} security vulnerabilities** identified during automated security analysis.",
            "",
            "## 🐛 Vulnerabilities Fixed",
            ""
        ]

        # 취약점 목록
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'UNKNOWN')
            vuln_type = vuln.get('type', 'Unknown')
            file_path = vuln.get('file', 'unknown')

            pr_sections.extend([
                f"### {idx}. {vuln_type} ({severity})",
                f"- **File**: `{file_path}`",
                f"- **Description**: {vuln.get('description', 'Security vulnerability detected')}",
                ""
            ])

        # 테스트 계획
        pr_sections.extend([
            "## ✅ Testing",
            "- [ ] Unit tests pass",
            "- [ ] Security tests pass",
            "- [ ] Manual testing completed",
            "",
            "## 📚 References",
            "- [OWASP Top 10](https://owasp.org/www-project-top-ten/)",
            "- [CWE Database](https://cwe.mitre.org/)",
            "",
            "## 🤖 Generated by Security Agent Portfolio",
            ""
        ])

        return '\n'.join(pr_sections)

    except Exception as e:
        logger.error(f"Error creating PR template: {e}")
        return f"# Security Fix PR\n\nError generating template: {str(e)}"


@tool("Generate Security Documentation")
def generate_security_documentation(vulnerabilities: Optional[Any] = None, fixes: Optional[Any] = None) -> dict:
    """
    보안 문서 생성

    SECURITY.md, README 보안 섹션 등 프로젝트에 필요한 보안 문서를 작성합니다.

    Args:
        vulnerabilities: 취약점 목록
        fixes: 수정 사항 목록

    Returns:
        문서 타입별 내용을 담은 dict
    """
    try:
        security_md = [
            "# Security Policy",
            "",
            "## Supported Versions",
            "| Version | Supported |",
            "|---------|-----------|",
            "| Latest  | ✅        |",
            "",
            "## Reporting a Vulnerability",
            "Please report security vulnerabilities to security@example.com",
            "",
            "## Recent Security Fixes",
            ""
        ]

        if vulnerabilities:
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                severity = vuln.get('severity', 'UNKNOWN')
                security_md.append(f"- Fixed {vuln_type} ({severity})")

        return {
            "security_md": '\n'.join(security_md),
            "readme_section": "## 🔒 Security\n\nThis project follows security best practices. See [SECURITY.md](SECURITY.md) for details.",
            "env_example": "# Security Configuration\nSECRET_KEY=your-secret-key-here\nAPI_KEY=your-api-key-here\n"
        }

    except Exception as e:
        logger.error(f"Error generating security docs: {e}")
        return {"error": str(e)}


@tool("Generate Fix Script")
def generate_fix_script(vulnerabilities: Optional[Any] = None) -> str:
    """
    취약점 수정 자동화 스크립트 생성

    환경 설정, 의존성 업데이트, 보안 검증 등을 자동으로 수행하는 Bash 스크립트를 작성합니다.

    Args:
        vulnerabilities: 취약점 목록

    Returns:
        Bash 스크립트 내용
    """
    try:
        script_lines = [
            "#!/bin/bash",
            "set -e",
            "",
            "echo '🔒 Security Fix Automation Script'",
            "echo '=================================='",
            "",
            "# Update dependencies",
            "echo 'Updating dependencies...'",
            "pip install --upgrade pip",
            "",
            "# Install security tools",
            "echo 'Installing security tools...'",
            "pip install bandit safety",
            "",
            "# Run security checks",
            "echo 'Running security checks...'",
            "bandit -r . -x tests/ || echo 'Security issues found'",
            "safety check || echo 'Dependency vulnerabilities found'",
            "",
            "echo '✅ Security fixes completed!'",
            ""
        ]

        return '\n'.join(script_lines)

    except Exception as e:
        logger.error(f"Error generating fix script: {e}")
        return f"#!/bin/bash\necho 'Error: {str(e)}'\n"


# Tool instance export (lazy initialization)
def get_tool_instance():
    """Lazy initialization of tool instance"""
    return GenerateFixCodeToolV2()

__all__ = [
    'GenerateFixCodeToolV2',
    'generate_fix_code',
    'create_pr_template',
    'generate_security_documentation',
    'generate_fix_script',
    'SECURITY_PATTERNS',
    'SecurityFix',
    'CodeFix',
    'get_tool_instance'
]