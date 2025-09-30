"""
수정 방안 생성 툴들
취약점별 수정 코드 생성, PR 템플릿 생성 등
"""

import time
import json
from typing import Dict, List, Any, Optional

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


class GenerateFixCodeInput(BaseModel):
    """Input schema for generate_fix_code tool"""
    vulnerability: Optional[Any] = Field(
        default=None,
        description="취약점 정보 (딕셔너리, 문자열, 리스트 모두 가능 - 제공되지 않으면 샘플 수정 코드 반환)"
    )


class GenerateFixCodeTool(BaseTool):
    """취약점에 대한 수정 코드를 생성하는 도구"""

    name: str = "generate_fix_code"
    description: str = "취약점에 대한 수정 코드를 생성합니다. 취약점 정보를 제공하면 해당 취약점에 맞는 수정 코드를 생성하고, 제공하지 않으면 샘플 코드를 반환합니다."
    args_schema: type[BaseModel] = GenerateFixCodeInput

    def _run(self, vulnerability: Optional[Any] = None) -> Dict[str, str]:
        """
        취약점에 대한 수정 코드를 생성합니다.

        Args:
            vulnerability: 취약점 정보 (딕셔너리, 문자열, 리스트 모두 가능)

        Returns:
            수정 코드 및 설명
        """
        try:
            # 데이터 타입 정규화
            if vulnerability is None:
                vulnerability = {}
            elif isinstance(vulnerability, str):
                # 문자열인 경우 (예: "CVE-2023-30861") 타입만 추출
                vulnerability = {'type': vulnerability, 'file': 'unknown', 'code': ''}
            elif isinstance(vulnerability, list):
                # 리스트인 경우 첫 번째 항목 사용
                vulnerability = vulnerability[0] if vulnerability else {}
                if isinstance(vulnerability, str):
                    vulnerability = {'type': vulnerability, 'file': 'unknown', 'code': ''}
            elif not isinstance(vulnerability, dict):
                vulnerability = {}

            vuln_type = vulnerability.get('type', 'UNKNOWN')
            file_path = vulnerability.get('file', 'unknown')
            original_code = vulnerability.get('code', '')

            fix_templates = {
                "SQL Injection": {
                    "description": "Parameterized queries를 사용하여 SQL Injection을 방지합니다.",
                    "before_code": original_code,
                    "after_code": """
# 안전한 방법: Parameterized queries 사용
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# 또는 SQLAlchemy ORM 사용
user = User.query.filter(User.id == user_id).first()

# 입력 검증 추가
def validate_user_id(user_id):
    try:
        return int(user_id)
    except ValueError:
        raise ValueError("Invalid user ID")

# 사용 예시
try:
    validated_id = validate_user_id(user_id)
    cursor.execute("SELECT * FROM users WHERE id = ?", (validated_id,))
except ValueError as e:
    return "Invalid input", 400
""",
                    "dependencies": ["sqlite3", "sqlalchemy"],
                    "test_code": """
def test_sql_injection_prevention():
    # 악의적인 입력 테스트
    malicious_input = "1; DROP TABLE users; --"
    try:
        result = get_user_safe(malicious_input)
        assert result is None  # 안전하게 처리됨
    except ValueError:
        pass  # 예상된 동작
"""
                },
                "SQL_INJECTION": {
                    "description": "Parameterized queries를 사용하여 SQL Injection을 방지합니다.",
                    "before_code": original_code,
                    "after_code": """
# 안전한 방법: Parameterized queries 사용
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# 또는 SQLAlchemy ORM 사용
user = User.query.filter(User.id == user_id).first()

# 입력 검증 추가
def validate_user_id(user_id):
    try:
        return int(user_id)
    except ValueError:
        raise ValueError("Invalid user ID")

# 사용 예시
try:
    validated_id = validate_user_id(user_id)
    cursor.execute("SELECT * FROM users WHERE id = ?", (validated_id,))
except ValueError as e:
    return "Invalid input", 400
""",
                    "dependencies": ["sqlite3", "sqlalchemy"],
                    "test_code": """
def test_sql_injection_prevention():
    # 악의적인 입력 테스트
    malicious_input = "1; DROP TABLE users; --"
    try:
        result = get_user_safe(malicious_input)
        assert result is None  # 안전하게 처리됨
    except ValueError:
        pass  # 예상된 동작
"""
                },

                "XSS": {
                    "description": "HTML 이스케이프를 사용하여 XSS 공격을 방지합니다.",
                    "before_code": original_code,
                    "after_code": """
from markupsafe import escape
from html import escape as html_escape

# 안전한 방법: HTML 이스케이프 사용
@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form['comment']
    # 사용자 입력을 이스케이프
    safe_comment = escape(comment)
    return f"<h2>Your Comment</h2><div>{safe_comment}</div>"

# 또는 템플릿 엔진 사용 (Jinja2는 자동 이스케이프)
return render_template('comment.html', comment=comment)

# 추가 보안: Content Security Policy 헤더
@app.after_request
def after_request(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
""",
                    "dependencies": ["markupsafe", "flask"],
                    "test_code": """
def test_xss_prevention():
    malicious_input = "<script>alert('XSS')</script>"
    safe_output = escape(malicious_input)
    assert "<script>" not in safe_output
    assert "&lt;script&gt;" in safe_output
"""
                },

                "HARDCODED_SECRET": {
                    "description": "환경 변수를 사용하여 하드코딩된 시크릿을 제거합니다.",
                    "before_code": original_code,
                    "after_code": """
import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# 안전한 방법: 환경 변수 사용
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

API_KEY = os.environ.get('API_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

# 기본값과 함께 사용
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///default.db')

# 개발 환경에서만 기본값 허용
if os.environ.get('FLASK_ENV') == 'development':
    SECRET_KEY = SECRET_KEY or 'dev-secret-key'
else:
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be set in production")
""",
                    "dependencies": ["python-dotenv"],
                    "env_file_template": """
# .env 파일 예시 (이 파일은 .gitignore에 추가해야 함)
SECRET_KEY=your-secret-key-here
API_KEY=your-api-key-here
DB_PASSWORD=your-db-password-here
DATABASE_URL=postgresql://user:pass@localhost/dbname
""",
                    "gitignore_addition": "\n# Environment variables\n.env\n*.env\n"
                },

                "COMMAND_INJECTION": {
                    "description": "subprocess 사용 시 shell=False를 사용하고 입력을 검증합니다.",
                    "before_code": original_code,
                    "after_code": """
import subprocess
import shlex
import re

def safe_ping(host):
    # 입력 검증: 호스트명 형식 확인
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise ValueError("Invalid hostname format")

    # 안전한 방법: shell=False 사용
    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],  # 리스트 형태로 전달
            capture_output=True,
            text=True,
            timeout=10,  # 타임아웃 설정
            check=False  # 에러 시 예외 발생하지 않음
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Request timeout"
    except Exception as e:
        return f"Error: {str(e)}"

# 허용된 명령어만 실행
ALLOWED_COMMANDS = ['ping', 'nslookup', 'dig']

def execute_safe_command(command, args):
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command '{command}' not allowed")

    # 인자 검증
    safe_args = []
    for arg in args:
        if re.match(r'^[a-zA-Z0-9.-]+$', arg):
            safe_args.append(arg)
        else:
            raise ValueError(f"Invalid argument: {arg}")

    return subprocess.run([command] + safe_args, capture_output=True, text=True)
""",
                    "dependencies": ["subprocess", "re"],
                    "test_code": """
def test_command_injection_prevention():
    # 악의적인 입력 테스트
    malicious_input = "localhost; cat /etc/passwd"
    try:
        result = safe_ping(malicious_input)
        assert "/etc/passwd" not in result
    except ValueError:
        pass  # 예상된 동작
"""
                },

                "UNSAFE_DESERIALIZATION": {
                    "description": "안전한 직렬화 방법을 사용합니다.",
                    "before_code": original_code,
                    "after_code": """
import json
import yaml
from yaml import SafeLoader

# pickle 대신 JSON 사용 (안전함)
@app.route('/save_data', methods=['POST'])
def save_data():
    try:
        data = request.get_json()  # JSON 데이터 받기
        # JSON은 안전한 데이터 타입만 지원
        return jsonify({"status": "saved", "data": data})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# YAML의 경우 SafeLoader 사용
def load_config_safe(config_data):
    try:
        # 안전한 YAML 로더 사용
        config = yaml.load(config_data, Loader=SafeLoader)
        return config
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")

# 데이터 검증 추가
from marshmallow import Schema, fields, ValidationError

class UserDataSchema(Schema):
    name = fields.Str(required=True, validate=fields.Length(max=100))
    email = fields.Email(required=True)
    age = fields.Int(validate=fields.Range(min=0, max=150))

def validate_and_save_data(data):
    schema = UserDataSchema()
    try:
        validated_data = schema.load(data)
        return validated_data
    except ValidationError as e:
        raise ValueError(f"Invalid data: {e.messages}")
""",
                    "dependencies": ["pyyaml", "marshmallow"],
                    "test_code": """
def test_safe_deserialization():
    # 안전한 JSON 테스트
    safe_data = '{"name": "test", "value": 123}'
    result = json.loads(safe_data)
    assert result['name'] == 'test'

    # YAML 안전 로더 테스트
    safe_yaml = 'name: test\\nvalue: 123'
    result = yaml.load(safe_yaml, Loader=SafeLoader)
    assert result['name'] == 'test'
"""
                },

                "DEBUG_MODE": {
                    "description": "프로덕션에서 Debug 모드를 비활성화합니다.",
                    "before_code": original_code,
                    "after_code": """
import os

# 환경별 설정
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    DEBUG = True
    DATABASE_URL = os.environ.get('DEV_DATABASE_URL', 'sqlite:///dev.db')

class ProductionConfig(Config):
    DEBUG = False  # 프로덕션에서는 절대 True가 되면 안됨
    DATABASE_URL = os.environ.get('DATABASE_URL')

class TestingConfig(Config):
    TESTING = True
    DATABASE_URL = 'sqlite:///test.db'

# 환경에 따른 설정 선택
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

if __name__ == '__main__':
    env = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config[env])

    # 프로덕션에서는 절대 debug=True 사용 금지
    debug_mode = env == 'development'
    app.run(debug=debug_mode, host='127.0.0.1', port=5000)
""",
                    "dependencies": ["flask"],
                    "env_variables": {
                        "FLASK_ENV": "production",
                        "SECRET_KEY": "your-production-secret-key"
                    }
                }
            }

            if vuln_type not in fix_templates:
                return {
                    "error": f"No fix template available for vulnerability type: {vuln_type}",
                    "general_advice": "Manual security review recommended"
                }

            fix_data = fix_templates[vuln_type]

            return {
                "vulnerability_type": vuln_type,
                "file_path": file_path,
                "description": fix_data["description"],
                "before_code": fix_data["before_code"],
                "after_code": fix_data["after_code"],
                "dependencies": fix_data.get("dependencies", []),
                "test_code": fix_data.get("test_code", ""),
                "env_file_template": fix_data.get("env_file_template", ""),
                "gitignore_addition": fix_data.get("gitignore_addition", ""),
                "env_variables": fix_data.get("env_variables", {}),
                "fix_timestamp": time.time()
            }

        except Exception as e:
            return {"error": f"Fix code generation failed: {str(e)}"}


class CreatePRTemplateInput(BaseModel):
    """Input schema for create_pr_template tool"""
    vulnerabilities: Optional[Any] = Field(
        default=None,
        description="수정된 취약점 목록 또는 요약 정보 (리스트, 딕셔너리, 문자열 모두 가능)"
    )
    project_info: Optional[Any] = Field(
        default=None,
        description="프로젝트 정보 (Optional)"
    )


class CreatePRTemplateTool(BaseTool):
    """GitHub Pull Request 템플릿을 생성하는 도구"""

    name: str = "create_pr_template"
    description: str = "GitHub Pull Request 템플릿을 생성합니다. 취약점 목록과 프로젝트 정보를 바탕으로 보안 패치 PR 템플릿을 생성합니다."
    args_schema: type[BaseModel] = CreatePRTemplateInput

    def _run(self, vulnerabilities: Optional[Any] = None, project_info: Optional[Any] = None) -> str:
        """
        GitHub Pull Request 템플릿을 생성합니다.

        Args:
            vulnerabilities: 수정된 취약점 목록 또는 요약 정보
            project_info: 프로젝트 정보 (Optional)

        Returns:
            PR 템플릿 마크다운 텍스트
        """
        try:
            # 취약점 데이터 정규화
            if not vulnerabilities:
                vulnerabilities = []
            elif isinstance(vulnerabilities, str):
                # 문자열로 전달된 경우 파싱 시도
                return self._generate_template_from_string(vulnerabilities, project_info)
            elif not isinstance(vulnerabilities, list):
                vulnerabilities = [vulnerabilities]

            if not vulnerabilities:
                return "## 🔐 Security Patch\n\nNo vulnerabilities to fix."

            # 심각도별 카운트
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'UNKNOWN')
                if severity in severity_counts:
                    severity_counts[severity] += 1

            # 타입별 그룹화
            vulnerability_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'UNKNOWN')
                if vuln_type not in vulnerability_types:
                    vulnerability_types[vuln_type] = []
                vulnerability_types[vuln_type].append(vuln)

            # PR 제목 생성
            critical_count = severity_counts["CRITICAL"]
            high_count = severity_counts["HIGH"]
            total_count = len(vulnerabilities)

            if critical_count > 0:
                title = f"🚨 URGENT: Fix {critical_count} Critical Security Vulnerabilities"
            elif high_count > 0:
                title = f"🔐 Security: Fix {high_count} High Severity Vulnerabilities"
            else:
                title = f"🔐 Security: Fix {total_count} Security Issues"

            # PR 본문 생성
            template = f"""# {title}

## 📊 Summary
- **Total vulnerabilities fixed**: {total_count}
- **Critical**: {severity_counts['CRITICAL']} 🚨
- **High**: {severity_counts['HIGH']} ⚠️
- **Medium**: {severity_counts['MEDIUM']} 📋
- **Low**: {severity_counts['LOW']} 📝

## 🔧 Changes Made

"""

            # 취약점 타입별 수정 사항
            for vuln_type, vulns in vulnerability_types.items():
                type_description = {
                    "SQL_INJECTION": "SQL Injection 취약점",
                    "XSS": "Cross-Site Scripting (XSS) 취약점",
                    "HARDCODED_SECRET": "하드코딩된 시크릿",
                    "COMMAND_INJECTION": "Command Injection 취약점",
                    "UNSAFE_DESERIALIZATION": "안전하지 않은 역직렬화",
                    "DEBUG_MODE": "Debug 모드 설정 문제",
                    "INSECURE_NETWORK": "안전하지 않은 네트워크 설정"
                }.get(vuln_type, vuln_type)

                template += f"### {type_description}\n"
                template += f"- **수정된 파일 수**: {len(set(v.get('file', 'unknown') for v in vulns))}\n"
                template += f"- **수정된 이슈 수**: {len(vulns)}\n"

                # 주요 수정 사항
                if vuln_type == "SQL_INJECTION":
                    template += "- Parameterized queries 적용\n- 입력 검증 로직 추가\n"
                elif vuln_type == "XSS":
                    template += "- HTML 이스케이프 적용\n- CSP 헤더 추가\n"
                elif vuln_type == "HARDCODED_SECRET":
                    template += "- 환경 변수로 시크릿 이전\n- .env 파일 템플릿 생성\n"
                elif vuln_type == "COMMAND_INJECTION":
                    template += "- shell=False 옵션 적용\n- 입력 검증 및 화이트리스트 구현\n"

                template += "\n"

            # 파일별 변경사항
            file_changes = {}
            for vuln in vulnerabilities:
                file_path = vuln.get('file', 'unknown')
                if file_path not in file_changes:
                    file_changes[file_path] = []
                file_changes[file_path].append(vuln.get('type', 'UNKNOWN'))

            template += "## 📁 Modified Files\n\n"
            for file_path, changes in file_changes.items():
                template += f"- `{file_path}`: {', '.join(set(changes))}\n"

            template += f"""

## 🧪 Testing

### Automated Tests
- [ ] All existing tests pass
- [ ] New security tests added for fixed vulnerabilities
- [ ] Static security analysis clean (no new issues)

### Manual Testing
- [ ] Verified SQL injection prevention
- [ ] Tested XSS protection
- [ ] Confirmed secrets are properly externalized
- [ ] Validated input sanitization

### Security Scan Results
- [ ] Trivy scan shows no critical vulnerabilities
- [ ] SAST tools report clean
- [ ] Dependency vulnerabilities resolved

## 🔒 Security Checklist

- [ ] No hardcoded secrets in code
- [ ] All user inputs are validated and sanitized
- [ ] Database queries use parameterized statements
- [ ] Error messages don't expose sensitive information
- [ ] Security headers are properly configured
- [ ] Environment variables are documented in .env.example

## 📈 Impact Assessment

### Before
- **Total vulnerabilities**: {total_count}
- **Security score**: Low
- **Risk level**: {'Critical' if critical_count > 0 else 'High' if high_count > 0 else 'Medium'}

### After
- **Total vulnerabilities**: 0 (target)
- **Security score**: High
- **Risk level**: Low

## 🚀 Deployment Notes

### Environment Variables Required
```bash
# Add these to your environment
SECRET_KEY=your-secret-key-here
API_KEY=your-api-key-here
DATABASE_URL=your-database-url-here
```

### Post-Deployment Verification
1. Run security scan to confirm fixes
2. Check application logs for any errors
3. Verify environment variables are loaded correctly
4. Test critical user flows

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [CVE Database](https://cve.mitre.org/)

## 👥 Reviewers

Please ensure you:
1. Review the security implications of each change
2. Verify test coverage for security fixes
3. Confirm no new vulnerabilities are introduced
4. Validate environment variable usage

---

**🔐 This PR addresses critical security vulnerabilities. Please prioritize review and deployment.**

/cc @security-team @devops-team
"""

            return template

        except Exception as e:
            return f"Error generating PR template: {str(e)}"

    def _generate_template_from_string(self, vuln_summary: str, project_info: Any = None) -> str:
        """문자열 형태의 취약점 정보에서 PR 템플릿 생성"""

        # 심각도 카운트 추출 시도
        import re
        critical_count = len(re.findall(r'CRITICAL', vuln_summary, re.IGNORECASE))
        high_count = len(re.findall(r'HIGH', vuln_summary, re.IGNORECASE))
        medium_count = len(re.findall(r'MEDIUM', vuln_summary, re.IGNORECASE))
        low_count = len(re.findall(r'LOW', vuln_summary, re.IGNORECASE))

        total_count = critical_count + high_count + medium_count + low_count

        # PR 제목
        if critical_count > 0:
            title = f"🚨 URGENT: Fix {critical_count} Critical Security Vulnerabilities"
        elif high_count > 0:
            title = f"🔐 Security: Fix {high_count} High Severity Vulnerabilities"
        else:
            title = f"🔐 Security: Fix {total_count} Security Issues"

        template = f"""# {title}

## 📊 Summary
- **Total vulnerabilities fixed**: {total_count}
- **Critical**: {critical_count} 🚨
- **High**: {high_count} ⚠️
- **Medium**: {medium_count} 📋
- **Low**: {low_count} 📝

## 🔧 Vulnerabilities Addressed

{vuln_summary}

## 🧪 Testing

### Automated Tests
- [ ] All existing tests pass
- [ ] New security tests added for fixed vulnerabilities
- [ ] Static security analysis clean (no new issues)

### Manual Testing
- [ ] Verified vulnerability fixes are effective
- [ ] Tested application functionality remains intact
- [ ] Confirmed no new vulnerabilities introduced

### Security Scan Results
- [ ] Trivy scan shows no critical vulnerabilities
- [ ] SAST tools report clean
- [ ] Dependency vulnerabilities resolved

## 🔒 Security Checklist

- [ ] No hardcoded secrets in code
- [ ] All user inputs are validated and sanitized
- [ ] Database queries use parameterized statements
- [ ] Error messages don't expose sensitive information
- [ ] Security headers are properly configured
- [ ] Environment variables are documented

## 🚀 Deployment Notes

### Post-Deployment Verification
1. Run security scan to confirm fixes
2. Check application logs for any errors
3. Verify environment variables are loaded correctly
4. Test critical user flows

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)

---

**🔐 This PR addresses critical security vulnerabilities. Please prioritize review and deployment.**

/cc @security-team @devops-team
"""
        return template


class GenerateSecurityDocumentationInput(BaseModel):
    """Input schema for generate_security_documentation tool"""
    vulnerabilities: Optional[Any] = Field(
        default=None,
        description="취약점 목록 또는 요약 정보 (리스트, 딕셔너리, 문자열 모두 가능)"
    )
    fixes: Optional[Any] = Field(
        default=None,
        description="수정 사항 목록 또는 요약 정보 (리스트, 딕셔너리, 문자열 모두 가능)"
    )


class GenerateSecurityDocumentationTool(BaseTool):
    """보안 수정에 대한 문서를 생성하는 도구"""

    name: str = "generate_security_documentation"
    description: str = "보안 수정에 대한 문서를 생성합니다. 취약점과 수정사항을 바탕으로 보안 가이드라인, README 섹션 등의 문서를 생성합니다."
    args_schema: type[BaseModel] = GenerateSecurityDocumentationInput

    def _run(self, vulnerabilities: Optional[Any] = None, fixes: Optional[Any] = None) -> Dict[str, str]:
        """
        보안 수정에 대한 문서를 생성합니다.

        Args:
            vulnerabilities: 취약점 목록 또는 요약 정보 (Optional)
            fixes: 수정 사항 목록 또는 요약 정보 (Optional)

        Returns:
            다양한 문서들 (README 업데이트, 보안 가이드 등)
        """
        try:
            # 데이터 타입 정규화
            if not vulnerabilities:
                vulnerabilities = []
            elif isinstance(vulnerabilities, str):
                # 문자열인 경우 빈 리스트로 처리 (문서는 일반적인 내용 생성)
                vulnerabilities = []
            elif not isinstance(vulnerabilities, list):
                vulnerabilities = [vulnerabilities]

            if not fixes:
                fixes = []
            elif isinstance(fixes, str):
                fixes = []
            elif not isinstance(fixes, list):
                fixes = [fixes]

            docs = {}

            # 1. 보안 가이드라인 문서
            security_guide = """# Security Guidelines

## Overview
This document outlines the security practices and guidelines for this project.

## Security Measures Implemented

### Input Validation
- All user inputs are validated and sanitized
- Parameterized queries are used for database operations
- HTML escaping is applied to prevent XSS

### Secret Management
- Secrets are stored in environment variables
- .env files are excluded from version control
- Production secrets are managed securely

### Dependencies
- Regular dependency updates and vulnerability scans
- Use of latest stable versions with security patches

### Configuration
- Debug mode disabled in production
- Secure headers implemented
- Network access properly restricted

## Security Checklist for Developers

### Before Committing Code
- [ ] No hardcoded secrets or credentials
- [ ] Input validation for all user data
- [ ] SQL queries use parameterized statements
- [ ] Output is properly escaped/sanitized
- [ ] Error handling doesn't expose sensitive info

### Before Deployment
- [ ] Environment variables configured
- [ ] Security scan passes
- [ ] Dependencies updated
- [ ] Debug mode disabled

## Incident Response
1. Identify and assess the security incident
2. Contain the threat immediately
3. Document all findings and actions
4. Implement fixes and preventive measures
5. Conduct post-incident review

## Tools and Resources
- Trivy for vulnerability scanning
- OWASP security guidelines
- Regular security training materials
"""

            docs['SECURITY.md'] = security_guide

            # 2. README에 추가할 보안 섹션
            readme_security_section = """
## Security

### Vulnerability Management
This project undergoes regular security scans using:
- Trivy for container and dependency scanning
- Static Application Security Testing (SAST)
- Regular dependency updates

### Reporting Security Issues
If you discover a security vulnerability, please:
1. Do not open a public issue
2. Email security@company.com with details
3. Include steps to reproduce if possible

### Environment Variables
Required environment variables for secure operation:

```bash
SECRET_KEY=your-secret-key
API_KEY=your-api-key
DATABASE_URL=your-database-url
```

Copy `.env.example` to `.env` and fill in your values.

### Security Features
- Input validation and sanitization
- Parameterized database queries
- HTML escaping for XSS prevention
- Secure session management
- HTTPS enforcement
"""

            docs['README_security_section.md'] = readme_security_section

            # 3. 환경 변수 예시 파일
            env_example = """# Environment Variables Template
# Copy this file to .env and fill in your actual values
# Never commit the .env file to version control

# Application
SECRET_KEY=your-secret-key-here
DEBUG=False
FLASK_ENV=production

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# External APIs
API_KEY=your-api-key-here
EXTERNAL_SERVICE_URL=https://api.example.com

# Security
SESSION_TIMEOUT=3600
MAX_LOGIN_ATTEMPTS=5
"""

            docs['.env.example'] = env_example

            return docs

        except Exception as e:
            return {"error": f"Documentation generation failed: {str(e)}"}


class GenerateFixScriptInput(BaseModel):
    """Input schema for generate_fix_script tool"""
    vulnerabilities: Optional[Any] = Field(
        default=None,
        description="취약점 목록 또는 요약 정보 (리스트, 딕셔너리, 문자열 모두 가능)"
    )


class GenerateFixScriptTool(BaseTool):
    """취약점 수정을 위한 자동화 스크립트를 생성하는 도구"""

    name: str = "generate_fix_script"
    description: str = "취약점 수정을 위한 자동화 스크립트를 생성합니다. 취약점 목록을 바탕으로 자동화된 수정 스크립트를 작성합니다."
    args_schema: type[BaseModel] = GenerateFixScriptInput

    def _run(self, vulnerabilities: Optional[Any] = None) -> str:
        """
        취약점 수정을 위한 자동화 스크립트를 생성합니다.

        Args:
            vulnerabilities: 취약점 목록 또는 요약 정보

        Returns:
            수정 스크립트
        """
        try:
            # 데이터 타입 정규화
            if not vulnerabilities:
                vulnerabilities = []
            elif isinstance(vulnerabilities, str):
                # 문자열인 경우 일반적인 스크립트 생성
                vulnerabilities = []
            elif not isinstance(vulnerabilities, list):
                vulnerabilities = [vulnerabilities]

            script_lines = [
                "#!/bin/bash",
                "# Automated Security Fix Script",
                "# Generated by SecurityAgent",
                "",
                "set -e  # Exit on any error",
                "",
                "echo '🔐 Starting automated security fixes...'",
                ""
            ]

            # 환경 변수 설정
            has_hardcoded_secrets = any(v.get('type') == 'HARDCODED_SECRET' for v in vulnerabilities)
            if has_hardcoded_secrets:
                script_lines.extend([
                    "# Create .env.example if it doesn't exist",
                    "if [ ! -f .env.example ]; then",
                    "    echo 'Creating .env.example...'",
                    "    cat > .env.example << 'EOF'",
                    "SECRET_KEY=your-secret-key-here",
                    "API_KEY=your-api-key-here",
                    "DATABASE_URL=your-database-url-here",
                    "EOF",
                    "fi",
                    "",
                    "# Update .gitignore to exclude .env files",
                    "if ! grep -q '.env' .gitignore 2>/dev/null; then",
                    "    echo 'Adding .env to .gitignore...'",
                    "    echo -e '\\n# Environment variables\\n.env\\n*.env' >> .gitignore",
                    "fi",
                    ""
                ])

            # 테스트 실행
            script_lines.extend([
                "# Run security tests",
                "echo 'Running security verification...'",
                "",
                "# Check if Trivy is available",
                "if command -v trivy &> /dev/null; then",
                "    echo 'Running Trivy scan...'",
                "    trivy fs . --severity CRITICAL,HIGH",
                "else",
                "    echo 'Trivy not found, skipping scan'",
                "fi",
                "",
                "# Run Python security checks if available",
                "if command -v bandit &> /dev/null; then",
                "    echo 'Running Bandit security scan...'",
                "    bandit -r . -x tests/ || echo 'Some security issues found'",
                "fi",
                "",
                "echo '✅ Security fixes completed!'",
                "echo 'Please review the changes and test your application.'",
                "echo 'Remember to:'",
                "echo '  1. Set up environment variables'",
                "echo '  2. Test all functionality'",
                "echo '  3. Run your test suite'",
                "echo '  4. Deploy carefully'",
                ""
            ])

            return '\n'.join(script_lines)

        except Exception as e:
            return f"#!/bin/bash\necho 'Error generating fix script: {str(e)}'"


# Tool instances for backward compatibility and easy import
_generate_fix_code_tool = GenerateFixCodeTool()
_create_pr_template_tool = CreatePRTemplateTool()
_generate_security_documentation_tool = GenerateSecurityDocumentationTool()
_generate_fix_script_tool = GenerateFixScriptTool()

# CrewAI-compatible tool wrappers
from crewai.tools import tool

@tool("Generate Fix Code")
def generate_fix_code(vulnerability: Optional[Any] = None) -> dict:
    """취약점에 대한 수정 코드를 생성합니다. SQL Injection, XSS, Command Injection 등 각 취약점 타입에 맞는 안전한 코드 패턴과 테스트 코드를 제공합니다."""
    return _generate_fix_code_tool._run(vulnerability=vulnerability)

@tool("Create PR Template")
def create_pr_template(vulnerabilities: Optional[Any] = None, project_info: Optional[Any] = None) -> str:
    """GitHub Pull Request 템플릿을 생성합니다. 취약점 목록과 수정 사항을 바탕으로 상세한 보안 패치 PR 문서를 작성합니다."""
    return _create_pr_template_tool._run(vulnerabilities=vulnerabilities, project_info=project_info)

@tool("Generate Security Documentation")
def generate_security_documentation(vulnerabilities: Optional[Any] = None, fixes: Optional[Any] = None) -> dict:
    """보안 수정에 대한 문서를 생성합니다. SECURITY.md, README 보안 섹션, .env.example 등 프로젝트에 필요한 보안 문서를 작성합니다."""
    return _generate_security_documentation_tool._run(vulnerabilities=vulnerabilities, fixes=fixes)

@tool("Generate Fix Script")
def generate_fix_script(vulnerabilities: Optional[Any] = None) -> str:
    """취약점 수정을 위한 자동화 스크립트를 생성합니다. 환경 설정, 의존성 업데이트, 보안 검증 등을 자동으로 수행하는 Bash 스크립트를 작성합니다."""
    return _generate_fix_script_tool._run(vulnerabilities=vulnerabilities)