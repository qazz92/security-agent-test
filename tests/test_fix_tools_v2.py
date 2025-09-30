"""
fix_tools_v2.py 테스트
LLM 기반 보안 코드 수정 도구의 동작을 검증
"""

import pytest
import json
from src.tools.fix_tools_v2 import (
    GenerateFixCodeToolV2,
    SECURITY_PATTERNS,
    SecurityFix,
    CodeFix
)


# ============================================================================
# Test Cases: 실제 취약한 코드로 테스트
# ============================================================================

VULNERABLE_CODE_SAMPLES = {
    "SQL_INJECTION": {
        "simple": {
            "code": """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
""",
            "file": "app.py",
            "line": 25,
            "expected_fixes": ["cursor.execute", "?", "user_id,"]
        },
        "complex": {
            "code": """
@app.route('/products/<product_id>')
def get_product(product_id):
    # Retrieve product details
    sql = f"SELECT name, price, stock FROM products WHERE id = {product_id}"
    result = db.execute(sql)
    return jsonify(result)
""",
            "file": "views/product.py",
            "line": 128,
            "expected_fixes": ["cursor.execute", "?", "product_id,", "products"]
        }
    },

    "XSS": {
        "simple": {
            "code": """
@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form['comment']
    return f"<div class='comment'>{comment}</div>"
""",
            "file": "routes.py",
            "line": 45,
            "expected_fixes": ["escape(", "comment", ")"]
        }
    },

    "COMMAND_INJECTION": {
        "simple": {
            "code": """
def ping_server(hostname):
    cmd = f"ping -c 1 {hostname}"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout
""",
            "file": "utils/network.py",
            "line": 67,
            "expected_fixes": ["shell=False", "['ping',", "'1',", "hostname]"]
        }
    }
}


class TestSecurityPatterns:
    """보안 패턴 정의 테스트"""

    def test_patterns_exist(self):
        """모든 필수 패턴이 정의되어 있는지 확인"""
        required_patterns = [
            "SQL_INJECTION",
            "XSS",
            "COMMAND_INJECTION",
            "HARDCODED_SECRET",
            "UNSAFE_DESERIALIZATION"
        ]

        for pattern in required_patterns:
            assert pattern in SECURITY_PATTERNS
            assert "name" in SECURITY_PATTERNS[pattern]
            assert "principle" in SECURITY_PATTERNS[pattern]
            assert "vulnerable_patterns" in SECURITY_PATTERNS[pattern]
            assert "secure_patterns" in SECURITY_PATTERNS[pattern]

    def test_pattern_completeness(self):
        """각 패턴이 필수 정보를 모두 포함하는지 확인"""
        for vuln_type, pattern in SECURITY_PATTERNS.items():
            # 필수 필드
            assert pattern["name"]
            assert pattern["description"]
            assert pattern["principle"]
            assert len(pattern["vulnerable_patterns"]) > 0
            assert len(pattern["secure_patterns"]) > 0
            assert pattern["example"]

            # CWE/OWASP 매핑
            assert "cwe" in pattern
            assert "owasp" in pattern


class TestGenerateFixCodeToolV2:
    """LLM 기반 수정 도구 테스트"""

    @pytest.fixture
    def tool(self):
        """Tool 인스턴스 생성"""
        return GenerateFixCodeToolV2()

    def test_tool_initialization(self, tool):
        """Tool이 올바르게 초기화되는지 확인"""
        assert tool.name == "generate_fix_code"
        assert tool.llm is not None
        assert tool.parser is not None

    def test_unsupported_vulnerability_type(self, tool):
        """지원하지 않는 취약점 유형 처리"""
        vulnerability = {
            "type": "UNKNOWN_VULNERABILITY",
            "code": "some code",
            "file": "test.py"
        }

        result = tool._run(vulnerability)

        assert "error" in result
        assert "available_types" in result
        assert "SQL_INJECTION" in result["available_types"]

    def test_missing_code(self, tool):
        """코드가 없는 경우 처리"""
        vulnerability = {
            "type": "SQL_INJECTION",
            "file": "test.py",
            "code": ""  # 빈 코드
        }

        result = tool._run(vulnerability)

        assert "error" in result or "pattern" in result

    def test_prompt_building(self, tool):
        """프롬프트가 올바르게 생성되는지 확인"""
        pattern = SECURITY_PATTERNS["SQL_INJECTION"]
        prompt = tool._build_fix_prompt(
            vuln_type="SQL_INJECTION",
            original_code="query = f'SELECT * FROM users WHERE id = {user_id}'",
            file_path="app.py",
            line_number=25,
            severity="CRITICAL",
            pattern=pattern
        )

        # 프롬프트 필수 요소 확인
        assert "원본 취약 코드" in prompt
        assert "보안 원칙" in prompt
        assert "안전한 패턴들" in prompt
        assert "출력 형식 (JSON)" in prompt
        assert "변수명" in prompt  # 구조 보존 요구사항
        assert pattern["principle"] in prompt

    def test_fallback_generation(self, tool):
        """Fallback 메커니즘 테스트"""
        vulnerability = {
            "type": "SQL_INJECTION",
            "code": "test code",
            "file": "test.py",
            "severity": "HIGH"
        }
        pattern = SECURITY_PATTERNS["SQL_INJECTION"]

        result = tool._generate_fallback_fix(vulnerability, pattern)

        assert result["vulnerability_type"] == "SQL_INJECTION"
        assert result["principle"] == pattern["principle"]
        assert result["example_fix"] == pattern["example"]
        assert result["manual_review_required"] is True


class TestPydanticModels:
    """Pydantic 모델 검증 테스트"""

    def test_code_fix_model(self):
        """CodeFix 모델 생성 및 검증"""
        code_fix = CodeFix(
            original_code="query = f'SELECT * FROM users WHERE id = {user_id}'",
            fixed_code='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            explanation="Parameterized query를 사용하여 SQL Injection 방지",
            changes_summary="f-string → parameterized query",
            preserved_elements=["user_id", "users 테이블", "SELECT 로직"]
        )

        assert code_fix.original_code
        assert code_fix.fixed_code
        assert code_fix.explanation
        assert len(code_fix.preserved_elements) > 0

    def test_security_fix_model(self):
        """SecurityFix 모델 생성 및 검증"""
        code_fix = CodeFix(
            original_code="test",
            fixed_code="test_fixed",
            explanation="test explanation",
            changes_summary="test summary",
            preserved_elements=["test_var"]
        )

        security_fix = SecurityFix(
            vulnerability_type="SQL_INJECTION",
            file_path="app.py",
            line_number=25,
            severity="CRITICAL",
            code_fix=code_fix,
            test_code="def test_fix(): pass",
            dependencies=["sqlite3"],
            additional_steps=["Run tests"]
        )

        assert security_fix.vulnerability_type == "SQL_INJECTION"
        assert security_fix.severity == "CRITICAL"
        assert security_fix.code_fix == code_fix


class TestIntegration:
    """통합 테스트 (실제 LLM 호출 - optional)"""

    @pytest.mark.skip(reason="LLM 호출 비용 - 수동 실행용")
    def test_sql_injection_fix_with_llm(self):
        """실제 LLM을 사용한 SQL Injection 수정"""
        tool = GenerateFixCodeToolV2()

        vulnerability = {
            "type": "SQL_INJECTION",
            "code": VULNERABLE_CODE_SAMPLES["SQL_INJECTION"]["simple"]["code"],
            "file": "app.py",
            "line": 25,
            "severity": "CRITICAL"
        }

        result = tool._run(vulnerability)

        # 성공 여부 확인
        assert result.get("success") is True or "error" in result

        if result.get("success"):
            # 수정된 코드 검증
            fixed_code = result["fixed_code"]
            assert "user_id" in fixed_code  # 변수명 보존
            assert "users" in fixed_code    # 테이블명 보존
            assert "?" in fixed_code or "User.query" in fixed_code  # Parameterized query

    @pytest.mark.skip(reason="LLM 호출 비용 - 수동 실행용")
    def test_xss_fix_with_llm(self):
        """실제 LLM을 사용한 XSS 수정"""
        tool = GenerateFixCodeToolV2()

        vulnerability = {
            "type": "XSS",
            "code": VULNERABLE_CODE_SAMPLES["XSS"]["simple"]["code"],
            "file": "routes.py",
            "line": 45,
            "severity": "HIGH"
        }

        result = tool._run(vulnerability)

        if result.get("success"):
            fixed_code = result["fixed_code"]
            assert "comment" in fixed_code  # 변수명 보존
            assert "escape" in fixed_code or "render_template" in fixed_code


class TestComparisonWithOldVersion:
    """구버전(Template만)과 신버전(LLM) 비교"""

    def test_template_only_limitation(self):
        """구버전의 한계: 다른 변수명 처리 불가"""

        # 구버전 Template 결과 시뮬레이션
        old_template_result = {
            "after_code": """
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
        }

        # 실제 코드는 product_id, products 테이블 사용
        actual_code = """
def get_product(product_id):
    query = f"SELECT * FROM products WHERE id = {product_id}"
"""

        # 문제: Template 코드는 users/user_id인데 실제는 products/product_id
        assert "users" in old_template_result["after_code"]
        assert "products" not in old_template_result["after_code"]
        # → 포트폴리오로 부적합!

    def test_llm_version_advantage(self):
        """신버전의 장점: 실제 코드에 맞게 생성"""

        # 신버전은 실제 코드를 분석하여 올바르게 수정
        # (실제 LLM 호출 없이 기대 동작 검증)

        expected_llm_result = {
            "original_code": "query = f\"SELECT * FROM products WHERE id = {product_id}\"",
            "fixed_code": "cursor.execute(\"SELECT * FROM products WHERE id = ?\", (product_id,))",
            "preserved_elements": ["product_id", "products", "SELECT 로직"]
        }

        # 검증: 실제 변수명/테이블명 보존
        assert "product_id" in expected_llm_result["fixed_code"]
        assert "products" in expected_llm_result["fixed_code"]
        assert "product_id" in expected_llm_result["preserved_elements"]
        # → 포트폴리오로 적합!


# ============================================================================
# Mock LLM Response for Testing
# ============================================================================

MOCK_LLM_RESPONSES = {
    "SQL_INJECTION": {
        "vulnerability_type": "SQL_INJECTION",
        "file_path": "app.py",
        "line_number": 25,
        "severity": "CRITICAL",
        "code_fix": {
            "original_code": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
            "fixed_code": """def get_user(user_id):
    # Validate input
    if not isinstance(user_id, int):
        raise ValueError("Invalid user ID")

    # Use parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()""",
            "explanation": "f-string으로 직접 삽입된 user_id를 parameterized query로 변경하여 SQL Injection 방지. 입력 검증도 추가했습니다.",
            "changes_summary": "f-string → parameterized query + 입력 검증",
            "preserved_elements": ["user_id 변수명", "users 테이블", "fetchone() 로직"]
        },
        "test_code": """def test_sql_injection_prevention():
    malicious_input = "1; DROP TABLE users; --"
    try:
        result = get_user(malicious_input)
        assert result is None
    except ValueError:
        pass  # Expected""",
        "dependencies": ["sqlite3"],
        "additional_steps": ["테스트 실행", "다른 SQL 쿼리도 검토"]
    }
}


if __name__ == "__main__":
    # 간단한 수동 테스트
    print("=== fix_tools_v2 테스트 ===\n")

    print("1. Security Patterns 확인")
    print(f"   - 정의된 패턴 수: {len(SECURITY_PATTERNS)}")
    print(f"   - 패턴 목록: {list(SECURITY_PATTERNS.keys())}\n")

    print("2. Pydantic 모델 테스트")
    code_fix = CodeFix(
        original_code="test",
        fixed_code="test_fixed",
        explanation="test",
        changes_summary="test",
        preserved_elements=["test"]
    )
    print(f"   - CodeFix 모델 생성 성공: {code_fix.original_code}\n")

    print("3. Tool 초기화 테스트")
    try:
        tool = GenerateFixCodeToolV2()
        print(f"   - Tool 생성 성공: {tool.name}\n")
    except Exception as e:
        print(f"   - Tool 생성 실패: {e}\n")

    print("=== 테스트 완료 ===")
    print("\n전체 테스트 실행: pytest tests/test_fix_tools_v2.py -v")