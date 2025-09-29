"""
도구 함수들에 대한 단위 테스트
"""

import pytest
import json
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
import sys

# 테스트를 위한 경로 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.scanner_tools import fetch_project_info, scan_with_trivy, analyze_dependencies, check_security_configs
from src.tools.analysis_tools import calculate_priority_score, analyze_vulnerability_trends, generate_security_metrics
from src.tools.fix_tools import generate_fix_code, create_pr_template


class TestScannerTools:
    """스캐너 도구 테스트"""

    @pytest.fixture
    def temp_project_dir(self):
        """임시 프로젝트 디렉토리 생성"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_vulnerable_project(self, temp_project_dir):
        """취약점이 있는 샘플 프로젝트 생성"""

        # app.py 생성
        app_content = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)
SECRET_KEY = "hardcoded-secret"  # 취약점

@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL Injection 취약점
    cursor.execute(query)
    return "result"

@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form['comment']
    return f"<div>{comment}</div>"  # XSS 취약점
'''

        with open(os.path.join(temp_project_dir, "app.py"), "w") as f:
            f.write(app_content)

        # requirements.txt 생성
        requirements_content = '''Flask==1.0.0
requests==2.19.0
PyYAML==3.13'''

        with open(os.path.join(temp_project_dir, "requirements.txt"), "w") as f:
            f.write(requirements_content)

        # Dockerfile 생성
        dockerfile_content = '''FROM python:3.6-slim
USER root
COPY . /app/'''

        with open(os.path.join(temp_project_dir, "Dockerfile"), "w") as f:
            f.write(dockerfile_content)

        return temp_project_dir

    def test_fetch_project_info_success(self, sample_vulnerable_project):
        """프로젝트 정보 수집 테스트 - 성공 케이스"""

        result = fetch_project_info(sample_vulnerable_project)

        assert "error" not in result
        assert result["language"] == "Python"
        assert result["framework"] == "Flask"
        assert result["has_dockerfile"] is True
        assert result["has_requirements"] is True
        assert "app.py" in result["files"]
        assert "requirements.txt" in result["files"]
        assert "Dockerfile" in result["files"]

    def test_fetch_project_info_nonexistent_path(self):
        """프로젝트 정보 수집 테스트 - 존재하지 않는 경로"""

        result = fetch_project_info("/nonexistent/path")

        assert "error" in result
        assert "does not exist" in result["error"]

    def test_analyze_dependencies_vulnerable_packages(self, sample_vulnerable_project):
        """종속성 분석 테스트 - 취약한 패키지"""

        result = analyze_dependencies(sample_vulnerable_project)

        assert "error" not in result
        assert "vulnerabilities" in result
        assert len(result["vulnerabilities"]) > 0

        # Flask 1.0.0 취약점 확인
        flask_vuln = next((v for v in result["vulnerabilities"] if v["package"] == "flask"), None)
        assert flask_vuln is not None
        assert flask_vuln["current_version"] == "1.0.0"
        assert flask_vuln["severity"] == "CRITICAL"

    def test_analyze_dependencies_no_requirements(self, temp_project_dir):
        """종속성 분석 테스트 - requirements.txt 없음"""

        result = analyze_dependencies(temp_project_dir)

        assert "error" in result
        assert "requirements.txt not found" in result["error"]

    def test_check_security_configs_vulnerabilities(self, sample_vulnerable_project):
        """보안 설정 검사 테스트 - 취약점 발견"""

        result = check_security_configs(sample_vulnerable_project)

        assert "error" not in result
        assert "security_issues" in result
        issues = result["security_issues"]

        # SQL Injection 취약점 확인
        sql_injection_issues = [issue for issue in issues if issue["type"] == "SQL_INJECTION"]
        assert len(sql_injection_issues) > 0

        # XSS 취약점 확인
        xss_issues = [issue for issue in issues if issue["type"] == "XSS"]
        assert len(xss_issues) > 0

        # 하드코딩된 시크릿 확인
        secret_issues = [issue for issue in issues if issue["type"] == "HARDCODED_SECRET"]
        assert len(secret_issues) > 0

    @patch('subprocess.run')
    def test_scan_with_trivy_mock_data(self, mock_subprocess, temp_project_dir):
        """Trivy 스캔 테스트 - 모의 데이터"""

        # Trivy가 없는 상황 시뮬레이션
        mock_subprocess.side_effect = FileNotFoundError("trivy not found")

        result = scan_with_trivy(temp_project_dir)

        assert "error" not in result
        assert result["scan_type"] == "trivy_mock"
        assert "filesystem_scan" in result
        assert "total_vulnerabilities" in result


class TestAnalysisTools:
    """분석 도구 테스트"""

    @pytest.fixture
    def sample_vulnerability(self):
        """샘플 취약점 데이터"""
        return {
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "file": "app.py",
            "line": 15,
            "description": "SQL injection vulnerability"
        }

    @pytest.fixture
    def sample_vulnerabilities(self):
        """샘플 취약점 목록"""
        return [
            {
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py",
                "line": 15
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "file": "app.py",
                "line": 25
            },
            {
                "type": "HARDCODED_SECRET",
                "severity": "HIGH",
                "file": "config.py",
                "line": 5
            }
        ]

    def test_calculate_priority_score_critical(self, sample_vulnerability):
        """우선순위 점수 계산 테스트 - Critical 취약점"""

        result = calculate_priority_score(sample_vulnerability)

        assert "error" not in result
        assert result["vulnerability_type"] == "SQL_INJECTION"
        assert result["severity"] == "CRITICAL"
        assert result["priority"] in ["P0", "P1"]
        assert result["final_score"] > 5.0
        assert "estimated_fix_time" in result

    def test_analyze_vulnerability_trends_multiple(self, sample_vulnerabilities):
        """취약점 트렌드 분석 테스트"""

        result = analyze_vulnerability_trends(sample_vulnerabilities)

        assert "error" not in result
        assert result["total_vulnerabilities"] == 3
        assert "severity_distribution" in result
        assert "type_distribution" in result
        assert result["severity_distribution"]["CRITICAL"] == 1
        assert result["severity_distribution"]["HIGH"] == 2

    def test_analyze_vulnerability_trends_empty(self):
        """취약점 트렌드 분석 테스트 - 빈 목록"""

        result = analyze_vulnerability_trends([])

        assert "error" in result

    def test_generate_security_metrics(self, sample_vulnerabilities):
        """보안 메트릭 생성 테스트"""

        # 모의 스캔 결과 생성
        scan_results = {
            "security_config_scan": {
                "security_issues": sample_vulnerabilities
            },
            "files_scanned": 3
        }

        result = generate_security_metrics(scan_results)

        assert "error" not in result
        assert "metrics" in result
        assert "security_score" in result
        assert "security_grade" in result
        assert result["metrics"]["vulnerability_count"] == 3
        assert result["metrics"]["critical_count"] == 1


class TestFixTools:
    """수정 도구 테스트"""

    @pytest.fixture
    def sample_sql_injection_vuln(self):
        """SQL Injection 취약점 샘플"""
        return {
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "file": "app.py",
            "line": 15,
            "code": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
            "description": "SQL injection vulnerability"
        }

    @pytest.fixture
    def sample_vulnerabilities_for_pr(self):
        """PR 템플릿용 취약점 샘플"""
        return [
            {
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py"
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "file": "templates/index.html"
            },
            {
                "type": "HARDCODED_SECRET",
                "severity": "HIGH",
                "file": "config.py"
            }
        ]

    def test_generate_fix_code_sql_injection(self, sample_sql_injection_vuln):
        """SQL Injection 수정 코드 생성 테스트"""

        result = generate_fix_code(sample_sql_injection_vuln)

        assert "error" not in result
        assert result["vulnerability_type"] == "SQL_INJECTION"
        assert "before_code" in result
        assert "after_code" in result
        assert "dependencies" in result
        assert "test_code" in result
        assert "parameterized" in result["after_code"] or "?" in result["after_code"]

    def test_generate_fix_code_unknown_type(self):
        """알 수 없는 취약점 타입 테스트"""

        unknown_vuln = {
            "type": "UNKNOWN_VULNERABILITY",
            "severity": "MEDIUM",
            "file": "test.py"
        }

        result = generate_fix_code(unknown_vuln)

        assert "error" in result

    def test_create_pr_template_multiple_vulns(self, sample_vulnerabilities_for_pr):
        """PR 템플릿 생성 테스트 - 다중 취약점"""

        result = create_pr_template(sample_vulnerabilities_for_pr)

        assert isinstance(result, str)
        assert "Security Patch" in result or "Security" in result
        assert "CRITICAL" in result
        assert "HIGH" in result
        assert "SQL_INJECTION" in result or "SQL" in result
        assert "XSS" in result
        assert "Changes Made" in result or "Changes" in result
        assert "Testing" in result

    def test_create_pr_template_empty_list(self):
        """PR 템플릿 생성 테스트 - 빈 취약점 목록"""

        result = create_pr_template([])

        assert isinstance(result, str)
        assert "No vulnerabilities" in result


class TestIntegration:
    """통합 테스트"""

    @pytest.fixture
    def test_project_setup(self):
        """테스트용 프로젝트 설정"""

        # 임시 디렉토리 생성
        temp_dir = tempfile.mkdtemp()

        # 취약한 파일들 생성
        vulnerable_app = '''
from flask import Flask, request
import sqlite3

SECRET_KEY = "test-secret"

@app.route('/user/<user_id>')
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query
'''

        vulnerable_requirements = '''Flask==1.0.0
requests==2.19.0'''

        with open(os.path.join(temp_dir, "app.py"), "w") as f:
            f.write(vulnerable_app)

        with open(os.path.join(temp_dir, "requirements.txt"), "w") as f:
            f.write(vulnerable_requirements)

        yield temp_dir

        # 정리
        shutil.rmtree(temp_dir)

    def test_full_scan_workflow(self, test_project_setup):
        """전체 스캔 워크플로우 테스트"""

        project_path = test_project_setup

        # 1. 프로젝트 정보 수집
        project_info = fetch_project_info(project_path)
        assert "error" not in project_info
        assert project_info["language"] == "Python"

        # 2. 종속성 분석
        deps_result = analyze_dependencies(project_path)
        assert "error" not in deps_result
        assert len(deps_result["vulnerabilities"]) > 0

        # 3. 보안 설정 검사
        security_result = check_security_configs(project_path)
        assert "error" not in security_result
        assert len(security_result["security_issues"]) > 0

        # 4. 우선순위 계산
        vulnerabilities = security_result["security_issues"]
        if vulnerabilities:
            priority_result = calculate_priority_score(vulnerabilities[0])
            assert "error" not in priority_result
            assert "priority" in priority_result

        # 5. 수정 코드 생성
        if vulnerabilities:
            fix_result = generate_fix_code(vulnerabilities[0])
            # 에러가 있을 수 있지만 구조는 확인
            assert isinstance(fix_result, dict)

    def test_end_to_end_vulnerability_processing(self, test_project_setup):
        """End-to-End 취약점 처리 테스트"""

        project_path = test_project_setup

        # 전체 프로세스 시뮬레이션
        results = {}

        # 1. 스캔
        results["project_info"] = fetch_project_info(project_path)
        results["dependencies"] = analyze_dependencies(project_path)
        results["security_configs"] = check_security_configs(project_path)

        # 2. 분석
        all_vulnerabilities = results["security_configs"]["security_issues"]
        if all_vulnerabilities:
            results["trends"] = analyze_vulnerability_trends(all_vulnerabilities)
            results["metrics"] = generate_security_metrics({
                "security_config_scan": results["security_configs"]
            })

        # 3. 수정 방안
        if all_vulnerabilities:
            results["pr_template"] = create_pr_template(all_vulnerabilities)

        # 결과 검증
        assert len(results) >= 3
        assert "error" not in results["project_info"]

        if all_vulnerabilities:
            assert len(all_vulnerabilities) > 0
            assert isinstance(results["pr_template"], str)


class TestErrorHandling:
    """에러 처리 테스트"""

    def test_fetch_project_info_permission_error(self):
        """권한 에러 처리 테스트"""

        with patch('os.path.exists', return_value=True), \
             patch('os.listdir', side_effect=PermissionError("Permission denied")):

            result = fetch_project_info("/restricted/path")
            assert "error" in result

    def test_analyze_dependencies_file_read_error(self):
        """파일 읽기 에러 처리 테스트"""

        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', side_effect=IOError("File read error")):

            result = analyze_dependencies("/test/path")
            assert "error" in result

    def test_trivy_command_timeout(self):
        """Trivy 명령어 타임아웃 테스트"""

        with patch('subprocess.run', side_effect=FileNotFoundError("trivy not found")):
            result = scan_with_trivy("/test/path")

            # 모의 데이터로 fallback 되어야 함
            assert "error" not in result
            assert result["scan_type"] == "trivy_mock"


class TestDataValidation:
    """데이터 검증 테스트"""

    def test_vulnerability_data_structure(self):
        """취약점 데이터 구조 검증"""

        # 다양한 형태의 취약점 데이터 테스트
        test_vulns = [
            {
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py"
            },
            {
                "VulnerabilityID": "CVE-2019-1010083",
                "Severity": "HIGH",
                "PkgName": "Flask"
            }
        ]

        # 트렌드 분석이 다양한 형태를 처리하는지 확인
        result = analyze_vulnerability_trends(test_vulns)
        assert "error" not in result
        assert result["total_vulnerabilities"] == 2

    def test_priority_score_edge_cases(self):
        """우선순위 점수 계산 엣지 케이스"""

        # 최소 정보만 있는 취약점
        minimal_vuln = {"type": "UNKNOWN"}
        result = calculate_priority_score(minimal_vuln)

        assert "error" not in result
        assert "priority" in result
        assert "final_score" in result

        # 모든 필드가 있는 취약점
        complete_vuln = {
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "file": "app.py",
            "environment": "production"
        }
        result = calculate_priority_score(complete_vuln)

        assert result["priority"] in ["P0", "P1", "P2", "P3"]
        assert result["final_score"] > 0


# 테스트 실행용 헬퍼
if __name__ == "__main__":
    pytest.main([__file__, "-v"])