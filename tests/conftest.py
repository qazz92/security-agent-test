"""
Pytest 설정 및 공용 픽스처
"""

import pytest
import tempfile
import shutil
import os
from unittest.mock import patch


@pytest.fixture(scope="session")
def test_data_dir():
    """테스트 데이터 디렉토리"""
    return os.path.join(os.path.dirname(__file__), "test_data")


@pytest.fixture
def temp_directory():
    """임시 디렉토리 픽스처"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_env_vars():
    """모의 환경 변수"""
    with patch.dict(os.environ, {
        'OPENROUTER_API_KEY': 'test-api-key',
        'MODEL_NAME': 'test-model',
        'TEMPERATURE': '0.3',
        'MAX_TOKENS': '2048'
    }):
        yield


@pytest.fixture
def vulnerable_python_code():
    """취약한 Python 코드 샘플"""
    return '''
import sqlite3
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "hardcoded-secret"

@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return "result"

@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form['comment']
    return f"<div>{comment}</div>"
'''


@pytest.fixture
def vulnerable_requirements():
    """취약한 requirements.txt 내용"""
    return '''Flask==1.0.0
requests==2.19.0
PyYAML==3.13
Jinja2==2.10'''


@pytest.fixture
def sample_vulnerabilities():
    """샘플 취약점 데이터"""
    return [
        {
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "file": "app.py",
            "line": 15,
            "description": "SQL injection vulnerability in user query",
            "code": 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        },
        {
            "type": "XSS",
            "severity": "HIGH",
            "file": "app.py",
            "line": 25,
            "description": "Cross-site scripting vulnerability",
            "code": 'return f"<div>{comment}</div>"'
        },
        {
            "type": "HARDCODED_SECRET",
            "severity": "HIGH",
            "file": "app.py",
            "line": 8,
            "description": "Hardcoded secret key",
            "code": 'SECRET_KEY = "hardcoded-secret"'
        }
    ]


@pytest.fixture
def sample_security_analysis():
    """샘플 보안 분석 결과"""
    return {
        "project_path": "/test/project",
        "analysis_summary": {
            "total_vulnerabilities": 3,
            "severity_distribution": {
                "CRITICAL": 1,
                "HIGH": 2,
                "MEDIUM": 0,
                "LOW": 0
            },
            "analysis_duration": 5.2,
            "tools_used": ["fetch_project_info", "scan_with_trivy", "check_security_configs"]
        },
        "vulnerabilities": [
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
                "file": "app.py",
                "line": 8
            }
        ],
        "detailed_results": {
            "project_info": {
                "language": "Python",
                "framework": "Flask",
                "files": ["app.py", "requirements.txt"]
            }
        }
    }


@pytest.fixture
def create_test_project(temp_directory, vulnerable_python_code, vulnerable_requirements):
    """테스트용 프로젝트 생성"""
    def _create_project(project_name="test_project"):
        project_dir = os.path.join(temp_directory, project_name)
        os.makedirs(project_dir, exist_ok=True)

        # app.py 파일 생성
        with open(os.path.join(project_dir, "app.py"), "w") as f:
            f.write(vulnerable_python_code)

        # requirements.txt 파일 생성
        with open(os.path.join(project_dir, "requirements.txt"), "w") as f:
            f.write(vulnerable_requirements)

        # .env 파일 생성 (추가 취약점)
        with open(os.path.join(project_dir, ".env"), "w") as f:
            f.write("SECRET_KEY=another-hardcoded-secret\nAPI_KEY=12345")

        return project_dir

    return _create_project


# 테스트 마커 정의
def pytest_configure(config):
    """Pytest 설정"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )


# 비동기 테스트를 위한 이벤트 루프 설정
@pytest.fixture(scope="session")
def event_loop():
    """이벤트 루프 픽스처"""
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# 로깅 설정
@pytest.fixture(autouse=True)
def configure_logging():
    """테스트용 로깅 설정"""
    import logging
    logging.getLogger().setLevel(logging.WARNING)  # 테스트 중 로그 출력 최소화