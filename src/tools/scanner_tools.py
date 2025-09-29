"""
보안 스캐너 툴들
Trivy, 종속성 분석 등 외부 도구를 활용한 취약점 스캔
"""

import os
import json
import subprocess
import time
from typing import Dict, List, Any, Optional
from langchain_core.tools import tool
import re
import yaml


@tool
def fetch_project_info(project_path: str) -> Dict[str, Any]:
    """
    프로젝트의 기본 정보를 수집합니다.

    Args:
        project_path: 프로젝트 경로

    Returns:
        프로젝트 메타데이터 (파일 목록, 언어, 프레임워크 등)
    """
    try:
        if not os.path.exists(project_path):
            return {"error": f"Project path does not exist: {project_path}"}

        files = os.listdir(project_path)

        # 언어 및 프레임워크 감지
        language = "Unknown"
        framework = "Unknown"

        if "requirements.txt" in files or any(f.endswith(".py") for f in files):
            language = "Python"

            # Python 파일들을 스캔하여 프레임워크 감지
            for root, dirs, filenames in os.walk(project_path):
                for filename in filenames:
                    if filename.endswith(".py"):
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8') as f:
                                content = f.read()
                                if "from flask import" in content or "import flask" in content:
                                    framework = "Flask"
                                elif "from django" in content or "import django" in content:
                                    framework = "Django"
                                elif "from fastapi" in content or "import fastapi" in content:
                                    framework = "FastAPI"
                        except:
                            continue

        elif "package.json" in files:
            language = "JavaScript/Node.js"
        elif "Cargo.toml" in files:
            language = "Rust"
        elif "go.mod" in files:
            language = "Go"

        # 보안 관련 파일들 체크
        security_files = []
        for file in files:
            if file in [".env", "config.yml", "database.yml", "secrets.yml"]:
                security_files.append(file)

        return {
            "project_path": project_path,
            "files": files,
            "file_count": len(files),
            "language": language,
            "framework": framework,
            "has_dockerfile": "Dockerfile" in files,
            "has_docker_compose": "docker-compose.yml" in files or "docker-compose.yaml" in files,
            "has_requirements": "requirements.txt" in files,
            "security_files": security_files,
            "scan_timestamp": time.time()
        }

    except Exception as e:
        return {"error": f"Failed to fetch project info: {str(e)}"}


@tool
def scan_with_trivy(target_path: str) -> Dict[str, Any]:
    """
    Trivy를 사용하여 파일시스템과 Docker 설정을 스캔합니다.

    Args:
        target_path: 스캔할 경로

    Returns:
        Trivy 스캔 결과 (실제 Trivy가 없으면 모의 데이터)
    """
    try:
        # Trivy 설치 확인
        trivy_available = False
        try:
            subprocess.run(['trivy', '--version'], capture_output=True, timeout=5)
            trivy_available = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("Trivy not found, using mock data")

        if trivy_available:
            # 실제 Trivy 실행
            try:
                # 파일시스템 스캔
                fs_result = subprocess.run(
                    ['trivy', 'fs', target_path, '--format', 'json', '--severity', 'CRITICAL,HIGH,MEDIUM'],
                    capture_output=True, text=True, timeout=60
                )

                fs_data = json.loads(fs_result.stdout) if fs_result.stdout else {}

                # Docker 설정 스캔 (있을 경우)
                config_data = {}
                if os.path.exists(os.path.join(target_path, "Dockerfile")):
                    config_result = subprocess.run(
                        ['trivy', 'config', target_path, '--format', 'json'],
                        capture_output=True, text=True, timeout=30
                    )
                    config_data = json.loads(config_result.stdout) if config_result.stdout else {}

                return {
                    "scan_type": "trivy_real",
                    "filesystem_scan": fs_data,
                    "config_scan": config_data,
                    "scan_timestamp": time.time()
                }

            except Exception as e:
                print(f"Trivy execution failed: {e}, falling back to mock data")

        # 모의 데이터 생성 (Trivy가 없거나 실행 실패시)
        mock_vulnerabilities = [
            {
                "VulnerabilityID": "CVE-2019-1010083",
                "PkgName": "Flask",
                "InstalledVersion": "1.0.0",
                "FixedVersion": "1.1.0",
                "Severity": "CRITICAL",
                "Title": "Flask before 1.1.0 allows developers to load configurations from the environment",
                "Description": "Flask before 1.1.0 allows developers to load configurations from the environment by setting FLASK_ENV=development which enables debug mode"
            },
            {
                "VulnerabilityID": "CVE-2018-18074",
                "PkgName": "requests",
                "InstalledVersion": "2.19.0",
                "FixedVersion": "2.20.0",
                "Severity": "HIGH",
                "Title": "Request splitting vulnerability in requests",
                "Description": "HTTP request splitting vulnerability exists in requests"
            },
            {
                "VulnerabilityID": "CVE-2017-18342",
                "PkgName": "PyYAML",
                "InstalledVersion": "3.13",
                "FixedVersion": "5.1",
                "Severity": "CRITICAL",
                "Title": "PyYAML vulnerable to arbitrary code execution",
                "Description": "PyYAML allows arbitrary code execution via yaml.load()"
            },
            {
                "VulnerabilityID": "CVE-2019-10906",
                "PkgName": "Jinja2",
                "InstalledVersion": "2.10",
                "FixedVersion": "2.10.1",
                "Severity": "HIGH",
                "Title": "Jinja2 sandbox escape vulnerability",
                "Description": "Jinja2 sandbox can be escaped allowing code execution"
            }
        ]

        return {
            "scan_type": "trivy_mock",
            "filesystem_scan": {
                "Results": [
                    {
                        "Target": f"{target_path}/requirements.txt",
                        "Type": "requirements",
                        "Vulnerabilities": mock_vulnerabilities
                    }
                ]
            },
            "config_scan": {
                "Results": [
                    {
                        "Target": f"{target_path}/Dockerfile",
                        "Type": "dockerfile",
                        "Misconfigurations": [
                            {
                                "ID": "DS002",
                                "Title": "Root user used",
                                "Description": "Running containers as root user is not recommended",
                                "Severity": "HIGH"
                            },
                            {
                                "ID": "DS026",
                                "Title": "No healthcheck defined",
                                "Description": "Healthcheck instruction should be used",
                                "Severity": "MEDIUM"
                            }
                        ]
                    }
                ]
            },
            "scan_timestamp": time.time(),
            "total_vulnerabilities": len(mock_vulnerabilities)
        }

    except Exception as e:
        return {"error": f"Trivy scan failed: {str(e)}"}


@tool
def analyze_dependencies(project_path: str) -> Dict[str, Any]:
    """
    프로젝트 종속성의 보안 취약점을 분석합니다.

    Args:
        project_path: 프로젝트 경로

    Returns:
        종속성 취약점 분석 결과
    """
    try:
        vulnerabilities = []
        requirements_file = os.path.join(project_path, "requirements.txt")

        if not os.path.exists(requirements_file):
            return {"error": "requirements.txt not found"}

        # requirements.txt 파싱
        with open(requirements_file, 'r') as f:
            lines = f.readlines()

        # 취약한 패키지들의 데이터베이스 (실제로는 외부 API 사용)
        vulnerable_packages = {
            "flask": {
                "1.0.0": {
                    "cves": ["CVE-2019-1010083"],
                    "safe_version": "1.1.0",
                    "severity": "CRITICAL"
                }
            },
            "requests": {
                "2.19.0": {
                    "cves": ["CVE-2018-18074"],
                    "safe_version": "2.31.0",
                    "severity": "HIGH"
                }
            },
            "pyyaml": {
                "3.13": {
                    "cves": ["CVE-2017-18342"],
                    "safe_version": "6.0.1",
                    "severity": "CRITICAL"
                }
            },
            "jinja2": {
                "2.10": {
                    "cves": ["CVE-2019-10906"],
                    "safe_version": "3.1.0",
                    "severity": "HIGH"
                }
            }
        }

        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # 패키지 이름과 버전 추출
                if '==' in line:
                    package_name, version = line.split('==')
                    package_name = package_name.lower()

                    if package_name in vulnerable_packages:
                        if version in vulnerable_packages[package_name]:
                            vuln_data = vulnerable_packages[package_name][version]
                            vulnerabilities.append({
                                "package": package_name,
                                "current_version": version,
                                "safe_version": vuln_data["safe_version"],
                                "cves": vuln_data["cves"],
                                "severity": vuln_data["severity"],
                                "fix_command": f"pip install {package_name}>={vuln_data['safe_version']}"
                            })
                else:
                    # 버전이 명시되지 않은 경우
                    package_name = line.lower()
                    if package_name in vulnerable_packages:
                        vulnerabilities.append({
                            "package": package_name,
                            "current_version": "unspecified",
                            "safe_version": "latest",
                            "cves": [],
                            "severity": "UNKNOWN",
                            "fix_command": f"pip install {package_name} --upgrade"
                        })

        return {
            "dependencies_analyzed": len(lines),
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "scan_timestamp": time.time(),
            "summary": {
                "critical": len([v for v in vulnerabilities if v["severity"] == "CRITICAL"]),
                "high": len([v for v in vulnerabilities if v["severity"] == "HIGH"]),
                "medium": len([v for v in vulnerabilities if v["severity"] == "MEDIUM"]),
                "low": len([v for v in vulnerabilities if v["severity"] == "LOW"])
            }
        }

    except Exception as e:
        return {"error": f"Dependencies analysis failed: {str(e)}"}


@tool
def check_security_configs(project_path: str) -> Dict[str, Any]:
    """
    프로젝트의 보안 설정 및 코드 패턴을 정적 분석합니다.

    Args:
        project_path: 프로젝트 경로

    Returns:
        보안 이슈 분석 결과
    """
    try:
        issues = []

        # Python 파일들 검사
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    relative_path = os.path.relpath(filepath, project_path)

                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                            lines = content.split('\n')

                        # 패턴별 취약점 검사
                        for line_num, line in enumerate(lines, 1):
                            # SQL Injection 패턴
                            if re.search(r'f".*SELECT.*WHERE.*{.*}"', line) or \
                               re.search(r'".*SELECT.*WHERE.*".*\.format\(', line) or \
                               re.search(r'%.*SELECT.*WHERE.*%', line):
                                issues.append({
                                    "type": "SQL_INJECTION",
                                    "file": relative_path,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "severity": "CRITICAL",
                                    "description": "Potential SQL injection vulnerability"
                                })

                            # 하드코딩된 시크릿
                            if re.search(r'(SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*["\'].*["\']', line, re.IGNORECASE):
                                issues.append({
                                    "type": "HARDCODED_SECRET",
                                    "file": relative_path,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "severity": "HIGH",
                                    "description": "Hardcoded secret detected"
                                })

                            # XSS 취약점
                            if 'return f"<' in line or 'return "<' in line:
                                issues.append({
                                    "type": "XSS",
                                    "file": relative_path,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "severity": "HIGH",
                                    "description": "Potential XSS vulnerability"
                                })

                            # Command Injection
                            if re.search(r'subprocess.*shell=True', line) or \
                               re.search(r'os\.system\(', line):
                                issues.append({
                                    "type": "COMMAND_INJECTION",
                                    "file": relative_path,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "severity": "CRITICAL",
                                    "description": "Potential command injection vulnerability"
                                })

                            # Unsafe Deserialization
                            if 'pickle.loads(' in line or 'yaml.load(' in line:
                                issues.append({
                                    "type": "UNSAFE_DESERIALIZATION",
                                    "file": relative_path,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "severity": "CRITICAL",
                                    "description": "Unsafe deserialization detected"
                                })

                            # Debug mode 활성화
                            if re.search(r'debug\s*=\s*True', line, re.IGNORECASE):
                                issues.append({
                                    "type": "DEBUG_MODE",
                                    "file": relative_path,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "severity": "MEDIUM",
                                    "description": "Debug mode enabled in production"
                                })

                    except Exception as e:
                        continue

        # 설정 파일들 검사
        config_files = ['.env', 'config.yml', 'database.yml', 'docker-compose.yml']
        for config_file in config_files:
            config_path = os.path.join(project_path, config_file)
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                        lines = content.split('\n')

                    for line_num, line in enumerate(lines, 1):
                        # 하드코딩된 자격증명
                        if re.search(r'(password|secret|key|token)\s*[:=]\s*["\']?[^"\'\s]+', line, re.IGNORECASE):
                            if not line.strip().startswith('#'):  # 주석이 아닌 경우
                                issues.append({
                                    "type": "HARDCODED_CREDENTIALS",
                                    "file": config_file,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "severity": "HIGH",
                                    "description": "Hardcoded credentials in configuration"
                                })

                        # 취약한 네트워크 설정
                        if '0.0.0.0' in line:
                            issues.append({
                                "type": "INSECURE_NETWORK",
                                "file": config_file,
                                "line": line_num,
                                "code": line.strip(),
                                "severity": "MEDIUM",
                                "description": "Binding to all interfaces (0.0.0.0)"
                            })

                except Exception as e:
                    continue

        return {
            "security_issues": issues,
            "total_issues": len(issues),
            "files_scanned": len([f for f in os.listdir(project_path) if f.endswith('.py')]),
            "scan_timestamp": time.time(),
            "summary": {
                "critical": len([i for i in issues if i["severity"] == "CRITICAL"]),
                "high": len([i for i in issues if i["severity"] == "HIGH"]),
                "medium": len([i for i in issues if i["severity"] == "MEDIUM"]),
                "low": len([i for i in issues if i["severity"] == "LOW"])
            }
        }

    except Exception as e:
        return {"error": f"Security config check failed: {str(e)}"}