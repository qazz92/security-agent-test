"""
Semgrep SAST 코드 분석 툴
정적 코드 분석으로 코드 레벨 취약점 탐지
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Any

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SemgrepScanInput(BaseModel):
    """Input schema for semgrep_scan tool"""
    project_path: str = Field(
        description="스캔할 프로젝트 경로"
    )
    config: str = Field(
        default="auto",
        description="Semgrep 설정 (auto, p/security-audit, p/owasp-top-ten, p/python)"
    )


class SemgrepScanTool(BaseTool):
    """Semgrep을 사용한 SAST 코드 분석 도구"""

    name: str = "scan_with_semgrep"
    description: str = """
    Semgrep을 사용하여 코드 레벨의 보안 취약점을 스캔합니다.
    다음과 같은 취약점을 탐지합니다:
    - SQL Injection
    - XSS (Cross-Site Scripting)
    - Path Traversal
    - Command Injection
    - Hardcoded Secrets (API Keys, Passwords)
    - Insecure Deserialization
    - SSRF (Server-Side Request Forgery)
    - XXE (XML External Entity)
    - Logic Flaws
    """
    args_schema: type[BaseModel] = SemgrepScanInput

    def _run(self, project_path: str, config: str = "auto") -> Dict[str, Any]:
        """
        Semgrep 스캔 실행

        Args:
            project_path: 스캔할 프로젝트 경로
            config: Semgrep 설정 (auto, p/security-audit, p/owasp-top-ten)

        Returns:
            스캔 결과 딕셔너리
        """
        try:
            if not os.path.exists(project_path):
                return {"error": f"Project path does not exist: {project_path}"}

            logger.info(f"🔍 Starting Semgrep scan on {project_path} with config={config}")

            # Semgrep 명령어 구성
            cmd = [
                "semgrep",
                "scan",
                "--config", config,
                "--json",
                "--no-git-ignore",  # .gitignore 무시
                project_path
            ]

            # Semgrep 실행
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5분 타임아웃
            )

            # JSON 파싱
            if result.stdout:
                scan_results = json.loads(result.stdout)
            else:
                scan_results = {"results": []}

            # 결과 분석
            findings = scan_results.get("results", [])
            errors = scan_results.get("errors", [])

            # 심각도별 분류
            severity_count = {
                "ERROR": 0,
                "WARNING": 0,
                "INFO": 0
            }

            vulnerabilities = []

            for finding in findings:
                severity = finding.get("extra", {}).get("severity", "INFO").upper()
                severity_count[severity] = severity_count.get(severity, 0) + 1

                vuln = {
                    "rule_id": finding.get("check_id", "unknown"),
                    "severity": severity,
                    "message": finding.get("extra", {}).get("message", "No message"),
                    "file": finding.get("path", "unknown"),
                    "line_start": finding.get("start", {}).get("line", 0),
                    "line_end": finding.get("end", {}).get("line", 0),
                    "code_snippet": finding.get("extra", {}).get("lines", ""),
                    "category": self._extract_category(finding.get("check_id", "")),
                    "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp", []),
                    "fix": finding.get("extra", {}).get("fix", "")
                }
                vulnerabilities.append(vuln)

            # 카테고리별 통계
            categories = {}
            for vuln in vulnerabilities:
                cat = vuln["category"]
                categories[cat] = categories.get(cat, 0) + 1

            summary = {
                "total_findings": len(findings),
                "by_severity": severity_count,
                "by_category": categories,
                "errors": len(errors),
                "scan_config": config
            }

            logger.info(f"✅ Semgrep scan completed: {len(findings)} findings")
            logger.info(f"   ERROR: {severity_count.get('ERROR', 0)}, WARNING: {severity_count.get('WARNING', 0)}, INFO: {severity_count.get('INFO', 0)}")

            return {
                "success": True,
                "summary": summary,
                "vulnerabilities": vulnerabilities,
                "errors": errors,
                "project_path": project_path
            }

        except subprocess.TimeoutExpired:
            logger.error("❌ Semgrep scan timed out after 5 minutes")
            return {
                "success": False,
                "error": "Semgrep scan timed out after 5 minutes"
            }
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse Semgrep output: {e}")
            return {
                "success": False,
                "error": f"Failed to parse Semgrep output: {e}",
                "raw_output": result.stdout if result else None
            }
        except Exception as e:
            logger.error(f"❌ Semgrep scan failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def _extract_category(self, rule_id: str) -> str:
        """Rule ID로부터 취약점 카테고리 추출"""
        rule_lower = rule_id.lower()

        if "sql" in rule_lower or "sqli" in rule_lower:
            return "SQL Injection"
        elif "xss" in rule_lower or "cross-site" in rule_lower:
            return "XSS"
        elif "path-traversal" in rule_lower or "directory-traversal" in rule_lower:
            return "Path Traversal"
        elif "command" in rule_lower or "cmd-injection" in rule_lower:
            return "Command Injection"
        elif "secret" in rule_lower or "hardcoded" in rule_lower or "credential" in rule_lower:
            return "Hardcoded Secrets"
        elif "deserial" in rule_lower:
            return "Insecure Deserialization"
        elif "ssrf" in rule_lower:
            return "SSRF"
        elif "xxe" in rule_lower:
            return "XXE"
        elif "open-redirect" in rule_lower:
            return "Open Redirect"
        elif "csrf" in rule_lower:
            return "CSRF"
        elif "auth" in rule_lower:
            return "Authentication"
        elif "crypto" in rule_lower or "cipher" in rule_lower:
            return "Cryptography"
        else:
            return "Other"


class SemgrepConfigListInput(BaseModel):
    """Input schema for list_semgrep_configs tool"""
    pass


class SemgrepConfigListTool(BaseTool):
    """사용 가능한 Semgrep 설정 목록 조회 도구"""

    name: str = "list_semgrep_configs"
    description: str = "사용 가능한 Semgrep 스캔 설정 목록을 조회합니다. 프로젝트에 맞는 룰셋을 선택할 수 있습니다."
    args_schema: type[BaseModel] = SemgrepConfigListInput

    def _run(self) -> Dict[str, Any]:
        """사용 가능한 Semgrep 설정 목록 반환"""

        configs = {
            "auto": {
                "description": "자동 감지 (프로젝트 언어에 맞는 룰셋 자동 선택)",
                "use_case": "일반적인 스캔"
            },
            "p/security-audit": {
                "description": "보안 감사용 포괄적 룰셋",
                "use_case": "전체 보안 취약점 스캔"
            },
            "p/owasp-top-ten": {
                "description": "OWASP Top 10 취약점 룰셋",
                "use_case": "웹 애플리케이션 보안"
            },
            "p/python": {
                "description": "Python 전용 보안 룰셋",
                "use_case": "Python 프로젝트"
            },
            "p/javascript": {
                "description": "JavaScript/Node.js 보안 룰셋",
                "use_case": "JavaScript 프로젝트"
            },
            "p/java": {
                "description": "Java 보안 룰셋",
                "use_case": "Java 프로젝트"
            },
            "p/golang": {
                "description": "Go 보안 룰셋",
                "use_case": "Go 프로젝트"
            },
            "p/ci": {
                "description": "CI/CD 파이프라인용 경량 룰셋",
                "use_case": "빠른 스캔"
            }
        }

        return {
            "success": True,
            "configs": configs,
            "recommended": "auto"
        }


# Tool 인스턴스 생성 (LangChain compatibility)
_semgrep_scan_tool = SemgrepScanTool()
_semgrep_config_tool = SemgrepConfigListTool()

# CrewAI-compatible tool wrappers
from crewai.tools import tool

@tool("Scan With Semgrep")
def scan_with_semgrep(project_path: str, config: str = "auto") -> dict:
    """Semgrep을 사용하여 SAST 코드 분석을 수행합니다. SQL Injection, XSS, Command Injection 등의 코드 레벨 취약점을 탐지합니다."""
    logger.info(f"🔧 [TOOL CALL] Scan With Semgrep - Path: {project_path}, Config: {config}")
    result = _semgrep_scan_tool._run(project_path=project_path, config=config)
    if result.get('success'):
        summary = result.get('summary', {})
        logger.info(f"✅ [TOOL DONE] Semgrep - Findings: {summary.get('total_findings', 0)}")
    return result

@tool("List Semgrep Configs")
def list_semgrep_configs() -> dict:
    """Semgrep에서 사용 가능한 설정 목록을 반환합니다. 다양한 보안 룰셋과 프레임워크별 설정을 확인할 수 있습니다."""
    logger.info(f"🔧 [TOOL CALL] List Semgrep Configs")
    result = _semgrep_config_tool._run()
    logger.info(f"✅ [TOOL DONE] List Semgrep Configs")
    return result
