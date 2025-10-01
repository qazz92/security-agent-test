"""
Semgrep SAST 코드 분석 툴
정적 코드 분석으로 코드 레벨 취약점 탐지

V2 개선사항:
- LLM 기반 취약점 카테고리 분류 (하드코딩 제거)
- 표준 취약점 타입으로 자동 변환 (SQL_INJECTION, XSS 등)
"""

import os
import json
import subprocess
import logging
from typing import Dict, List, Any

from langchain_core.tools import BaseTool
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

from ..utils.model_selector import get_model_selector, TaskComplexity, ModelConfig
import litellm

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

            # 먼저 모든 취약점 정보를 수집 (category 없이)
            for finding in findings:
                severity = finding.get("extra", {}).get("severity", "INFO").upper()
                severity_count[severity] = severity_count.get(severity, 0) + 1

                message = finding.get("extra", {}).get("message", "No message")
                rule_id = finding.get("check_id", "unknown")

                vuln = {
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": message,
                    "file": finding.get("path", "unknown"),
                    "line_start": finding.get("start", {}).get("line", 0),
                    "line_end": finding.get("end", {}).get("line", 0),
                    "code_snippet": finding.get("extra", {}).get("lines", ""),
                    "category": None,  # 배치로 처리 예정
                    "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp", []),
                    "fix": finding.get("extra", {}).get("fix", "")
                }
                vulnerabilities.append(vuln)

            # 🚀 배치 처리: 모든 취약점의 카테고리를 한 번에 분류
            if vulnerabilities:
                categories_batch = self._extract_categories_batch(vulnerabilities)
                for i, vuln in enumerate(vulnerabilities):
                    vuln["category"] = categories_batch.get(i, "OTHER")

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

    def _extract_categories_batch(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[int, str]:
        """
        배치로 모든 취약점의 카테고리를 한 번에 추출 (성능 최적화)

        Args:
            vulnerabilities: 취약점 리스트

        Returns:
            {index: category} 딕셔너리
        """
        try:
            # 배치 입력 생성
            batch_input = []
            for i, vuln in enumerate(vulnerabilities):
                batch_input.append(f"{i}. Rule: {vuln['rule_id']}, Message: {vuln['message'][:100]}")

            batch_text = "\n".join(batch_input)

            system_prompt = """You are a security vulnerability classifier.

Given a numbered list of Semgrep findings, classify EACH one into ONE of these EXACT vulnerability types:

**Supported Types (MUST use exactly):**
- SQL_INJECTION
- XSS
- COMMAND_INJECTION
- PATH_TRAVERSAL
- SSRF
- XXE
- HARDCODED_SECRET
- UNSAFE_DESERIALIZATION
- OPEN_REDIRECT
- CSRF
- WEAK_CRYPTO
- DEBUG_MODE
- AUTHENTICATION
- OTHER

**Output Format:**
Return ONLY a JSON object mapping index to type:
{"0": "SQL_INJECTION", "1": "XSS", "2": "HARDCODED_SECRET", ...}

NO explanations, NO markdown, just the JSON object."""

            user_prompt = f"Classify these vulnerabilities:\n\n{batch_text}\n\nJSON output:"

            # Get model config
            config = ModelConfig.INSTRUCT
            model_name = f"openrouter/{config['model']}"

            # 배치 호출
            response = litellm.completion(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=2000,  # 배치 응답을 위한 충분한 토큰
                api_key=os.getenv('OPENROUTER_API_KEY'),
                api_base=os.getenv('OPENAI_API_BASE', 'https://openrouter.ai/api/v1')
            )

            # JSON 파싱
            content = response.choices[0].message.content.strip()

            # JSON 추출 (마크다운 코드 블록 제거)
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]

            categories_map = json.loads(content)

            # 인덱스를 정수로 변환
            result = {}
            for key, value in categories_map.items():
                result[int(key)] = value.upper()

            logger.info(f"✅ Batch category extraction: {len(result)} vulnerabilities classified")
            return result

        except Exception as e:
            logger.error(f"❌ Batch category extraction failed: {e}")
            # Fallback: 개별 처리
            logger.info("Falling back to individual category extraction...")
            result = {}
            for i, vuln in enumerate(vulnerabilities):
                result[i] = self._extract_category(vuln['rule_id'], vuln['message'])
            return result

    def _extract_category(self, rule_id: str, message: str = "") -> str:
        """
        LLM 기반 취약점 카테고리 추출 (하드코딩 제거)

        Args:
            rule_id: Semgrep rule ID (예: python.flask.security.injection.tainted-sql-string)
            message: 취약점 설명 메시지

        Returns:
            표준 취약점 타입 (예: SQL_INJECTION, XSS, COMMAND_INJECTION 등)
        """
        try:
            # Use LiteLLM directly to ensure global callbacks (Langfuse + model name cleanup) are applied
            system_prompt = """You are a security vulnerability classifier.

Given a Semgrep rule ID and message, classify it into ONE of these EXACT vulnerability types:

**Supported Types (MUST use exactly):**
- SQL_INJECTION
- XSS
- COMMAND_INJECTION
- PATH_TRAVERSAL
- SSRF
- XXE
- HARDCODED_SECRET
- UNSAFE_DESERIALIZATION
- OPEN_REDIRECT
- CSRF
- WEAK_CRYPTO
- DEBUG_MODE
- AUTHENTICATION
- OTHER

**Output Format:**
Return ONLY the vulnerability type string, nothing else.
NO explanations, NO JSON, just the type.

Examples:
Input: "python.flask.security.injection.tainted-sql-string"
Output: SQL_INJECTION

Input: "python.flask.security.xss.audit.directly-returned-format-string"
Output: XSS

Input: "python.lang.security.insecure-hash-algorithm-md5"
Output: WEAK_CRYPTO"""

            user_prompt = f"Rule ID: {rule_id}\nMessage: {message[:200]}\n\nVulnerability type:"

            # Get model config for SIMPLE_EXTRACTION task
            config = ModelConfig.INSTRUCT  # Simple extraction uses instruct model
            model_name = f"openrouter/{config['model']}"  # CrewAI/LiteLLM needs prefix

            # Call LiteLLM directly - global callbacks will automatically apply
            response = litellm.completion(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=config["temperature"],
                max_tokens=50,  # Very short response needed
                api_key=os.getenv('OPENROUTER_API_KEY'),
                api_base=os.getenv('OPENAI_API_BASE', 'https://openrouter.ai/api/v1')
            )

            # Extract type from response
            vuln_type = response.choices[0].message.content.strip().upper()

            # Validate it's a known type
            valid_types = [
                "SQL_INJECTION", "XSS", "COMMAND_INJECTION", "PATH_TRAVERSAL",
                "SSRF", "XXE", "HARDCODED_SECRET", "UNSAFE_DESERIALIZATION",
                "OPEN_REDIRECT", "CSRF", "WEAK_CRYPTO", "DEBUG_MODE",
                "AUTHENTICATION", "OTHER"
            ]

            if vuln_type not in valid_types:
                logger.warning(f"LLM returned invalid type '{vuln_type}', using 'OTHER'")
                return "OTHER"

            return vuln_type

        except Exception as e:
            logger.error(f"LLM category extraction failed: {e}")
            # Fallback to simple keyword matching
            rule_lower = rule_id.lower()
            if "sql" in rule_lower:
                return "SQL_INJECTION"
            elif "xss" in rule_lower:
                return "XSS"
            elif "command" in rule_lower:
                return "COMMAND_INJECTION"
            elif "path" in rule_lower:
                return "PATH_TRAVERSAL"
            elif "ssrf" in rule_lower:
                return "SSRF"
            else:
                return "OTHER"


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
