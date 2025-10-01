"""
오케스트레이터 에이전트
CrewAI 기반 다중 에이전트 보안 분석 워크플로우 조율
"""

import asyncio
import time
import json
import logging
import os
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

from .security_crew import SecurityCrewManager
from ..models.llm_config import create_security_llm, SecurityModelSelector

# 로거 설정
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class SecurityOrchestrator:
    """CrewAI 기반 보안 분석 및 수정 워크플로우 오케스트레이터"""

    def __init__(self, verbose: bool = True):
        """
        Args:
            verbose: 상세 로깅 활성화
        """
        self.verbose = verbose

        # CrewAI 방식: 다중 에이전트 자동 협업
        logger.info("🤖 Using CrewAI for multi-agent orchestration")
        self.crew_manager = SecurityCrewManager(verbose=verbose)

        # 전체 워크플로우 결과 저장
        self.workflow_results = {}
        self.performance_metrics = {
            "workflow_start_time": None,
            "workflow_end_time": None,
            "total_duration": None,
            "phases_completed": [],
            "agents_used": [],
            "orchestration_mode": "crewai"
        }

    async def analyze_and_remediate(
        self,
        project_path: str,
        user_query: str = "Comprehensive security analysis and remediation"
    ) -> Dict[str, Any]:
        """CrewAI 기반 보안 분석 및 수정 방안 생성 워크플로우 실행"""

        # 🚀 FAST_TEST_MODE: 캐시된 결과 사용 (빠른 테스트용)
        if os.environ.get('FAST_TEST_MODE') == 'true':
            cached_result = self._load_last_result()
            if cached_result:
                logger.info("⚡ FAST_TEST_MODE: Using cached result (skipping analysis)")
                return cached_result

        self.performance_metrics["workflow_start_time"] = time.time()

        try:
            logger.info("🤖 Starting CrewAI-based security analysis...")

            # CrewAI Crew 실행 (비동기 래퍼)
            loop = asyncio.get_event_loop()
            github_repo_url = os.environ.get('GITHUB_REPO_URL', 'https://github.com/qazz92/security-agent-test')

            crew_result = await loop.run_in_executor(
                None,
                lambda: self.crew_manager.analyze_project(project_path, github_repo_url)
            )

            # 성능 메트릭 업데이트
            self.performance_metrics["workflow_end_time"] = time.time()
            self.performance_metrics["total_duration"] = (
                self.performance_metrics["workflow_end_time"] -
                self.performance_metrics["workflow_start_time"]
            )
            self.performance_metrics["agents_used"] = crew_result.get("agents_used", [])
            self.performance_metrics["phases_completed"] = ["crewai_analysis"]

            # CrewAI 결과를 Streamlit 호환 형식으로 변환
            raw_result = crew_result.get("result", "")
            # CrewOutput 객체를 문자열로 변환
            if hasattr(raw_result, 'raw'):
                raw_result_str = str(raw_result.raw)
            elif hasattr(raw_result, '__str__'):
                raw_result_str = str(raw_result)
            else:
                raw_result_str = ""

            parsed_result = self._parse_crewai_result(raw_result_str)

            # Streamlit 호환 구조로 구조화
            workflow_results = {
                "workflow_metadata": {
                    "project_path": project_path,
                    "user_query": user_query,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "workflow_version": "2.0-crewai",
                    "orchestration_mode": "crewai",
                    "agents_used": crew_result.get("agents_used", [])
                },
                "security_analysis": parsed_result.get("security_analysis", {}),
                "remediation_plan": parsed_result.get("remediation_plan", {}),
                "final_report": parsed_result.get("final_report", {}),
                "executive_summary": parsed_result.get("executive_summary", raw_result_str[:500] + "..."),
                "crewai_result": raw_result_str,
                "success": crew_result.get("success", False),
                "performance_metrics": self.performance_metrics,
                "github_repo_url": github_repo_url
            }

            self.workflow_results = workflow_results

            # 결과를 파일로 저장 (빠른 테스트용)
            self._save_last_result(workflow_results)

            logger.info("✅ CrewAI analysis completed successfully")
            logger.info(f"⏱️ Total duration: {self.performance_metrics['total_duration']:.1f}s")

            return workflow_results

        except Exception as e:
            logger.error(f"❌ CrewAI analysis failed: {e}")
            return self._create_error_result(
                f"CrewAI workflow execution failed: {str(e)}",
                project_path
            )

    def _parse_crewai_result(self, raw_result: str) -> Dict[str, Any]:
        """CrewAI 결과를 구조화된 JSON으로 변환 (JSON 우선, Fallback: Regex)"""

        # 기본 구조
        parsed = {
            "security_analysis": {
                "vulnerabilities": [],
                "analysis_summary": {
                    "total_vulnerabilities": 0,
                    "severity_distribution": {},
                    "analysis_duration": self.performance_metrics.get("total_duration", 0)
                }
            },
            "remediation_plan": {},
            "final_report": {},
            "executive_summary": ""
        }

        try:
            import json

            agent_json = None

            # 🚀 Simple approach: Find ```json ... ``` block
            if "```json" in raw_result:
                start_marker = "```json"
                end_marker = "```"

                start_idx = raw_result.find(start_marker)
                if start_idx != -1:
                    # Find the end marker after start_marker
                    start_idx += len(start_marker)
                    end_idx = raw_result.find(end_marker, start_idx)

                    if end_idx != -1:
                        json_text = raw_result[start_idx:end_idx].strip()

                        try:
                            agent_json = json.loads(json_text)
                            logger.info("✅ Found JSON in markdown block (```json ... ```)")
                        except json.JSONDecodeError as e:
                            logger.warning(f"⚠️ JSON parsing failed at position {e.pos}: {e.msg}")
                            logger.debug(f"   JSON snippet around error: {json_text[max(0, e.pos-50):e.pos+50]}")

            # Fallback: Try parsing entire response as JSON
            if agent_json is None:
                try:
                    agent_json = json.loads(raw_result)
                    logger.info("✅ Parsed entire response as JSON (no markdown wrapper)")
                except json.JSONDecodeError as e:
                    logger.warning(f"⚠️ No valid JSON found in Agent output: {e.msg}")

            if agent_json:

                # JSON 데이터 직접 사용
                summary = agent_json.get("summary", {})
                vulnerabilities = agent_json.get("vulnerabilities", [])

                # 취약점 리스트 변환
                for vuln in vulnerabilities:
                    parsed["security_analysis"]["vulnerabilities"].append({
                        "type": vuln.get("type", "Unknown"),
                        "file": vuln.get("file", "unknown"),
                        "severity": vuln.get("severity", "HIGH"),
                        "line": 0,
                        "description": vuln.get("description", ""),
                        "code": vuln.get("before_code", "N/A")
                    })

                # Summary 직접 사용
                total_vulns = summary.get("total_vulnerabilities", len(vulnerabilities))
                critical_count = summary.get("critical_count", 0)
                high_count = summary.get("high_count", 0)
                medium_count = summary.get("medium_count", 0)
                low_count = summary.get("low_count", 0)

                parsed["security_analysis"]["analysis_summary"] = {
                    "total_vulnerabilities": total_vulns,
                    "severity_distribution": {
                        "CRITICAL": critical_count,
                        "HIGH": high_count,
                        "MEDIUM": medium_count,
                        "LOW": low_count
                    },
                    "analysis_duration": self.performance_metrics.get("total_duration", 0)
                }

                # PR 템플릿
                pr_template = agent_json.get("pr_template", raw_result)
                parsed["executive_summary"] = pr_template[:1000] if len(pr_template) > 1000 else pr_template

            else:
                # 🔄 Fallback: Regex 파싱 (기존 방식)
                logger.warning("⚠️ No JSON found, falling back to regex parsing")

                vuln_headers = re.findall(r'###\s*(\d+)\.\s*([^\n]+)', raw_result)

                for idx, full_title in vuln_headers:
                    match = re.match(r'([^\(]+)\s*\(([^\)]+)\)', full_title)
                    if match:
                        vuln_type = match.group(1).strip()
                        file_info = match.group(2).strip()
                    else:
                        vuln_type = full_title.strip()
                        file_info = "unknown"

                    vuln_type_lower = vuln_type.lower()
                    if any(keyword in vuln_type_lower for keyword in ['sql injection', 'command injection', 'hardcoded', 'deserialization']):
                        severity = "CRITICAL"
                    elif any(keyword in vuln_type_lower for keyword in ['xss', 'ssrf', 'xxe', 'path traversal', 'open redirect']):
                        severity = "HIGH"
                    elif any(keyword in vuln_type_lower for keyword in ['weak crypto', 'csrf']):
                        severity = "MEDIUM"
                    else:
                        severity = "HIGH"

                    parsed["security_analysis"]["vulnerabilities"].append({
                        "type": vuln_type,
                        "file": file_info,
                        "severity": severity,
                        "line": 0,
                        "description": f"{vuln_type} vulnerability in {file_info}",
                        "code": "N/A"
                    })

                # Severity 계산
                severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for vuln in parsed["security_analysis"]["vulnerabilities"]:
                    severity_counts[vuln["severity"]] += 1

                total_vulns = len(parsed["security_analysis"]["vulnerabilities"])
                critical_count = severity_counts["CRITICAL"]
                high_count = severity_counts["HIGH"]
                medium_count = severity_counts["MEDIUM"]
                low_count = severity_counts["LOW"]

                parsed["security_analysis"]["analysis_summary"] = {
                    "total_vulnerabilities": total_vulns,
                    "severity_distribution": severity_counts,
                    "analysis_duration": self.performance_metrics.get("total_duration", 0)
                }

                parsed["executive_summary"] = raw_result[:1000] + "..."

            # 공통: 보안 점수 및 리포트 생성
            critical_count = parsed["security_analysis"]["analysis_summary"]["severity_distribution"]["CRITICAL"]
            high_count = parsed["security_analysis"]["analysis_summary"]["severity_distribution"]["HIGH"]
            medium_count = parsed["security_analysis"]["analysis_summary"]["severity_distribution"]["MEDIUM"]
            low_count = parsed["security_analysis"]["analysis_summary"]["severity_distribution"]["LOW"]
            total_vulns = parsed["security_analysis"]["analysis_summary"]["total_vulnerabilities"]

            security_score = max(0, 100 - (critical_count * 25 + high_count * 10 + medium_count * 5 + low_count * 2))
            risk_level = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM" if medium_count > 0 else "LOW"

            parsed["remediation_plan"] = {
                "remediation_summary": {
                    "fixes_generated": total_vulns,
                    "pr_template_created": True,
                    "estimated_effort": {"total_hours": total_vulns * 2}
                },
                "detailed_remediation": {
                    "pr_template": raw_result
                }
            }

            parsed["final_report"] = {
                "security_posture": {
                    "overall_score": security_score,
                    "risk_level": risk_level,
                    "vulnerabilities_summary": {
                        "immediate_action_required": critical_count > 0
                    }
                },
                "recommendations": [
                    f"즉시 {critical_count}개 Critical 취약점 수정" if critical_count > 0 else None,
                    f"{high_count}개 High 취약점 7일 내 수정" if high_count > 0 else None,
                    "정기적인 보안 스캔 도입",
                    "개발팀 보안 교육 실시"
                ]
            }
            parsed["final_report"]["recommendations"] = [r for r in parsed["final_report"]["recommendations"] if r]

        except Exception as e:
            logger.error(f"❌ Failed to parse CrewAI result: {e}")
            import traceback
            logger.error(traceback.format_exc())
            parsed["executive_summary"] = raw_result[:1000] + "..."

        return parsed

    def _save_last_result(self, results: Dict[str, Any]) -> None:
        """마지막 분석 결과를 파일로 저장 (raw crewai_result만 저장)"""
        try:
            cache_dir = "/app/results"
            os.makedirs(cache_dir, exist_ok=True)
            cache_file = os.path.join(cache_dir, "last_analysis_result.json")

            # Raw crewai_result와 메타데이터만 저장 (파싱 결과는 저장하지 않음)
            cache_data = {
                "crewai_result": results.get("crewai_result", ""),
                "workflow_metadata": results.get("workflow_metadata", {}),
                "performance_metrics": results.get("performance_metrics", {}),
                "github_repo_url": results.get("github_repo_url", ""),
                "success": results.get("success", False)
            }

            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, default=str, ensure_ascii=False)

            logger.info(f"💾 Raw analysis result cached to {cache_file}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to cache result: {e}")

    def _load_last_result(self) -> Optional[Dict[str, Any]]:
        """캐시된 raw result를 로드하고 무조건 새로 파싱"""
        try:
            cache_file = "/app/results/last_analysis_result.json"
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)

                crewai_result = cached_data.get("crewai_result", "")

                if not crewai_result or len(crewai_result) < 100:
                    logger.warning("⚠️ Cached result is empty or too short")
                    return None

                logger.info("📂 Loaded cached raw result, parsing now...")

                # 무조건 새로 파싱 (최신 파싱 로직 적용)
                parsed_result = self._parse_crewai_result(crewai_result)

                # 완전한 결과 구조 생성
                result = {
                    "workflow_metadata": cached_data.get("workflow_metadata", {}),
                    "security_analysis": parsed_result.get("security_analysis", {}),
                    "remediation_plan": parsed_result.get("remediation_plan", {}),
                    "final_report": parsed_result.get("final_report", {}),
                    "executive_summary": parsed_result.get("executive_summary", crewai_result[:500] + "..."),
                    "crewai_result": crewai_result,
                    "success": cached_data.get("success", False),
                    "performance_metrics": cached_data.get("performance_metrics", {}),
                    "github_repo_url": cached_data.get("github_repo_url", "")
                }

                vuln_count = result['security_analysis']['analysis_summary']['total_vulnerabilities']
                logger.info(f"   ✅ Parsing complete: {vuln_count} vulnerabilities found")

                return result
            else:
                logger.info("ℹ️ No cached result found")
                return None
        except Exception as e:
            logger.warning(f"⚠️ Failed to load cached result: {e}")
            return None

    def _create_error_result(self, error_message: str, project_path: str, *args) -> Dict[str, Any]:
        """에러 결과 생성"""
        return {
            "error": error_message,
            "project_path": project_path,
            "timestamp": datetime.now().isoformat(),
            "success": False
        }

    def get_workflow_summary(self) -> str:
        """워크플로우 요약 생성"""

        if not self.workflow_results:
            return "No workflow results available."

        performance = self.performance_metrics
        metadata = self.workflow_results.get("workflow_metadata", {})

        return f"""
🎯 CrewAI Workflow Summary:
  - Total Duration: {performance.get('total_duration', 0):.1f} seconds
  - Orchestration Mode: {metadata.get('orchestration_mode', 'crewai')}
  - Agents Used: {', '.join(performance.get('agents_used', []))}
  - Success: {'✅' if self.workflow_results.get('success') else '❌'}

✅ Ready for review!
"""

    def save_results(self, output_file: str = None) -> str:
        """결과를 파일로 저장"""

        if not self.workflow_results:
            return "No results to save."

        output_file = output_file or f"security_analysis_{int(time.time())}.json"

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.workflow_results, f, indent=2, ensure_ascii=False, default=str)

            return f"Results saved to {output_file}"

        except Exception as e:
            return f"Failed to save results: {str(e)}"