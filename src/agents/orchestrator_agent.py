"""
오케스트레이터 에이전트
CrewAI 기반 다중 에이전트 보안 분석 워크플로우 조율
"""

import asyncio
import time
import json
import logging
import os
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

            # CrewAI 결과 구조화
            workflow_results = {
                "workflow_metadata": {
                    "project_path": project_path,
                    "user_query": user_query,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "workflow_version": "2.0-crewai",
                    "orchestration_mode": "crewai",
                    "agents_used": crew_result.get("agents_used", [])
                },
                "crewai_result": crew_result.get("result", ""),
                "success": crew_result.get("success", False),
                "performance_metrics": self.performance_metrics,
                "github_repo_url": github_repo_url
            }

            self.workflow_results = workflow_results

            logger.info("✅ CrewAI analysis completed successfully")
            logger.info(f"⏱️ Total duration: {self.performance_metrics['total_duration']:.1f}s")

            return workflow_results

        except Exception as e:
            logger.error(f"❌ CrewAI analysis failed: {e}")
            return self._create_error_result(
                f"CrewAI workflow execution failed: {str(e)}",
                project_path
            )

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