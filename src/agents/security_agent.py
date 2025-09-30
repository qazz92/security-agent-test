"""
보안 분석 에이전트
취약점 탐지 및 분석을 담당
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from ..models.llm_config import create_security_llm, SecurityModelSelector, PromptTemplates
from ..tools.scanner_tools import fetch_project_info, scan_with_trivy, analyze_dependencies, check_security_configs
from ..tools.analysis_tools import calculate_priority_score, analyze_vulnerability_trends, generate_security_metrics, generate_compliance_report


class SecurityAnalysisAgent:
    """보안 분석 전문 에이전트"""

    def __init__(self, verbose: bool = True):
        # 보안 분석에는 가장 보수적이고 정확한 모델 사용
        self.llm = create_security_llm(
            task_type="pattern_detection",
            security_level="CRITICAL"
        )
        self.verbose = verbose

        # 분석 도구들
        self.analysis_tools = [
            fetch_project_info,
            scan_with_trivy,
            analyze_dependencies,
            check_security_configs,
            calculate_priority_score,
            analyze_vulnerability_trends,
            generate_security_metrics,
            generate_compliance_report
        ]

        # 에이전트 초기화
        self.agent_executor = self._create_agent()

        # 분석 결과 저장
        self.analysis_results = {}
        self.performance_metrics = {
            "start_time": None,
            "end_time": None,
            "tools_used": [],
            "vulnerabilities_found": 0
        }

    def _create_agent(self) -> AgentExecutor:
        """보안 분석 에이전트 생성 - LangChain 0.3.x 호환"""

        # 프롬프트 템플릿 설정 (Tool Calling Agent용)
        system_prompt = """You are a senior security engineer specialized in comprehensive vulnerability analysis.

Your responsibilities:
1. Systematically analyze projects for security vulnerabilities
2. Use multiple scanning tools to ensure comprehensive coverage
3. Prioritize findings based on severity and exploitability
4. Provide detailed technical analysis with actionable insights
5. Generate security metrics and compliance reports

Analysis Workflow:
1. Gather project information and structure
2. Perform Trivy scans for known vulnerabilities
3. Analyze dependencies for CVEs
4. Conduct static code analysis for security patterns
5. Calculate priority scores for each finding
6. Generate trend analysis and metrics
7. Create compliance reports

For each vulnerability found, provide:
- Technical description and impact
- CVSS severity assessment
- Exploitation scenarios
- Business impact analysis
- Recommended priority level

Be thorough, accurate, and focus on actionable security insights."""

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad")
        ])

        # LangChain 0.3.x의 새로운 Tool Calling Agent 생성
        agent = create_tool_calling_agent(
            llm=self.llm,
            tools=self.analysis_tools,
            prompt=prompt
        )

        return AgentExecutor(
            agent=agent,
            tools=self.analysis_tools,
            verbose=self.verbose,
            handle_parsing_errors=True,
            max_iterations=10,
            return_intermediate_steps=True
        )

    async def analyze_project(self, project_path: str, user_query: str = None) -> Dict[str, Any]:
        """프로젝트 보안 분석 실행"""

        self.performance_metrics["start_time"] = time.time()

        try:
            # 분석 요청 구성
            analysis_prompt = f"""
Perform a comprehensive security analysis of the project at: {project_path}

Analysis Requirements:
1. Fetch project information and understand structure
2. Run Trivy scan for container and dependency vulnerabilities
3. Analyze all dependencies for known CVEs
4. Perform static code analysis for security anti-patterns
5. Calculate priority scores for all findings
6. Generate vulnerability trend analysis
7. Create security metrics and compliance report

User Query: {user_query or 'Comprehensive security analysis'}

Please follow the workflow systematically and provide detailed findings.
Start with project information gathering, then proceed with security scans.
"""

            # 에이전트 실행
            if self.verbose:
                print("\n🔍 Starting comprehensive security analysis...")
                print("   [1/7] Fetching project information...")

            result = await self._run_agent_async(analysis_prompt)

            if self.verbose:
                print("   [2/7] Running Trivy vulnerability scan...")
                print("   [3/7] Analyzing dependencies for CVEs...")
                print("   [4/7] Checking security configurations...")
                print("   [5/7] Calculating priority scores...")
                print("   [6/7] Analyzing vulnerability trends...")
                print("   [7/7] Generating security metrics...")

            # 결과 처리
            self.performance_metrics["end_time"] = time.time()
            self.performance_metrics["duration"] = (
                self.performance_metrics["end_time"] - self.performance_metrics["start_time"]
            )

            # 분석 결과 구조화
            analysis_results = self._structure_analysis_results(result, project_path)

            self.analysis_results = analysis_results
            return analysis_results

        except Exception as e:
            self.performance_metrics["end_time"] = time.time()
            return {
                "error": f"Security analysis failed: {str(e)}",
                "project_path": project_path,
                "analysis_timestamp": time.time()
            }

    async def _run_agent_async(self, prompt: str) -> Dict[str, Any]:
        """비동기로 에이전트 실행"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.agent_executor.invoke({"input": prompt})
        )

    def _structure_analysis_results(self, raw_result: Dict[str, Any], project_path: str) -> Dict[str, Any]:
        """분석 결과를 구조화된 형태로 변환"""

        # 중간 단계에서 도구 호출 결과 추출
        intermediate_steps = raw_result.get("intermediate_steps", [])
        tool_results = {}

        for step in intermediate_steps:
            if len(step) >= 2:
                action, observation = step[0], step[1]
                tool_name = getattr(action, 'tool', 'unknown')

                # JSON 파싱 시도
                try:
                    if isinstance(observation, str):
                        import json
                        observation = json.loads(observation)
                except:
                    pass

                tool_results[tool_name] = observation
                self.performance_metrics["tools_used"].append(tool_name)

        # 취약점 수집 및 정리
        vulnerabilities = []
        total_risk_score = 0

        # Trivy 결과 처리
        if 'scan_with_trivy' in tool_results:
            trivy_data = tool_results['scan_with_trivy']
            if 'filesystem_scan' in trivy_data and 'Results' in trivy_data['filesystem_scan']:
                for result in trivy_data['filesystem_scan']['Results']:
                    if 'Vulnerabilities' in result:
                        vulnerabilities.extend(result['Vulnerabilities'])

        # 정적 분석 결과 처리
        if 'check_security_configs' in tool_results:
            security_issues = tool_results['check_security_configs'].get('security_issues', [])
            vulnerabilities.extend(security_issues)

        self.performance_metrics["vulnerabilities_found"] = len(vulnerabilities)

        # 심각도별 분류
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get('Severity', vuln.get('severity', 'UNKNOWN')).upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            "project_path": project_path,
            "analysis_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_distribution": severity_counts,
                "analysis_duration": self.performance_metrics.get("duration", 0),
                "tools_used": list(set(self.performance_metrics["tools_used"])),
                "analysis_timestamp": time.time()
            },
            "detailed_results": {
                "project_info": tool_results.get('fetch_project_info', {}),
                "trivy_scan": tool_results.get('scan_with_trivy', {}),
                "dependency_analysis": tool_results.get('analyze_dependencies', {}),
                "security_config_scan": tool_results.get('check_security_configs', {}),
                "vulnerability_trends": tool_results.get('analyze_vulnerability_trends', {}),
                "security_metrics": tool_results.get('generate_security_metrics', {}),
                "compliance_report": tool_results.get('generate_compliance_report', {})
            },
            "vulnerabilities": vulnerabilities,
            "agent_output": raw_result.get("output", ""),
            "performance_metrics": self.performance_metrics,
            "recommendations": self._generate_recommendations(vulnerabilities, severity_counts)
        }

    def _generate_recommendations(self, vulnerabilities: List[Dict], severity_counts: Dict[str, int]) -> List[str]:
        """분석 결과 기반 권장사항 생성"""
        recommendations = []

        if severity_counts["CRITICAL"] > 0:
            recommendations.append(f"🚨 즉시 조치 필요: {severity_counts['CRITICAL']}개의 Critical 취약점 발견")

        if severity_counts["HIGH"] > 0:
            recommendations.append(f"⚠️ 우선 수정: {severity_counts['HIGH']}개의 High 취약점 발견")

        # 취약점 패턴 분석
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', vuln.get('VulnerabilityID', 'Unknown'))
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        # 가장 많은 취약점 타입
        if vuln_types:
            most_common = max(vuln_types.items(), key=lambda x: x[1])
            if most_common[1] > 1:
                recommendations.append(f"🔍 {most_common[0]} 타입 취약점이 {most_common[1]}개 발견됨 - 패턴 검토 필요")

        # 종속성 관련 권장사항
        if any('CVE' in str(vuln) for vuln in vulnerabilities):
            recommendations.append("📦 종속성 업데이트를 통한 CVE 수정 권장")

        # 일반적인 보안 권장사항
        if len(vulnerabilities) > 10:
            recommendations.append("🛡️ 정기적인 보안 스캔 프로세스 구축 권장")

        recommendations.append("📋 모든 수정사항에 대한 테스트 케이스 작성 필요")

        return recommendations

    def get_analysis_summary(self) -> str:
        """분석 결과 요약 텍스트 생성"""
        if not self.analysis_results:
            return "No analysis results available."

        summary = self.analysis_results.get("analysis_summary", {})

        return f"""
🔒 보안 분석 완료

📊 요약:
- 총 취약점: {summary.get('total_vulnerabilities', 0)}개
- Critical: {summary.get('severity_distribution', {}).get('CRITICAL', 0)}개
- High: {summary.get('severity_distribution', {}).get('HIGH', 0)}개
- Medium: {summary.get('severity_distribution', {}).get('MEDIUM', 0)}개
- Low: {summary.get('severity_distribution', {}).get('LOW', 0)}개

⏱️ 분석 시간: {summary.get('analysis_duration', 0):.1f}초
🔧 사용된 도구: {len(summary.get('tools_used', []))}개

{'🚨 즉시 조치 필요!' if summary.get('severity_distribution', {}).get('CRITICAL', 0) > 0 else '✅ Critical 취약점 없음'}
"""