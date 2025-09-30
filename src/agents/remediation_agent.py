"""
수정 방안 생성 에이전트
취약점 수정 코드 생성 및 PR 템플릿 작성을 담당
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from ..models.llm_config import create_security_llm, SecurityModelSelector, PromptTemplates
from ..tools.fix_tools import generate_fix_code, create_pr_template, generate_security_documentation, generate_fix_script
from ..tools.analysis_tools import calculate_priority_score
from ..tools.github_tools import create_github_pr, create_github_issue


class RemediationAgent:
    """수정 방안 생성 전문 에이전트"""

    def __init__(self, verbose: bool = True):
        # 수정 방안 생성 - 제한적 창의성 허용하되 보안성 유지
        self.llm = create_security_llm(
            task_type="fix_code_generation",
            security_level="MEDIUM"  # 창의성과 정확성의 균형
        )
        self.verbose = verbose

        # 수정 도구들
        self.remediation_tools = [
            generate_fix_code,
            create_pr_template,
            generate_security_documentation,
            generate_fix_script,
            calculate_priority_score,
            create_github_pr,
            create_github_issue
        ]

        # 에이전트 초기화
        self.agent_executor = self._create_agent()

        # 수정 방안 결과 저장
        self.remediation_results = {}
        self.performance_metrics = {
            "start_time": None,
            "end_time": None,
            "fixes_generated": 0,
            "tools_used": []
        }

    def _create_agent(self) -> AgentExecutor:
        """수정 방안 생성 에이전트 생성"""

        system_prompt = """You are a senior security engineer specialized in vulnerability remediation and secure coding practices.

Your responsibilities:
1. Generate specific, actionable fix code for security vulnerabilities
2. Create comprehensive Pull Request templates
3. Develop security documentation and guidelines
4. Provide automated fix scripts where possible
5. Ensure all fixes follow security best practices
6. Create GitHub Pull Requests and Issues when requested

Remediation Workflow:
1. Analyze each vulnerability type and context
2. Generate specific fix code with before/after examples
3. Include proper input validation and sanitization
4. Add security test cases to prevent regression
5. Create detailed PR templates with checklists
6. Generate supporting documentation
7. Provide implementation guidance and timelines
8. If user provides a GitHub repository URL, offer to create an actual PR

You have access to tools for:
- generating fix code
- creating PR templates
- generating documentation
- creating fix scripts
- calculating priority scores
- creating actual GitHub Pull Requests (requires GitHub CLI)
- creating GitHub Issues for vulnerability tracking

Code Quality Standards:
- Follow secure coding principles (OWASP guidelines)
- Include proper error handling
- Add input validation and sanitization
- Use parameterized queries for database operations
- Implement proper authentication and authorization
- Apply principle of least privilege
- Include security headers and configurations

For each fix:
- Provide working code examples
- Explain the security improvement
- Include test cases
- Estimate implementation effort
- Suggest deployment considerations

Be practical, secure, and focus on implementable solutions."""

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad")
        ])

        # LangChain 0.3.x의 새로운 Tool Calling Agent 생성
        agent = create_tool_calling_agent(
            llm=self.llm,
            tools=self.remediation_tools,
            prompt=prompt
        )

        return AgentExecutor(
            agent=agent,
            tools=self.remediation_tools,
            verbose=self.verbose,
            handle_parsing_errors=True,
            max_iterations=8,
            return_intermediate_steps=True
        )

    async def generate_remediation_plan(
        self,
        security_analysis: Dict[str, Any],
        project_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """보안 분석 결과를 바탕으로 수정 방안 생성"""

        self.performance_metrics["start_time"] = time.time()

        try:
            # 취약점 추출
            vulnerabilities = security_analysis.get("vulnerabilities", [])
            if not vulnerabilities:
                return {
                    "error": "No vulnerabilities found in security analysis",
                    "analysis_timestamp": time.time()
                }

            # 수정 방안 생성 요청 구성
            remediation_prompt = f"""
Generate comprehensive remediation solutions for the security vulnerabilities found:

Security Analysis Summary:
- Total vulnerabilities: {len(vulnerabilities)}
- Project path: {security_analysis.get('project_path', 'unknown')}

Vulnerabilities to fix:
{self._format_vulnerabilities_for_prompt(vulnerabilities)}

Project Information:
{project_info or {}}

Remediation Requirements:
1. Generate specific fix code for each vulnerability type
2. Create a comprehensive PR template for all fixes
3. Calculate priority scores for implementation order
4. Generate security documentation and guidelines
5. Create an automated fix script where possible

For each vulnerability:
- Provide secure code replacement
- Include proper testing approach
- Estimate fix complexity and time
- Suggest implementation order

Focus on practical, secure, and maintainable solutions.
Ensure all fixes follow security best practices and include proper validation.
"""

            if self.verbose:
                print("\n🔧 Generating comprehensive remediation plan...")
                print("   [1/4] Generating fix code for vulnerabilities...")
                print("   [2/4] Creating GitHub PR template...")
                print("   [3/4] Generating security documentation...")
                print("   [4/4] Creating automated fix script...")

            result = await self._run_agent_async(remediation_prompt)

            # 결과 처리
            self.performance_metrics["end_time"] = time.time()
            self.performance_metrics["duration"] = (
                self.performance_metrics["end_time"] - self.performance_metrics["start_time"]
            )

            # 수정 방안 결과 구조화
            remediation_results = self._structure_remediation_results(
                result, vulnerabilities, security_analysis
            )

            self.remediation_results = remediation_results
            return remediation_results

        except Exception as e:
            self.performance_metrics["end_time"] = time.time()
            return {
                "error": f"Remediation plan generation failed: {str(e)}",
                "vulnerabilities_count": len(vulnerabilities) if vulnerabilities else 0,
                "analysis_timestamp": time.time()
            }

    def _format_vulnerabilities_for_prompt(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """취약점 목록을 프롬프트용으로 포매팅"""
        formatted = []
        for i, vuln in enumerate(vulnerabilities[:10]):  # 최대 10개만 표시
            vuln_info = {
                "id": i + 1,
                "type": vuln.get("type", vuln.get("VulnerabilityID", "Unknown")),
                "severity": vuln.get("severity", vuln.get("Severity", "Unknown")),
                "file": vuln.get("file", "Unknown"),
                "description": vuln.get("description", vuln.get("Description", "No description"))
            }
            formatted.append(f"  {vuln_info['id']}. {vuln_info['type']} ({vuln_info['severity']}) in {vuln_info['file']}")

        if len(vulnerabilities) > 10:
            formatted.append(f"  ... and {len(vulnerabilities) - 10} more vulnerabilities")

        return "\n".join(formatted)

    async def _run_agent_async(self, prompt: str) -> Dict[str, Any]:
        """비동기로 에이전트 실행"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.agent_executor.invoke({"input": prompt})
        )

    def _structure_remediation_results(
        self,
        raw_result: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        security_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """수정 방안 결과를 구조화된 형태로 변환"""

        # 중간 단계에서 도구 호출 결과 추출
        intermediate_steps = raw_result.get("intermediate_steps", [])
        tool_results = {}

        for step in intermediate_steps:
            if len(step) >= 2:
                action, observation = step[0], step[1]
                tool_name = getattr(action, 'tool', 'unknown')

                # JSON 파싱 시도
                try:
                    if isinstance(observation, str) and observation.startswith('{'):
                        import json
                        observation = json.loads(observation)
                except:
                    pass

                tool_results[tool_name] = observation
                self.performance_metrics["tools_used"].append(tool_name)

        # 생성된 수정사항 카운트
        fixes_generated = 0
        if 'generate_fix_code' in tool_results:
            fixes_generated += 1
        self.performance_metrics["fixes_generated"] = fixes_generated

        # 우선순위 정보 수집
        priority_scores = []
        if 'calculate_priority_score' in tool_results:
            priority_data = tool_results['calculate_priority_score']
            if isinstance(priority_data, list):
                priority_scores = priority_data
            else:
                priority_scores = [priority_data]

        # 수정 방안 요약 생성
        fix_summary = self._generate_fix_summary(vulnerabilities, tool_results)

        return {
            "remediation_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "fixes_generated": fixes_generated,
                "pr_template_created": 'create_pr_template' in tool_results,
                "documentation_created": 'generate_security_documentation' in tool_results,
                "fix_script_created": 'generate_fix_script' in tool_results,
                "remediation_duration": self.performance_metrics.get("duration", 0),
                "tools_used": list(set(self.performance_metrics["tools_used"])),
                "analysis_timestamp": time.time()
            },
            "detailed_remediation": {
                "fix_codes": tool_results.get('generate_fix_code', {}),
                "pr_template": tool_results.get('create_pr_template', ""),
                "security_documentation": tool_results.get('generate_security_documentation', {}),
                "fix_script": tool_results.get('generate_fix_script', ""),
                "priority_scores": priority_scores
            },
            "implementation_plan": self._create_implementation_plan(vulnerabilities, priority_scores),
            "fix_summary": fix_summary,
            "agent_output": raw_result.get("output", ""),
            "performance_metrics": self.performance_metrics,
            "estimated_effort": self._estimate_total_effort(vulnerabilities),
            "success_criteria": self._define_success_criteria(vulnerabilities)
        }

    def _generate_fix_summary(self, vulnerabilities: List[Dict], tool_results: Dict) -> Dict[str, Any]:
        """수정 방안 요약 생성"""

        # 취약점 타입별 분류
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', vuln.get('VulnerabilityID', 'Unknown'))
            severity = vuln.get('severity', vuln.get('Severity', 'Unknown'))

            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = {
                    "count": 0,
                    "max_severity": "LOW",
                    "files": set()
                }

            vuln_types[vuln_type]["count"] += 1
            vuln_types[vuln_type]["files"].add(vuln.get('file', 'unknown'))

            # 최대 심각도 업데이트
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            current_severity = vuln_types[vuln_type]["max_severity"]
            if severity_order.get(severity, 0) > severity_order.get(current_severity, 0):
                vuln_types[vuln_type]["max_severity"] = severity

        return {
            "vulnerability_types": vuln_types,
            "total_files_affected": len(set(v.get('file', 'unknown') for v in vulnerabilities)),
            "severity_distribution": self._calculate_severity_distribution(vulnerabilities),
            "fix_categories": {
                "code_changes": len([v for v in vulnerabilities if v.get('file', '').endswith('.py')]),
                "config_changes": len([v for v in vulnerabilities if 'config' in v.get('file', '').lower()]),
                "dependency_updates": len([v for v in vulnerabilities if 'requirements.txt' in v.get('file', '')])
            }
        }

    def _calculate_severity_distribution(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """심각도별 분포 계산"""
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', vuln.get('Severity', 'UNKNOWN')).upper()
            if severity in distribution:
                distribution[severity] += 1
        return distribution

    def _create_implementation_plan(self, vulnerabilities: List[Dict], priority_scores: List[Dict]) -> Dict[str, Any]:
        """구현 계획 생성"""

        # 우선순위별 그룹화
        p0_items = []
        p1_items = []
        p2_items = []
        p3_items = []

        for vuln in vulnerabilities:
            severity = vuln.get('severity', vuln.get('Severity', 'MEDIUM')).upper()
            vuln_type = vuln.get('type', vuln.get('VulnerabilityID', 'Unknown'))

            item = {
                "type": vuln_type,
                "file": vuln.get('file', 'unknown'),
                "severity": severity,
                "estimated_time": self._estimate_fix_time(vuln_type, severity)
            }

            if severity == "CRITICAL":
                p0_items.append(item)
            elif severity == "HIGH":
                p1_items.append(item)
            elif severity == "MEDIUM":
                p2_items.append(item)
            else:
                p3_items.append(item)

        return {
            "phase_1_immediate": {
                "items": p0_items,
                "estimated_time": sum(item["estimated_time"] for item in p0_items),
                "description": "Critical security issues requiring immediate attention"
            },
            "phase_2_urgent": {
                "items": p1_items,
                "estimated_time": sum(item["estimated_time"] for item in p1_items),
                "description": "High severity issues to be fixed within 1 week"
            },
            "phase_3_important": {
                "items": p2_items,
                "estimated_time": sum(item["estimated_time"] for item in p2_items),
                "description": "Medium severity issues to be addressed in next sprint"
            },
            "phase_4_improvement": {
                "items": p3_items,
                "estimated_time": sum(item["estimated_time"] for item in p3_items),
                "description": "Low severity improvements for next major release"
            }
        }

    def _estimate_fix_time(self, vuln_type: str, severity: str) -> float:
        """취약점 타입과 심각도에 따른 수정 시간 추정 (시간 단위)"""
        base_times = {
            "SQL_INJECTION": 2.0,
            "XSS": 1.5,
            "COMMAND_INJECTION": 2.5,
            "HARDCODED_SECRET": 0.5,
            "UNSAFE_DESERIALIZATION": 3.0,
            "DEBUG_MODE": 0.25,
            "INSECURE_NETWORK": 1.0
        }

        severity_multipliers = {
            "CRITICAL": 1.5,
            "HIGH": 1.2,
            "MEDIUM": 1.0,
            "LOW": 0.8
        }

        base_time = base_times.get(vuln_type, 1.0)
        multiplier = severity_multipliers.get(severity, 1.0)

        return base_time * multiplier

    def _estimate_total_effort(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """전체 수정 작업 소요 시간 추정"""
        total_hours = 0
        by_phase = {
            "immediate": 0,
            "urgent": 0,
            "important": 0,
            "improvement": 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get('severity', vuln.get('Severity', 'MEDIUM')).upper()
            vuln_type = vuln.get('type', vuln.get('VulnerabilityID', 'Unknown'))
            fix_time = self._estimate_fix_time(vuln_type, severity)

            total_hours += fix_time

            if severity == "CRITICAL":
                by_phase["immediate"] += fix_time
            elif severity == "HIGH":
                by_phase["urgent"] += fix_time
            elif severity == "MEDIUM":
                by_phase["important"] += fix_time
            else:
                by_phase["improvement"] += fix_time

        return {
            "total_hours": round(total_hours, 1),
            "total_days": round(total_hours / 8, 1),
            "by_phase": by_phase,
            "team_size_recommendation": 2 if total_hours > 16 else 1,
            "estimated_completion": f"{round(total_hours / 8, 1)} days with 1 developer"
        }

    def _define_success_criteria(self, vulnerabilities: List[Dict]) -> List[str]:
        """성공 기준 정의"""
        criteria = [
            "모든 Critical 및 High 취약점 수정 완료",
            "보안 스캔 도구에서 신규 취약점 0개 검출",
            "모든 수정사항에 대한 테스트 케이스 작성 및 통과",
            "코드 리뷰 및 보안 검토 완료"
        ]

        # 특정 취약점 타입별 기준 추가
        vuln_types = set(v.get('type', v.get('VulnerabilityID', '')) for v in vulnerabilities)

        if any('SQL_INJECTION' in vtype for vtype in vuln_types):
            criteria.append("모든 데이터베이스 쿼리에 Parameterized Query 적용")

        if any('XSS' in vtype for vtype in vuln_types):
            criteria.append("모든 사용자 입력에 적절한 이스케이프 처리 적용")

        if any('SECRET' in vtype for vtype in vuln_types):
            criteria.append("모든 시크릿이 환경 변수로 이전되고 .env 파일이 .gitignore에 추가됨")

        criteria.extend([
            "배포 후 기능 테스트 통과",
            "성능 영향도 확인 및 승인",
            "보안 문서 업데이트 완료"
        ])

        return criteria

    def get_remediation_summary(self) -> str:
        """수정 방안 요약 텍스트 생성"""
        if not self.remediation_results:
            return "No remediation results available."

        summary = self.remediation_results.get("remediation_summary", {})
        effort = self.remediation_results.get("estimated_effort", {})

        return f"""
🔧 수정 방안 생성 완료

📋 생성된 수정사항:
- 취약점 수정 코드: {summary.get('fixes_generated', 0)}개
- PR 템플릿: {'✅' if summary.get('pr_template_created') else '❌'}
- 보안 문서: {'✅' if summary.get('documentation_created') else '❌'}
- 자동 수정 스크립트: {'✅' if summary.get('fix_script_created') else '❌'}

⏱️ 예상 수정 시간:
- 총 소요시간: {effort.get('total_hours', 0)}시간 ({effort.get('total_days', 0)}일)
- 권장 팀 크기: {effort.get('team_size_recommendation', 1)}명

🎯 다음 단계: Critical 취약점부터 우선 수정 시작
"""