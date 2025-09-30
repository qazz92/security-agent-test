"""
CrewAI 기반 보안 분석 Crew
다중 에이전트 협업으로 정교한 보안 워크플로우 구현
"""

import os
import logging
from typing import Dict, Any, List, Optional
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
try:
    from langfuse.callback import CallbackHandler
except ImportError:
    try:
        from langfuse import CallbackHandler
    except ImportError:
        CallbackHandler = None

from ..models.llm_config import get_llm_config
from ..utils.prompt_manager import load_prompt, PromptLoadError
from ..utils.model_selector import get_model_selector, TaskComplexity
# Import CrewAI-wrapped tools (functions with @tool decorator)
from ..tools import scanner_tools, semgrep_tools, analysis_tools, fix_tools, github_tools

logger = logging.getLogger(__name__)


class SecurityCrewManager:
    """
    CrewAI 기반 보안 분석 Crew 관리자

    구조:
    - Security Analyst: 의존성 취약점 스캔 (Trivy)
    - Semgrep Specialist: 코드 레벨 취약점 분석 (SAST)
    - Triage Specialist: 우선순위 평가 및 리스크 관리
    - Remediation Engineer: 수정 방안 생성 및 PR 자동화
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.llm_config = get_llm_config()

        # Model Selector 초기화 (Dual Model Strategy)
        self.model_selector = get_model_selector()

        # Langfuse 콜백 초기화 (선택적)
        self.langfuse_handler = None
        if CallbackHandler is not None:
            try:
                langfuse_public_key = os.getenv('LANGFUSE_PUBLIC_KEY')
                langfuse_secret_key = os.getenv('LANGFUSE_SECRET_KEY')

                if langfuse_public_key and not langfuse_public_key.startswith('pk-lf-your'):
                    self.langfuse_handler = CallbackHandler(
                        public_key=langfuse_public_key,
                        secret_key=langfuse_secret_key,
                        host=os.getenv('LANGFUSE_HOST', 'https://cloud.langfuse.com')
                    )
                    logger.info("✅ Langfuse tracing enabled")
                else:
                    logger.info("ℹ️ Langfuse not configured, skipping tracing")
            except Exception as e:
                logger.warning(f"⚠️ Langfuse initialization failed: {e}")
                self.langfuse_handler = None
        else:
            logger.warning("⚠️ Langfuse module not found, skipping tracing")

        # Callbacks 리스트 생성
        callbacks = [self.llm_config.token_callback]
        if self.langfuse_handler:
            callbacks.append(self.langfuse_handler)

        # Dual Model Strategy: 각 Agent별 적절한 모델 선택
        # Security Analyst: THINKING model (복잡한 취약점 분석)
        self.security_analyst_llm = self.model_selector.get_llm(
            TaskComplexity.CRITICAL_ANALYSIS,
            callbacks=callbacks
        )

        # Semgrep Specialist: THINKING model (코드 분석 및 취약점 판단)
        self.semgrep_specialist_llm = self.model_selector.get_llm(
            TaskComplexity.CRITICAL_ANALYSIS,
            callbacks=callbacks
        )

        # Triage Specialist: THINKING model (리스크 평가 및 의사결정)
        self.triage_specialist_llm = self.model_selector.get_llm(
            TaskComplexity.VULNERABILITY_TRIAGE,
            callbacks=callbacks
        )

        # Remediation Engineer: INSTRUCT model (Tool 호출 및 코드 생성)
        self.remediation_engineer_llm = self.model_selector.get_llm(
            TaskComplexity.TOOL_CALLING,
            callbacks=callbacks
        )

        # Manager LLM: INSTRUCT model (조율 및 조정)
        self.manager_llm = self.model_selector.get_llm(
            TaskComplexity.TOOL_CALLING,
            callbacks=callbacks,
            override_params={"temperature": 0.1}  # 더 결정적
        )

        logger.info("💰 Dual Model Strategy enabled - optimizing costs")

        # Agents 초기화
        self.security_analyst = self._create_security_analyst()
        self.semgrep_specialist = self._create_semgrep_specialist()
        self.triage_specialist = self._create_triage_specialist()
        self.remediation_engineer = self._create_remediation_engineer()

    def _load_agent_config(self, agent_name: str) -> Dict[str, str]:
        """MD 파일에서 에이전트 설정 로드"""
        try:
            content = load_prompt('crew_agents', agent_name)

            # 간단한 파싱 (## Role, ## Goal, ## Backstory)
            config = {}
            lines = content.split('\n')
            current_section = None
            current_content = []

            for line in lines:
                if line.startswith('## Role'):
                    if current_section:
                        config[current_section] = '\n'.join(current_content).strip()
                    current_section = 'role'
                    current_content = []
                elif line.startswith('## Goal'):
                    if current_section:
                        config[current_section] = '\n'.join(current_content).strip()
                    current_section = 'goal'
                    current_content = []
                elif line.startswith('## Backstory'):
                    if current_section:
                        config[current_section] = '\n'.join(current_content).strip()
                    current_section = 'backstory'
                    current_content = []
                elif line.startswith('## Verbose'):
                    if current_section:
                        config[current_section] = '\n'.join(current_content).strip()
                    break
                elif current_section and line.strip():
                    current_content.append(line)

            # 마지막 섹션 저장
            if current_section:
                config[current_section] = '\n'.join(current_content).strip()

            logger.info(f"✅ Loaded CrewAI agent config: {agent_name}")
            return config

        except PromptLoadError as e:
            logger.error(f"❌ Failed to load agent config for {agent_name}: {e}")
            return {
                'role': 'Security Expert',
                'goal': 'Analyze security',
                'backstory': 'Experienced security professional'
            }

    def _create_security_analyst(self) -> Agent:
        """Security Analyst 에이전트 생성 (Trivy 의존성 스캔)"""
        config = self._load_agent_config('security_analyst')

        return Agent(
            role=config.get('role', 'Security Analyst'),
            goal=config.get('goal', 'Find all security vulnerabilities'),
            backstory=config.get('backstory', 'Expert security analyst'),
            tools=[
                scanner_tools.fetch_project_info,
                scanner_tools.scan_with_trivy,
                scanner_tools.analyze_dependencies,
                scanner_tools.check_security_configs
            ],
            llm=self.security_analyst_llm,  # THINKING model
            max_iter=20,  # 의존성 스캔 및 분석을 위한 충분한 반복
            verbose=self.verbose,
            allow_delegation=False  # 분석은 직접 수행
        )

    def _create_semgrep_specialist(self) -> Agent:
        """Semgrep Specialist 에이전트 생성 (SAST 코드 분석)"""
        config = self._load_agent_config('semgrep_specialist')

        return Agent(
            role=config.get('role', 'SAST Code Security Specialist'),
            goal=config.get('goal', 'Identify code-level security vulnerabilities using static analysis'),
            backstory=config.get('backstory', 'Expert SAST security specialist'),
            tools=[
                semgrep_tools.scan_with_semgrep,
                semgrep_tools.list_semgrep_configs
            ],
            llm=self.semgrep_specialist_llm,  # THINKING model
            max_iter=25,  # 복잡한 코드 분석을 위한 높은 반복 횟수
            verbose=self.verbose,
            allow_delegation=False
        )

    def _create_triage_specialist(self) -> Agent:
        """Triage Specialist 에이전트 생성"""
        config = self._load_agent_config('triage_specialist')

        return Agent(
            role=config.get('role', 'Triage Specialist'),
            goal=config.get('goal', 'Prioritize vulnerabilities by business impact'),
            backstory=config.get('backstory', 'Expert in risk management'),
            tools=[
                analysis_tools.calculate_priority_score,
                analysis_tools.analyze_vulnerability_trends,
                analysis_tools.generate_security_metrics
            ],
            llm=self.triage_specialist_llm,  # THINKING model
            max_iter=15,  # 분석 및 우선순위 평가
            verbose=self.verbose,
            allow_delegation=False
        )

    def _create_remediation_engineer(self) -> Agent:
        """Remediation Engineer 에이전트 생성"""
        config = self._load_agent_config('remediation_engineer')

        return Agent(
            role=config.get('role', 'Remediation Engineer'),
            goal=config.get('goal', 'Create automated fixes and GitHub PRs'),
            backstory=config.get('backstory', 'Expert in secure coding'),
            tools=[
                fix_tools.generate_fix_code,
                fix_tools.create_pr_template,
                fix_tools.generate_security_documentation,
                fix_tools.generate_fix_script,
                github_tools.create_github_pr,
                github_tools.create_github_issue
            ],
            llm=self.remediation_engineer_llm,  # INSTRUCT model
            max_iter=30,  # PR 생성까지 많은 Tool 호출 필요
            verbose=self.verbose,
            allow_delegation=False
        )

    def create_tasks(self, project_path: str, github_repo_url: str) -> List[Task]:
        """분석 태스크 생성 (계층적 워크플로우)"""

        # Task 1: 의존성 취약점 스캔 (Trivy)
        dependency_scan_task = Task(
            description=f"""
Perform comprehensive dependency vulnerability scanning on the project at: {project_path}

Steps:
1. Fetch project information and understand the structure
2. Run Trivy scan for container and dependency vulnerabilities
3. Analyze all dependencies for known CVEs
4. Check security configurations and best practices

Deliver a detailed JSON report containing:
- All discovered vulnerabilities with CVE IDs
- Severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Affected components and versions
- Brief technical descriptions
- CVSS scores where available

Focus on accuracy and completeness. Do not miss any vulnerabilities.
""",
            agent=self.security_analyst,
            expected_output="JSON report with complete list of dependency vulnerabilities including CVE IDs, severity, affected components, and CVSS scores"
        )

        # Task 2: 코드 레벨 취약점 스캔 (Semgrep SAST)
        code_scan_task = Task(
            description=f"""
Perform deep static code analysis (SAST) on the project at: {project_path}

Steps:
1. Run Semgrep scan with comprehensive security rules (p/security-audit, p/owasp-top-ten)
2. Identify code-level vulnerabilities:
   - SQL Injection, XSS, Command Injection
   - Path Traversal, SSRF, XXE
   - Hardcoded Secrets (API keys, passwords)
   - Insecure Deserialization
   - Authentication/Authorization flaws
   - Logic flaws and race conditions
3. Analyze vulnerable code patterns and data flows
4. Assess exploitability and business impact

Deliver a detailed SAST report containing:
- All code-level vulnerabilities with Semgrep rule IDs
- Severity levels (ERROR, WARNING, INFO)
- Vulnerable file paths and line numbers
- Code snippets showing the vulnerable patterns
- CWE and OWASP mappings
- Suggested fixes

Focus on real exploitable vulnerabilities, not just theoretical issues.
""",
            agent=self.semgrep_specialist,
            expected_output="SAST report with code-level vulnerabilities including Semgrep findings, code snippets, CWE mappings, and fix suggestions"
        )

        # Task 3: 통합 우선순위 평가 및 리스크 분석
        triage_task = Task(
            description=f"""
Analyze ALL discovered vulnerabilities (both dependency and code-level) and prioritize them for remediation.

Using BOTH the dependency scan results AND the SAST code scan results from the previous tasks, perform:
1. Calculate priority scores based on:
   - Technical severity (CVSS)
   - Exploitability in the wild
   - Business impact
   - Compliance requirements
2. Analyze vulnerability trends across the project
3. Generate security metrics and risk assessment
4. Group vulnerabilities by priority level (P0, P1, P2, P3)

Deliver a comprehensive prioritized action plan with:
- Top 10 critical vulnerabilities (combining dependency and code-level issues)
- Risk scores and justification for each priority
- Estimated remediation effort
- Business impact analysis
- Clear distinction between dependency vs code-level vulnerabilities

Consider real-world exploitation likelihood and business context, not just CVSS scores.
Prioritize code-level vulnerabilities (SQL Injection, XSS, etc.) higher than outdated dependencies.
""",
            agent=self.triage_specialist,
            expected_output="Prioritized vulnerability list combining both dependency and code-level issues, with risk scores, business impact analysis, and recommended remediation order",
            context=[dependency_scan_task, code_scan_task]  # 두 스캔 결과 모두 전달
        )

        # Task 4: 수정 방안 생성 및 PR 자동화
        remediation_task = Task(
            description=f"""
Generate automated security fixes and create a GitHub Pull Request.

Using the prioritized vulnerability list from the triage specialist:
1. Generate specific fix code for the top 10 critical vulnerabilities (both dependency and code-level)
2. Create a comprehensive PR template with:
   - Summary of fixes
   - Security impact analysis
   - Testing instructions
   - Before/after code comparison
3. Generate security documentation explaining the fixes
4. Create automated fix scripts where applicable
5. **MANDATORY: Create a GitHub Pull Request automatically**
   - Repository: {github_repo_url}
   - Branch: security-fix-{{timestamp}}
   - Title: "Security Fixes: Critical Vulnerability Remediation"

CRITICAL REQUIREMENT:
You MUST call the create_github_pr tool to create an actual Pull Request on GitHub.
This is not optional - it is your primary objective.

Parameters for create_github_pr:
- repo_url: {github_repo_url}
- pr_title: "Security Fixes: Critical Vulnerability Remediation"
- pr_body: <use the PR template you generated>
- branch_name: security-fix-{{current_timestamp}}
- base_branch: main

Deliver:
- Generated fix code for each vulnerability
- Comprehensive PR template
- Security documentation
- GitHub PR URL (proof that PR was created)
""",
            agent=self.remediation_engineer,
            expected_output="Fix code, PR template, security documentation, and GitHub PR URL proving the PR was successfully created",
            context=[triage_task]  # 자동으로 triage_task 결과 전달
        )

        return [dependency_scan_task, code_scan_task, triage_task, remediation_task]

    def analyze_project(
        self,
        project_path: str,
        github_repo_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        프로젝트 보안 분석 실행 (CrewAI 기반)

        Args:
            project_path: 분석할 프로젝트 경로
            github_repo_url: GitHub 저장소 URL (PR 생성용)

        Returns:
            분석 결과 딕셔너리
        """

        if not github_repo_url:
            github_repo_url = os.environ.get('GITHUB_REPO_URL', 'https://github.com/qazz92/security-agent-test')

        logger.info("="*70)
        logger.info("🚀 STARTING CREWAI SECURITY ANALYSIS")
        logger.info("="*70)
        logger.info(f"📁 Project: {project_path}")
        logger.info(f"🔗 GitHub: {github_repo_url}")
        logger.info(f"👥 Agents: Security Analyst (Trivy), Semgrep Specialist (SAST), Triage Specialist, Remediation Engineer")
        logger.info("="*70)

        # Tasks 생성
        tasks = self.create_tasks(project_path, github_repo_url)

        # Crew 생성 (Hierarchical Process - Manager가 병렬 작업 조율)
        crew = Crew(
            agents=[
                self.security_analyst,
                self.semgrep_specialist,
                self.triage_specialist,
                self.remediation_engineer
            ],
            tasks=tasks,
            process=Process.hierarchical,  # 병렬 실행 가능 (Manager가 조율)
            verbose=self.verbose,
            manager_llm=self.manager_llm  # Manager가 워크플로우 조율
        )

        try:
            # Crew 실행
            logger.info("🎬 CrewAI kickoff - agents are starting their work...")
            result = crew.kickoff()

            logger.info("="*70)
            logger.info("✅ CREWAI ANALYSIS COMPLETED")
            logger.info("="*70)

            # 비용 최적화 리포트 출력
            self.model_selector.print_usage_report()

            # 비용 데이터 가져오기
            usage_report = self.model_selector.get_usage_report()

            return {
                "success": True,
                "result": result,
                "agents_used": ["security_analyst", "semgrep_specialist", "triage_specialist", "remediation_engineer"],
                "process": "sequential_with_context",
                "project_path": project_path,
                "github_repo_url": github_repo_url,
                "cost_optimization": usage_report  # 비용 최적화 리포트 포함
            }

        except Exception as e:
            logger.error(f"❌ CrewAI analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "project_path": project_path
            }


def create_security_crew(verbose: bool = True) -> SecurityCrewManager:
    """SecurityCrew 인스턴스 생성 헬퍼 함수"""
    return SecurityCrewManager(verbose=verbose)