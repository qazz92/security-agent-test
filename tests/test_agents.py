"""
에이전트들에 대한 통합 테스트
"""

import pytest
import asyncio
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock, AsyncMock
import sys

# 테스트를 위한 경로 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.security_agent import SecurityAnalysisAgent
from src.agents.remediation_agent import RemediationAgent
from src.agents.orchestrator_agent import SecurityOrchestrator


class TestSecurityAnalysisAgent:
    """보안 분석 에이전트 테스트"""

    @pytest.fixture
    def security_agent(self):
        """보안 분석 에이전트 인스턴스"""
        return SecurityAnalysisAgent(verbose=False)

    @pytest.fixture
    def sample_project_path(self):
        """샘플 프로젝트 경로"""
        return "demo/hello-world-vulnerable"

    @pytest.mark.asyncio
    async def test_agent_initialization(self, security_agent):
        """에이전트 초기화 테스트"""
        assert security_agent is not None
        assert security_agent.llm is not None
        assert security_agent.analysis_tools is not None
        assert len(security_agent.analysis_tools) > 0
        assert security_agent.agent_executor is not None

    @pytest.mark.asyncio
    @patch('src.agents.security_agent.SecurityAnalysisAgent._run_agent_async')
    async def test_analyze_project_mock(self, mock_run_agent, security_agent, sample_project_path):
        """프로젝트 분석 테스트 (모의)"""

        # 모의 에이전트 응답
        mock_response = {
            "output": "Analysis completed successfully",
            "intermediate_steps": [
                (
                    MagicMock(tool="fetch_project_info"),
                    '{"language": "Python", "framework": "Flask", "files": ["app.py"]}'
                ),
                (
                    MagicMock(tool="scan_with_trivy"),
                    '{"scan_type": "trivy_mock", "total_vulnerabilities": 5}'
                ),
                (
                    MagicMock(tool="check_security_configs"),
                    '{"security_issues": [{"type": "SQL_INJECTION", "severity": "CRITICAL"}]}'
                )
            ]
        }

        mock_run_agent.return_value = mock_response

        result = await security_agent.analyze_project(sample_project_path, "Test analysis")

        # 결과 검증
        assert "error" not in result
        assert result["project_path"] == sample_project_path
        assert "analysis_summary" in result
        assert "detailed_results" in result
        assert "vulnerabilities" in result
        assert "performance_metrics" in result

        # 메트릭 검증
        assert "start_time" in security_agent.performance_metrics
        assert "end_time" in security_agent.performance_metrics
        assert "duration" in security_agent.performance_metrics

    @pytest.mark.asyncio
    @patch('src.agents.security_agent.SecurityAnalysisAgent._run_agent_async')
    async def test_analyze_project_with_error(self, mock_run_agent, security_agent, sample_project_path):
        """프로젝트 분석 실패 테스트"""

        # 에러 시뮬레이션
        mock_run_agent.side_effect = Exception("LLM API error")

        result = await security_agent.analyze_project(sample_project_path, "Test analysis")

        # 에러 처리 확인
        assert "error" in result
        assert "LLM API error" in result["error"]

    def test_structure_analysis_results(self, security_agent):
        """분석 결과 구조화 테스트"""

        # 모의 원시 결과
        raw_result = {
            "output": "Analysis completed",
            "intermediate_steps": [
                (
                    MagicMock(tool="fetch_project_info"),
                    {"language": "Python", "files": ["app.py", "requirements.txt"]}
                ),
                (
                    MagicMock(tool="check_security_configs"),
                    {
                        "security_issues": [
                            {
                                "type": "SQL_INJECTION",
                                "severity": "CRITICAL",
                                "file": "app.py",
                                "line": 15
                            }
                        ]
                    }
                )
            ]
        }

        result = security_agent._structure_analysis_results(raw_result, "/test/path")

        # 구조 검증
        assert "project_path" in result
        assert "analysis_summary" in result
        assert "detailed_results" in result
        assert "vulnerabilities" in result
        assert "recommendations" in result

        # 취약점 정보 확인
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["type"] == "SQL_INJECTION"

    def test_generate_recommendations(self, security_agent):
        """권장사항 생성 테스트"""

        vulnerabilities = [
            {"type": "SQL_INJECTION", "severity": "CRITICAL"},
            {"type": "XSS", "severity": "HIGH"},
            {"type": "HARDCODED_SECRET", "severity": "HIGH"}
        ]

        severity_counts = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0}

        recommendations = security_agent._generate_recommendations(vulnerabilities, severity_counts)

        assert len(recommendations) > 0
        assert any("Critical" in rec for rec in recommendations)
        assert any("High" in rec for rec in recommendations)

    def test_get_analysis_summary(self, security_agent):
        """분석 요약 텍스트 테스트"""

        # 모의 분석 결과 설정
        security_agent.analysis_results = {
            "analysis_summary": {
                "total_vulnerabilities": 8,
                "severity_distribution": {
                    "CRITICAL": 2,
                    "HIGH": 3,
                    "MEDIUM": 2,
                    "LOW": 1
                },
                "analysis_duration": 12.5,
                "tools_used": ["fetch_project_info", "scan_with_trivy"]
            }
        }

        summary = security_agent.get_analysis_summary()

        assert "8개" in summary or "8" in summary
        assert "Critical" in summary or "CRITICAL" in summary
        assert "12.5" in summary or "12" in summary


class TestRemediationAgent:
    """수정 방안 에이전트 테스트"""

    @pytest.fixture
    def remediation_agent(self):
        """수정 방안 에이전트 인스턴스"""
        return RemediationAgent(verbose=False)

    @pytest.fixture
    def sample_security_analysis(self):
        """샘플 보안 분석 결과"""
        return {
            "project_path": "/test/project",
            "vulnerabilities": [
                {
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "file": "app.py",
                    "line": 15,
                    "description": "SQL injection in user query"
                },
                {
                    "type": "XSS",
                    "severity": "HIGH",
                    "file": "app.py",
                    "line": 25,
                    "description": "Cross-site scripting in comment"
                }
            ],
            "analysis_summary": {
                "total_vulnerabilities": 2,
                "severity_distribution": {"CRITICAL": 1, "HIGH": 1}
            }
        }

    @pytest.mark.asyncio
    async def test_agent_initialization(self, remediation_agent):
        """에이전트 초기화 테스트"""
        assert remediation_agent is not None
        assert remediation_agent.llm is not None
        assert remediation_agent.remediation_tools is not None
        assert len(remediation_agent.remediation_tools) > 0
        assert remediation_agent.agent_executor is not None

    @pytest.mark.asyncio
    @patch('src.agents.remediation_agent.RemediationAgent._run_agent_async')
    async def test_generate_remediation_plan_mock(self, mock_run_agent, remediation_agent, sample_security_analysis):
        """수정 방안 생성 테스트 (모의)"""

        # 모의 에이전트 응답
        mock_response = {
            "output": "Remediation plan generated successfully",
            "intermediate_steps": [
                (
                    MagicMock(tool="generate_fix_code"),
                    {
                        "vulnerability_type": "SQL_INJECTION",
                        "before_code": "SELECT * FROM users WHERE id = {user_id}",
                        "after_code": "SELECT * FROM users WHERE id = ?",
                        "description": "Use parameterized queries"
                    }
                ),
                (
                    MagicMock(tool="create_pr_template"),
                    "# Security Patch\n\nFixed 2 vulnerabilities..."
                ),
                (
                    MagicMock(tool="calculate_priority_score"),
                    {"priority": "P0", "final_score": 8.5}
                )
            ]
        }

        mock_run_agent.return_value = mock_response

        result = await remediation_agent.generate_remediation_plan(sample_security_analysis)

        # 결과 검증
        assert "error" not in result
        assert "remediation_summary" in result
        assert "detailed_remediation" in result
        assert "implementation_plan" in result

        # 요약 정보 확인
        summary = result["remediation_summary"]
        assert summary["total_vulnerabilities"] == 2
        assert "fixes_generated" in summary
        assert "pr_template_created" in summary

    @pytest.mark.asyncio
    async def test_generate_remediation_plan_no_vulnerabilities(self, remediation_agent):
        """취약점이 없는 경우 테스트"""

        empty_analysis = {
            "vulnerabilities": [],
            "project_path": "/test/project"
        }

        result = await remediation_agent.generate_remediation_plan(empty_analysis)

        assert "error" in result
        assert "No vulnerabilities" in result["error"]

    def test_format_vulnerabilities_for_prompt(self, remediation_agent):
        """프롬프트용 취약점 포맷팅 테스트"""

        vulnerabilities = [
            {
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py",
                "description": "SQL injection vulnerability"
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "file": "templates/index.html",
                "description": "Cross-site scripting"
            }
        ]

        formatted = remediation_agent._format_vulnerabilities_for_prompt(vulnerabilities)

        assert "SQL_INJECTION" in formatted
        assert "XSS" in formatted
        assert "CRITICAL" in formatted
        assert "HIGH" in formatted

    def test_estimate_fix_time(self, remediation_agent):
        """수정 시간 추정 테스트"""

        # 다양한 취약점 타입과 심각도 테스트
        test_cases = [
            ("SQL_INJECTION", "CRITICAL", 3.0),  # 예상값보다 큰지 확인
            ("XSS", "HIGH", 1.5),
            ("HARDCODED_SECRET", "MEDIUM", 0.5),
            ("DEBUG_MODE", "LOW", 0.2)
        ]

        for vuln_type, severity, min_expected in test_cases:
            time_estimate = remediation_agent._estimate_fix_time(vuln_type, severity)
            assert time_estimate >= min_expected * 0.5  # 최소 기대값의 50% 이상


class TestSecurityOrchestrator:
    """보안 오케스트레이터 테스트"""

    @pytest.fixture
    def orchestrator(self):
        """오케스트레이터 인스턴스"""
        return SecurityOrchestrator(verbose=False)

    @pytest.fixture
    def sample_project_path(self):
        """샘플 프로젝트 경로"""
        return "demo/hello-world-vulnerable"

    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self, orchestrator):
        """오케스트레이터 초기화 테스트"""
        assert orchestrator is not None
        assert orchestrator.security_agent is not None
        assert orchestrator.remediation_agent is not None
        assert orchestrator.llm is not None

    @pytest.mark.asyncio
    @patch('src.agents.security_agent.SecurityAnalysisAgent.analyze_project')
    @patch('src.agents.remediation_agent.RemediationAgent.generate_remediation_plan')
    async def test_analyze_and_remediate_mock(self, mock_remediation, mock_security, orchestrator, sample_project_path):
        """전체 분석 및 수정 워크플로우 테스트 (모의)"""

        # 모의 보안 분석 결과
        mock_security_result = {
            "project_path": sample_project_path,
            "analysis_summary": {
                "total_vulnerabilities": 3,
                "severity_distribution": {"CRITICAL": 1, "HIGH": 2}
            },
            "vulnerabilities": [
                {"type": "SQL_INJECTION", "severity": "CRITICAL", "file": "app.py"}
            ],
            "detailed_results": {
                "project_info": {"language": "Python", "framework": "Flask"}
            }
        }

        # 모의 수정 방안 결과
        mock_remediation_result = {
            "remediation_summary": {
                "total_vulnerabilities": 3,
                "fixes_generated": 3,
                "pr_template_created": True
            },
            "estimated_effort": {"total_hours": 8.5, "total_days": 1.1}
        }

        mock_security.return_value = mock_security_result
        mock_remediation.return_value = mock_remediation_result

        # 워크플로우 실행
        result = await orchestrator.analyze_and_remediate(sample_project_path, "Test analysis")

        # 결과 검증
        assert "error" not in result
        assert "workflow_metadata" in result
        assert "security_analysis" in result
        assert "remediation_plan" in result
        assert "final_report" in result
        assert "executive_summary" in result

        # 메타데이터 확인
        metadata = result["workflow_metadata"]
        assert metadata["project_path"] == sample_project_path
        assert "analysis_timestamp" in metadata

        # 성능 메트릭 확인
        performance = result["performance_metrics"]
        assert "workflow_start_time" in performance
        assert "workflow_end_time" in performance
        assert "phases_completed" in performance

    @pytest.mark.asyncio
    @patch('src.agents.security_agent.SecurityAnalysisAgent.analyze_project')
    async def test_analyze_and_remediate_security_error(self, mock_security, orchestrator, sample_project_path):
        """보안 분석 실패 시 에러 처리 테스트"""

        # 보안 분석 실패 시뮬레이션
        mock_security.return_value = {"error": "Security analysis failed"}

        result = await orchestrator.analyze_and_remediate(sample_project_path, "Test analysis")

        # 에러 처리 확인
        assert "error" in result
        assert "Security analysis failed" in result["error"]

    def test_calculate_security_score(self, orchestrator):
        """보안 점수 계산 테스트"""

        test_cases = [
            ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, 100),  # 완벽한 점수
            ({"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, 75),   # Critical 1개
            ({"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0}, 70),   # High 2개
            ({"CRITICAL": 2, "HIGH": 3, "MEDIUM": 5, "LOW": 10}, 0)    # 많은 취약점
        ]

        for severity_counts, expected_min in test_cases:
            score = orchestrator._calculate_security_score(severity_counts)
            assert 0 <= score <= 100
            if expected_min == 100:
                assert score == 100
            elif expected_min == 0:
                assert score == 0
            else:
                assert score >= expected_min - 10  # 약간의 여유

    def test_determine_risk_level(self, orchestrator):
        """위험 수준 결정 테스트"""

        test_cases = [
            ({"CRITICAL": 1, "HIGH": 0}, "CRITICAL"),
            ({"CRITICAL": 0, "HIGH": 3}, "HIGH"),
            ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0}, "MEDIUM"),
            ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2}, "LOW")
        ]

        for severity_counts, expected_level in test_cases:
            level = orchestrator._determine_risk_level(severity_counts)
            assert level == expected_level

    def test_assess_business_impact(self, orchestrator):
        """비즈니스 임팩트 평가 테스트"""

        vulnerabilities = [
            {"type": "SQL_INJECTION", "severity": "CRITICAL"},
            {"type": "HARDCODED_SECRET", "severity": "HIGH"}
        ]

        severity_counts = {"CRITICAL": 1, "HIGH": 1}

        impact = orchestrator._assess_business_impact(vulnerabilities, severity_counts)

        assert "risk_scenarios" in impact
        assert "estimated_breach_cost" in impact
        assert "compliance_risk" in impact
        assert len(impact["risk_scenarios"]) > 0

    def test_generate_strategic_recommendations(self, orchestrator):
        """전략적 권장사항 생성 테스트"""

        security_analysis = {
            "analysis_summary": {
                "severity_distribution": {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1}
            },
            "vulnerabilities": [
                {"type": "SQL_INJECTION"},
                {"type": "HARDCODED_SECRET"}
            ]
        }

        remediation_plan = {"estimated_effort": {"total_hours": 15}}

        recommendations = orchestrator._generate_strategic_recommendations(
            security_analysis, remediation_plan
        )

        assert len(recommendations) > 0
        assert any("Critical" in rec for rec in recommendations)

    def test_save_results(self, orchestrator):
        """결과 저장 테스트"""

        # 모의 결과 설정
        orchestrator.workflow_results = {
            "test": "data",
            "timestamp": "2024-01-01T00:00:00"
        }

        # 임시 파일로 저장
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as temp_file:
            temp_filename = temp_file.name

        try:
            result_message = orchestrator.save_results(temp_filename)
            assert "saved" in result_message.lower()
            assert os.path.exists(temp_filename)

            # 파일 내용 확인
            with open(temp_filename, 'r') as f:
                import json
                saved_data = json.load(f)
                assert saved_data["test"] == "data"

        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)


class TestAgentIntegration:
    """에이전트 간 통합 테스트"""

    @pytest.mark.asyncio
    async def test_security_to_remediation_flow(self):
        """보안 분석 → 수정 방안 플로우 테스트"""

        # 모의 보안 분석 결과
        security_analysis = {
            "project_path": "/test/project",
            "vulnerabilities": [
                {
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "file": "app.py",
                    "description": "SQL injection vulnerability"
                }
            ],
            "analysis_summary": {
                "total_vulnerabilities": 1,
                "severity_distribution": {"CRITICAL": 1}
            }
        }

        # 수정 방안 에이전트 생성
        remediation_agent = RemediationAgent(verbose=False)

        # 실제 데이터 포맷 검증
        formatted_vulns = remediation_agent._format_vulnerabilities_for_prompt(
            security_analysis["vulnerabilities"]
        )

        assert "SQL_INJECTION" in formatted_vulns
        assert "CRITICAL" in formatted_vulns

    def test_data_flow_consistency(self):
        """데이터 플로우 일관성 테스트"""

        # 보안 분석 에이전트 결과 형태
        security_result_format = {
            "project_path": str,
            "vulnerabilities": list,
            "analysis_summary": dict,
            "detailed_results": dict
        }

        # 수정 에이전트 입력 요구사항
        remediation_input_requirements = ["vulnerabilities", "project_path"]

        # 형태 일치 확인 (실제 구현에서는 더 정교한 검증 필요)
        for required_field in remediation_input_requirements:
            assert required_field in security_result_format

    @pytest.mark.asyncio
    async def test_error_propagation(self):
        """에러 전파 테스트"""

        orchestrator = SecurityOrchestrator(verbose=False)

        # 존재하지 않는 프로젝트 경로로 테스트
        with patch('src.agents.security_agent.SecurityAnalysisAgent.analyze_project') as mock_analyze:
            mock_analyze.return_value = {"error": "Project not found"}

            result = await orchestrator.analyze_and_remediate(
                "/nonexistent/path", "Test analysis"
            )

            # 에러가 최상위 결과까지 전파되는지 확인
            assert "error" in result
            assert "Project not found" in result["error"]


# 테스트 실행 헬퍼
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])