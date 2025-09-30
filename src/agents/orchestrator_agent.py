"""
오케스트레이터 에이전트
보안 분석과 수정 방안 에이전트들을 조율하는 메인 에이전트
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from .security_agent import SecurityAnalysisAgent
from .remediation_agent import RemediationAgent
from ..models.llm_config import create_security_llm, SecurityModelSelector


class SecurityOrchestrator:
    """보안 분석 및 수정 워크플로우 오케스트레이터"""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        # 오케스트레이터는 종합적인 분석과 의사결정을 담당
        self.llm = create_security_llm(
            task_type="comprehensive_analysis",
            security_level="HIGH"
        )

        # 전문 에이전트들 초기화
        self.security_agent = SecurityAnalysisAgent(verbose=verbose)
        self.remediation_agent = RemediationAgent(verbose=verbose)

        # 전체 워크플로우 결과 저장
        self.workflow_results = {}
        self.performance_metrics = {
            "workflow_start_time": None,
            "workflow_end_time": None,
            "total_duration": None,
            "phases_completed": [],
            "agents_used": []
        }

    async def analyze_and_remediate(
        self,
        project_path: str,
        user_query: str = "Comprehensive security analysis and remediation"
    ) -> Dict[str, Any]:
        """전체 보안 분석 및 수정 방안 생성 워크플로우 실행"""

        self.performance_metrics["workflow_start_time"] = time.time()

        try:
            if self.verbose:
                print("\n" + "="*70)
                print("🚀 STARTING COMPREHENSIVE SECURITY WORKFLOW")
                print("="*70)
                print(f"📁 Project: {project_path}")
                print(f"📝 Query: {user_query}")
                print(f"⏰ Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("="*70 + "\n")

            # Phase 1: 보안 분석
            print("\n" + "="*70)
            print("🔍 PHASE 1: SECURITY ANALYSIS")
            print("="*70)
            print("📋 Step 1/3: Analyzing project for security vulnerabilities...")
            print("   → This may take 30-60 seconds depending on project size")

            phase1_start = time.time()
            security_analysis = await self.security_agent.analyze_project(project_path, user_query)
            phase1_duration = time.time() - phase1_start
            self.performance_metrics["phases_completed"].append("security_analysis")
            self.performance_metrics["agents_used"].append("security_agent")

            if "error" in security_analysis:
                return self._create_error_result(
                    f"Security analysis failed: {security_analysis['error']}",
                    project_path
                )

            # 보안 분석 결과 요약 출력
            print(f"\n✅ Phase 1 completed in {phase1_duration:.1f}s")
            if self.verbose:
                print(self.security_agent.get_analysis_summary())

            # Phase 2: 수정 방안 생성
            print("\n" + "="*70)
            print("🔧 PHASE 2: REMEDIATION PLANNING")
            print("="*70)
            print("📋 Step 2/3: Generating remediation plans and fix codes...")
            print("   → Creating PR templates and documentation")

            phase2_start = time.time()
            project_info = security_analysis.get("detailed_results", {}).get("project_info", {})
            remediation_plan = await self.remediation_agent.generate_remediation_plan(
                security_analysis, project_info
            )
            phase2_duration = time.time() - phase2_start
            self.performance_metrics["phases_completed"].append("remediation_planning")
            self.performance_metrics["agents_used"].append("remediation_agent")

            if "error" in remediation_plan:
                return self._create_error_result(
                    f"Remediation planning failed: {remediation_plan['error']}",
                    project_path,
                    security_analysis
                )

            # 수정 방안 결과 요약 출력
            print(f"\n✅ Phase 2 completed in {phase2_duration:.1f}s")
            if self.verbose:
                print(self.remediation_agent.get_remediation_summary())

            # Phase 3: 최종 리포트 생성
            print("\n" + "="*70)
            print("📊 PHASE 3: FINAL REPORT GENERATION")
            print("="*70)
            print("📋 Step 3/3: Generating comprehensive security report...")
            print("   → Calculating risk scores and ROI analysis")

            phase3_start = time.time()
            final_report = await self._generate_final_report(
                security_analysis, remediation_plan, project_path, user_query
            )
            phase3_duration = time.time() - phase3_start
            self.performance_metrics["phases_completed"].append("final_report")

            # 워크플로우 완료
            self.performance_metrics["workflow_end_time"] = time.time()
            self.performance_metrics["total_duration"] = (
                self.performance_metrics["workflow_end_time"] -
                self.performance_metrics["workflow_start_time"]
            )

            # 전체 결과 구성
            workflow_results = {
                "workflow_metadata": {
                    "project_path": project_path,
                    "user_query": user_query,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "workflow_version": "1.0",
                    "agents_used": list(set(self.performance_metrics["agents_used"]))
                },
                "security_analysis": security_analysis,
                "remediation_plan": remediation_plan,
                "final_report": final_report,
                "performance_metrics": self.performance_metrics,
                "executive_summary": self._create_executive_summary(security_analysis, remediation_plan)
            }

            self.workflow_results = workflow_results

            # 최종 완료 메시지
            print(f"\n✅ Phase 3 completed in {phase3_duration:.1f}s")
            print("\n" + "="*70)
            print("✅ WORKFLOW COMPLETED SUCCESSFULLY")
            print("="*70)
            print(f"⏰ Total Duration: {self.performance_metrics['total_duration']:.1f}s")
            print(f"📊 Phase Breakdown:")
            print(f"   • Phase 1 (Security Analysis): {phase1_duration:.1f}s")
            print(f"   • Phase 2 (Remediation Planning): {phase2_duration:.1f}s")
            print(f"   • Phase 3 (Final Report): {phase3_duration:.1f}s")
            print("="*70)

            if self.verbose:
                print(self._get_workflow_summary())

            return workflow_results

        except Exception as e:
            self.performance_metrics["workflow_end_time"] = time.time()
            return self._create_error_result(
                f"Workflow execution failed: {str(e)}",
                project_path
            )

    async def _generate_final_report(
        self,
        security_analysis: Dict[str, Any],
        remediation_plan: Dict[str, Any],
        project_path: str,
        user_query: str
    ) -> Dict[str, Any]:
        """최종 종합 리포트 생성"""

        try:
            # 보안 점수 계산
            vulnerabilities = security_analysis.get("vulnerabilities", [])
            severity_counts = security_analysis.get("analysis_summary", {}).get("severity_distribution", {})

            security_score = self._calculate_security_score(severity_counts)
            risk_level = self._determine_risk_level(severity_counts)

            # 비즈니스 임팩트 평가
            business_impact = self._assess_business_impact(vulnerabilities, severity_counts)

            # 컴플라이언스 상태
            compliance_status = self._evaluate_compliance_status(vulnerabilities)

            # ROI 분석
            roi_analysis = self._calculate_security_roi(
                vulnerabilities,
                remediation_plan.get("estimated_effort", {})
            )

            return {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "project_path": project_path,
                    "report_version": "1.0"
                },
                "security_posture": {
                    "overall_score": security_score,
                    "risk_level": risk_level,
                    "vulnerabilities_summary": {
                        "total": len(vulnerabilities),
                        "by_severity": severity_counts,
                        "immediate_action_required": severity_counts.get("CRITICAL", 0) > 0
                    }
                },
                "business_impact": business_impact,
                "compliance_status": compliance_status,
                "remediation_overview": {
                    "total_effort": remediation_plan.get("estimated_effort", {}),
                    "implementation_phases": len(remediation_plan.get("implementation_plan", {})),
                    "estimated_completion": self._estimate_completion_timeline(remediation_plan)
                },
                "roi_analysis": roi_analysis,
                "recommendations": self._generate_strategic_recommendations(
                    security_analysis, remediation_plan
                ),
                "next_steps": self._define_next_steps(security_analysis, remediation_plan)
            }

        except Exception as e:
            return {
                "error": f"Final report generation failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }

    def _calculate_security_score(self, severity_counts: Dict[str, int]) -> int:
        """보안 점수 계산 (100점 만점)"""
        total_vulns = sum(severity_counts.values())
        if total_vulns == 0:
            return 100

        # 심각도별 가중치
        weighted_score = (
            severity_counts.get("CRITICAL", 0) * 25 +
            severity_counts.get("HIGH", 0) * 15 +
            severity_counts.get("MEDIUM", 0) * 8 +
            severity_counts.get("LOW", 0) * 3
        )

        return max(0, 100 - weighted_score)

    def _determine_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """위험 수준 결정"""
        if severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 2:
            return "HIGH"
        elif severity_counts.get("HIGH", 0) > 0 or severity_counts.get("MEDIUM", 0) > 5:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_business_impact(self, vulnerabilities: List[Dict], severity_counts: Dict[str, int]) -> Dict[str, Any]:
        """비즈니스 임팩트 평가"""

        # 잠재적 피해 시나리오
        impact_scenarios = []

        if severity_counts.get("CRITICAL", 0) > 0:
            impact_scenarios.extend([
                "데이터 유출로 인한 고객 신뢰도 하락",
                "규제 위반 시 법적 제재 및 벌금",
                "시스템 침해로 인한 서비스 중단"
            ])

        if any(v.get("type") == "SQL_INJECTION" for v in vulnerabilities):
            impact_scenarios.append("데이터베이스 전체 노출 위험")

        if any("SECRET" in v.get("type", "") for v in vulnerabilities):
            impact_scenarios.append("API 키 및 자격증명 노출")

        # 비용 추정
        estimated_breach_cost = self._estimate_breach_cost(severity_counts)

        return {
            "risk_scenarios": impact_scenarios,
            "estimated_breach_cost": estimated_breach_cost,
            "compliance_risk": "HIGH" if severity_counts.get("CRITICAL", 0) > 0 else "MEDIUM",
            "reputation_impact": "SEVERE" if severity_counts.get("CRITICAL", 0) > 2 else "MODERATE",
            "operational_impact": {
                "immediate": severity_counts.get("CRITICAL", 0),
                "short_term": severity_counts.get("HIGH", 0),
                "long_term": severity_counts.get("MEDIUM", 0) + severity_counts.get("LOW", 0)
            }
        }

    def _estimate_breach_cost(self, severity_counts: Dict[str, int]) -> Dict[str, Any]:
        """데이터 침해 비용 추정"""

        # 업계 평균 비용 기준 (USD)
        base_cost_per_record = 150  # 개인정보 1건당 평균 비용
        estimated_records_at_risk = 1000  # 기본 추정값

        # 심각도별 비용 승수
        cost_multiplier = 1.0
        if severity_counts.get("CRITICAL", 0) > 0:
            cost_multiplier = 3.0
        elif severity_counts.get("HIGH", 0) > 0:
            cost_multiplier = 2.0

        estimated_cost = base_cost_per_record * estimated_records_at_risk * cost_multiplier

        return {
            "estimated_total_cost": estimated_cost,
            "cost_breakdown": {
                "data_recovery": estimated_cost * 0.3,
                "legal_compliance": estimated_cost * 0.2,
                "reputation_damage": estimated_cost * 0.3,
                "operational_disruption": estimated_cost * 0.2
            },
            "currency": "USD",
            "confidence_level": "MEDIUM"
        }

    def _evaluate_compliance_status(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """컴플라이언스 상태 평가"""

        # 주요 컴플라이언스 프레임워크 체크
        frameworks = {
            "GDPR": {"compliant": True, "violations": []},
            "PCI_DSS": {"compliant": True, "violations": []},
            "SOX": {"compliant": True, "violations": []},
            "HIPAA": {"compliant": True, "violations": []}
        }

        # 취약점별 컴플라이언스 영향 평가
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")

            if "SQL_INJECTION" in vuln_type:
                frameworks["PCI_DSS"]["compliant"] = False
                frameworks["PCI_DSS"]["violations"].append("Data protection requirements")
                frameworks["GDPR"]["violations"].append("Data security measures")

            if "SECRET" in vuln_type:
                for framework in frameworks.values():
                    framework["compliant"] = False
                    framework["violations"].append("Access control requirements")

        return {
            "frameworks": frameworks,
            "overall_compliance": all(f["compliant"] for f in frameworks.values()),
            "critical_violations": sum(len(f["violations"]) for f in frameworks.values()),
            "remediation_required": not all(f["compliant"] for f in frameworks.values())
        }

    def _calculate_security_roi(self, vulnerabilities: List[Dict], effort: Dict[str, Any]) -> Dict[str, Any]:
        """보안 투자 수익률 계산"""

        # 수정 비용 추정 (개발자 시급 기준)
        hourly_rate = 100  # USD per hour
        total_hours = effort.get("total_hours", 0)
        remediation_cost = total_hours * hourly_rate

        # 잠재적 침해 비용 (위에서 계산)
        potential_breach_cost = 150000  # 기본 추정값

        # ROI 계산
        cost_avoidance = potential_breach_cost
        roi_percentage = ((cost_avoidance - remediation_cost) / remediation_cost * 100) if remediation_cost > 0 else 0

        return {
            "remediation_cost": remediation_cost,
            "potential_breach_cost": potential_breach_cost,
            "cost_avoidance": cost_avoidance,
            "roi_percentage": round(roi_percentage, 1),
            "payback_period": "Immediate" if roi_percentage > 0 else "Long-term",
            "recommendation": "PROCEED" if roi_percentage > 100 else "EVALUATE"
        }

    def _generate_strategic_recommendations(
        self,
        security_analysis: Dict[str, Any],
        remediation_plan: Dict[str, Any]
    ) -> List[str]:
        """전략적 권장사항 생성"""

        recommendations = []
        severity_counts = security_analysis.get("analysis_summary", {}).get("severity_distribution", {})

        # 즉시 조치 권장사항
        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append("🚨 Critical 취약점 즉시 수정 - 운영 중단 위험")

        # 프로세스 개선 권장사항
        if sum(severity_counts.values()) > 10:
            recommendations.extend([
                "🔄 정기적인 보안 스캔 프로세스 구축",
                "👥 개발팀 보안 교육 실시",
                "🛡️ DevSecOps 파이프라인 도입"
            ])

        # 기술적 권장사항
        vuln_types = set()
        for vuln in security_analysis.get("vulnerabilities", []):
            vuln_types.add(vuln.get("type", ""))

        if "SQL_INJECTION" in vuln_types:
            recommendations.append("🗃️ ORM 사용으로 SQL Injection 근본 차단")

        if "SECRET" in " ".join(vuln_types):
            recommendations.append("🔐 Secret Management 솔루션 도입")

        # 거버넌스 권장사항
        recommendations.extend([
            "📋 보안 코딩 가이드라인 수립",
            "🔍 코드 리뷰에 보안 체크리스트 포함",
            "📊 보안 메트릭 모니터링 대시보드 구축"
        ])

        return recommendations

    def _define_next_steps(
        self,
        security_analysis: Dict[str, Any],
        remediation_plan: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """다음 단계 정의"""

        steps = []
        severity_counts = security_analysis.get("analysis_summary", {}).get("severity_distribution", {})

        # 1. 즉시 조치 단계
        if severity_counts.get("CRITICAL", 0) > 0:
            steps.append({
                "phase": "immediate",
                "timeline": "24 hours",
                "actions": [
                    "Critical 취약점 수정 작업 시작",
                    "임시 보안 조치 적용",
                    "모니터링 강화"
                ],
                "responsible": "Development Team Lead",
                "priority": "P0"
            })

        # 2. 단기 조치 단계
        steps.append({
            "phase": "short_term",
            "timeline": "1-2 weeks",
            "actions": [
                "High severity 취약점 수정",
                "보안 테스트 케이스 작성",
                "코드 리뷰 및 배포"
            ],
            "responsible": "Development Team",
            "priority": "P1"
        })

        # 3. 중장기 개선 단계
        steps.append({
            "phase": "medium_term",
            "timeline": "1-3 months",
            "actions": [
                "Medium/Low 취약점 수정",
                "보안 프로세스 개선",
                "팀 교육 실시"
            ],
            "responsible": "Security Team",
            "priority": "P2"
        })

        # 4. 지속적 개선 단계
        steps.append({
            "phase": "continuous",
            "timeline": "Ongoing",
            "actions": [
                "정기 보안 스캔 자동화",
                "보안 메트릭 모니터링",
                "프로세스 개선"
            ],
            "responsible": "DevSecOps Team",
            "priority": "P3"
        })

        return steps

    def _estimate_completion_timeline(self, remediation_plan: Dict[str, Any]) -> str:
        """완료 예상 시점 계산"""

        effort = remediation_plan.get("estimated_effort", {})
        total_days = effort.get("total_days", 0)

        if total_days <= 1:
            return "1 day"
        elif total_days <= 7:
            return f"{int(total_days)} days"
        elif total_days <= 30:
            return f"{int(total_days / 7)} weeks"
        else:
            return f"{int(total_days / 30)} months"

    def _create_executive_summary(
        self,
        security_analysis: Dict[str, Any],
        remediation_plan: Dict[str, Any]
    ) -> str:
        """경영진을 위한 요약 보고서 생성"""

        severity_counts = security_analysis.get("analysis_summary", {}).get("severity_distribution", {})
        total_vulns = sum(severity_counts.values())
        effort = remediation_plan.get("estimated_effort", {})

        summary = f"""
# Executive Security Summary

## 🎯 Key Findings
- **Total Security Issues**: {total_vulns}
- **Critical Issues**: {severity_counts.get('CRITICAL', 0)} (require immediate attention)
- **High Priority Issues**: {severity_counts.get('HIGH', 0)}
- **Overall Risk Level**: {self._determine_risk_level(severity_counts)}

## 💼 Business Impact
- **Immediate Action Required**: {'YES' if severity_counts.get('CRITICAL', 0) > 0 else 'NO'}
- **Estimated Remediation Time**: {effort.get('total_days', 0)} days
- **Recommended Team Size**: {effort.get('team_size_recommendation', 1)} developers

## 🚀 Recommended Actions
1. **Immediate** (24-48 hours): Fix {severity_counts.get('CRITICAL', 0)} critical issues
2. **Short-term** (1-2 weeks): Address {severity_counts.get('HIGH', 0)} high-priority issues
3. **Medium-term** (1-3 months): Implement security process improvements

## 📊 Success Metrics
- Zero critical vulnerabilities within 48 hours
- 90%+ reduction in high-risk issues within 2 weeks
- Automated security scanning in place within 1 month

**Next Step**: Approve immediate resource allocation for critical issue remediation.
"""

        return summary.strip()

    def _create_error_result(
        self,
        error_message: str,
        project_path: str,
        partial_results: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """에러 발생 시 결과 생성"""

        return {
            "error": error_message,
            "project_path": project_path,
            "timestamp": datetime.now().isoformat(),
            "partial_results": partial_results or {},
            "performance_metrics": self.performance_metrics,
            "recovery_suggestions": [
                "Check project path accessibility",
                "Verify tool dependencies (Trivy, etc.)",
                "Check API key configuration",
                "Review error logs for specific issues"
            ]
        }

    def _get_workflow_summary(self) -> str:
        """워크플로우 요약 생성"""

        if not self.workflow_results:
            return "No workflow results available."

        security_summary = self.workflow_results.get("security_analysis", {}).get("analysis_summary", {})
        remediation_summary = self.workflow_results.get("remediation_plan", {}).get("remediation_summary", {})
        performance = self.performance_metrics

        return f"""
🎯 Workflow Summary:
  - Total Duration: {performance.get('total_duration', 0):.1f} seconds
  - Phases Completed: {len(performance.get('phases_completed', []))}
  - Agents Used: {len(set(performance.get('agents_used', [])))}

🔍 Security Analysis:
  - Vulnerabilities Found: {security_summary.get('total_vulnerabilities', 0)}
  - Critical Issues: {security_summary.get('severity_distribution', {}).get('CRITICAL', 0)}
  - Analysis Tools Used: {len(security_summary.get('tools_used', []))}

🔧 Remediation Plan:
  - Fix Codes Generated: {remediation_summary.get('fixes_generated', 0)}
  - PR Template: {'✅' if remediation_summary.get('pr_template_created') else '❌'}
  - Documentation: {'✅' if remediation_summary.get('documentation_created') else '❌'}

✅ Ready for implementation!
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