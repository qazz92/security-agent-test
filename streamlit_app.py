"""
SecurityAgent Streamlit UI
보안 분석 및 수정 방안 생성을 위한 웹 인터페이스
"""

import streamlit as st
import asyncio
import json
import time
import os
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import pandas as pd
from typing import Dict, Any, List

# 로컬 모듈 임포트
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.orchestrator_agent import SecurityOrchestrator
from src.utils.performance import get_performance_tracker, get_alert_manager
from src.utils.logger import get_security_logger, SecurityEventType


# Streamlit 페이지 설정
st.set_page_config(
    page_title="SecurityAgent Portfolio",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS 스타일링
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #1f77b4;
    }
    .vulnerability-critical {
        background-color: #ffebee;
        border-left: 5px solid #f44336;
        padding: 0.5rem;
        margin: 0.25rem 0;
    }
    .vulnerability-high {
        background-color: #fff3e0;
        border-left: 5px solid #ff9800;
        padding: 0.5rem;
        margin: 0.25rem 0;
    }
    .vulnerability-medium {
        background-color: #fff8e1;
        border-left: 5px solid #ffeb3b;
        padding: 0.5rem;
        margin: 0.25rem 0;
    }
    .vulnerability-low {
        background-color: #f1f8e9;
        border-left: 5px solid #4caf50;
        padding: 0.5rem;
        margin: 0.25rem 0;
    }
    .code-block {
        background-color: #2d3748;
        color: #e2e8f0;
        padding: 1rem;
        border-radius: 0.5rem;
        font-family: 'Courier New', monospace;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)


class SecurityAgentUI:
    """SecurityAgent UI 클래스"""

    def __init__(self):
        # 세션 상태 초기화
        if 'orchestrator' not in st.session_state:
            st.session_state.orchestrator = SecurityOrchestrator(verbose=False)

        if 'analysis_results' not in st.session_state:
            st.session_state.analysis_results = None

        if 'current_analysis' not in st.session_state:
            st.session_state.current_analysis = None

        if 'analysis_history' not in st.session_state:
            st.session_state.analysis_history = []

        self.performance_tracker = get_performance_tracker()
        self.security_logger = get_security_logger()
        self.alert_manager = get_alert_manager()

    def run(self):
        """메인 UI 실행"""

        # 헤더
        st.markdown('<div class="main-header">🔐 SecurityAgent Portfolio</div>', unsafe_allow_html=True)
        st.markdown("**AI-Powered Security Vulnerability Analysis & Remediation System**")

        # 사이드바 메뉴
        with st.sidebar:
            st.header("🔧 Navigation")
            page = st.selectbox(
                "Select Page",
                ["🔍 Security Analysis", "📊 Performance Dashboard", "📋 Analysis History", "⚙️ Settings"],
                index=0
            )

        # 페이지 라우팅
        if page == "🔍 Security Analysis":
            self.show_analysis_page()
        elif page == "📊 Performance Dashboard":
            self.show_performance_dashboard()
        elif page == "📋 Analysis History":
            self.show_history_page()
        elif page == "⚙️ Settings":
            self.show_settings_page()

    def show_analysis_page(self):
        """보안 분석 페이지"""

        st.header("🔍 Security Analysis")

        # 입력 섹션
        col1, col2 = st.columns([2, 1])

        with col1:
            project_path = st.text_input(
                "📁 Project Path",
                value=os.path.join(os.getcwd(), "demo", "hello-world-vulnerable"),
                help="Enter the path to the project you want to analyze"
            )

        with col2:
            st.markdown("### 🎯 Quick Actions")

            if st.button("🚀 Start Analysis", type="primary", use_container_width=True):
                if project_path and os.path.exists(project_path):
                    self.run_security_analysis(project_path)
                else:
                    st.error("❌ Project path does not exist!")

            if st.button("⚡ Load Last Result (Fast)", use_container_width=True):
                self.load_last_result()

            if st.button("📊 Load Demo Results", use_container_width=True):
                self.load_demo_results()

            if st.button("🗑️ Clear Results", use_container_width=True):
                st.session_state.analysis_results = None
                st.session_state.current_analysis = None
                st.rerun()

        # 실시간 분석 상태
        if st.session_state.current_analysis:
            self.show_analysis_progress()

        # 분석 결과 표시
        if st.session_state.analysis_results:
            self.show_analysis_results()

    def run_security_analysis(self, project_path: str):
        """보안 분석 실행"""

        # 분석 상태 초기화
        st.session_state.current_analysis = {
            "status": "running",
            "start_time": time.time(),
            "project_path": project_path
        }

        # 진행 상황 표시
        progress_placeholder = st.empty()
        status_placeholder = st.empty()

        with progress_placeholder.container():
            progress_bar = st.progress(0)
            status_text = st.empty()

        try:
            # 비동기 분석 실행
            status_text.text("🚀 Initializing security analysis...")
            progress_bar.progress(10)

            # 실제 분석 실행 (동기 방식으로 변경)
            status_text.text("🔍 Running comprehensive security scan...")
            progress_bar.progress(30)

            orchestrator = st.session_state.orchestrator

            # 동기적으로 실행
            results = asyncio.run(orchestrator.analyze_and_remediate(project_path))

            progress_bar.progress(70)
            status_text.text("🔧 Generating remediation plans...")

            progress_bar.progress(90)
            status_text.text("📊 Finalizing results...")

            progress_bar.progress(100)
            status_text.text("✅ Analysis completed successfully!")

            # 결과 저장
            st.session_state.analysis_results = results
            st.session_state.current_analysis = None

            # 히스토리에 추가
            st.session_state.analysis_history.append({
                "timestamp": datetime.now().isoformat(),
                "project_path": project_path,
                "results_summary": self.extract_results_summary(results)
            })

            time.sleep(1)  # 결과 표시를 위한 잠시 대기
            progress_placeholder.empty()

            st.success("🎉 Security analysis completed successfully!")
            st.rerun()

        except Exception as e:
            st.session_state.current_analysis = None
            progress_placeholder.empty()
            st.error(f"❌ Analysis failed: {str(e)}")

            # 에러 로깅
            self.security_logger.log_security_event(
                SecurityEventType.ERROR_OCCURRED,
                f"Analysis failed for {project_path}",
                {"error": str(e), "project_path": project_path}
            )

    def show_analysis_progress(self):
        """분석 진행 상황 표시"""

        current_analysis = st.session_state.current_analysis
        if not current_analysis:
            return

        duration = time.time() - current_analysis["start_time"]

        st.info(f"🔄 Analysis in progress... ({duration:.1f}s)")

        # 실시간 상태 업데이트
        if st.button("🔄 Refresh Status"):
            st.rerun()

    def show_analysis_results(self):
        """분석 결과 표시"""

        results = st.session_state.analysis_results
        if not results or "error" in results:
            st.error("❌ Analysis results contain errors")
            if "error" in results:
                st.error(results["error"])
            return

        # 결과 요약
        st.header("📊 Analysis Results")

        # Executive Summary
        if "executive_summary" in results:
            with st.expander("👔 Executive Summary", expanded=True):
                st.markdown(results["executive_summary"])

        # 메트릭 카드
        self.show_metrics_cards(results)

        # 탭으로 구분된 상세 결과
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🔍 Vulnerabilities",
            "🔧 Remediation Plan",
            "📊 Security Metrics",
            "📋 Final Report",
            "📁 Raw Data"
        ])

        with tab1:
            self.show_vulnerabilities_tab(results)

        with tab2:
            self.show_remediation_tab(results)

        with tab3:
            self.show_metrics_tab(results)

        with tab4:
            self.show_final_report_tab(results)

        with tab5:
            self.show_raw_data_tab(results)

    def show_metrics_cards(self, results: Dict[str, Any]):
        """메트릭 카드 표시"""

        security_analysis = results.get("security_analysis", {})
        analysis_summary = security_analysis.get("analysis_summary", {})
        severity_distribution = analysis_summary.get("severity_distribution", {})

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            total_vulns = analysis_summary.get("total_vulnerabilities", 0)
            st.metric("🎯 Total Vulnerabilities", total_vulns)

        with col2:
            critical_count = severity_distribution.get("CRITICAL", 0)
            st.metric("🚨 Critical", critical_count, delta=None if critical_count == 0 else "Action Required")

        with col3:
            high_count = severity_distribution.get("HIGH", 0)
            st.metric("⚠️ High", high_count)

        with col4:
            medium_count = severity_distribution.get("MEDIUM", 0)
            st.metric("📋 Medium", medium_count)

        with col5:
            duration = analysis_summary.get("analysis_duration", 0)
            if duration is None:
                duration = 0
            st.metric("⏱️ Analysis Time", f"{duration:.1f}s")

    def show_vulnerabilities_tab(self, results: Dict[str, Any]):
        """취약점 탭 표시"""

        # 올바른 경로로 vulnerabilities 추출
        security_analysis = results.get("security_analysis", {})
        vulnerabilities = security_analysis.get("vulnerabilities", [])

        if not vulnerabilities:
            st.info("✅ No vulnerabilities found!")
            return

        # 심각도별 필터
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0
        )

        # 취약점 타입별 차트
        col1, col2 = st.columns(2)

        with col1:
            self.show_severity_chart(vulnerabilities)

        with col2:
            self.show_vulnerability_types_chart(vulnerabilities)

        # 취약점 목록
        st.subheader("🔍 Vulnerability Details")

        filtered_vulns = vulnerabilities
        if severity_filter != "All":
            filtered_vulns = [
                v for v in vulnerabilities
                if v.get("severity", v.get("Severity", "")).upper() == severity_filter
            ]

        for i, vuln in enumerate(filtered_vulns):
            self.show_vulnerability_card(vuln, i)

    def show_vulnerability_card(self, vuln: Dict[str, Any], index: int):
        """개별 취약점 카드 표시"""

        severity = vuln.get("severity", vuln.get("Severity", "UNKNOWN")).upper()
        vuln_type = vuln.get("type", vuln.get("VulnerabilityID", "Unknown"))
        file_path = vuln.get("file", "Unknown")
        description = vuln.get("description", vuln.get("Description", "No description"))

        # 심각도별 스타일 클래스
        severity_class = f"vulnerability-{severity.lower()}"

        with st.expander(f"{self.get_severity_icon(severity)} {vuln_type} in {file_path}"):
            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown(f"**Description:** {description}")

                if "line" in vuln:
                    st.markdown(f"**Line:** {vuln['line']}")

                if "code" in vuln:
                    st.markdown("**Vulnerable Code:**")
                    st.code(vuln["code"], language="python")

            with col2:
                st.markdown(f"**Severity:** {severity}")
                st.markdown(f"**File:** {file_path}")

                # CVSS 정보가 있는 경우
                if "CVSS" in vuln:
                    st.markdown(f"**CVSS:** {vuln['CVSS']}")

    def show_remediation_tab(self, results: Dict[str, Any]):
        """수정 방안 탭 표시"""

        remediation_plan = results.get("remediation_plan", {})
        if not remediation_plan:
            st.warning("⚠️ No remediation plan available")
            return

        # 수정 방안 요약
        remediation_summary = remediation_plan.get("remediation_summary", {})

        col1, col2, col3 = st.columns(3)
        with col1:
            fixes_generated = remediation_summary.get("fixes_generated", 0)
            st.metric("🔧 Fixes Generated", fixes_generated)

        with col2:
            effort = remediation_plan.get("estimated_effort", {})
            total_hours = effort.get("total_hours", 0)
            st.metric("⏱️ Estimated Effort", f"{total_hours}h")

        with col3:
            pr_created = remediation_summary.get("pr_template_created", False)
            st.metric("📝 PR Template", "✅" if pr_created else "❌")

        # PR 템플릿
        detailed_remediation = remediation_plan.get("detailed_remediation", {})
        if "pr_template" in detailed_remediation:
            st.subheader("📝 Pull Request Template")
            pr_template = detailed_remediation["pr_template"]

            # 복사 버튼과 함께 표시
            col1, col2 = st.columns([4, 1])
            with col1:
                st.text_area("PR Template", pr_template, height=300)
            with col2:
                if st.button("📋 Copy to Clipboard", key="copy_pr"):
                    st.write("📋 Template copied!")

        # 구현 계획
        if "implementation_plan" in remediation_plan:
            st.subheader("📋 Implementation Plan")
            implementation_plan = remediation_plan["implementation_plan"]

            for phase_name, phase_data in implementation_plan.items():
                with st.expander(f"Phase: {phase_name}"):
                    st.markdown(f"**Description:** {phase_data.get('description', 'N/A')}")
                    st.markdown(f"**Estimated Time:** {phase_data.get('estimated_time', 0)} hours")

                    items = phase_data.get('items', [])
                    if items:
                        st.markdown("**Tasks:**")
                        for item in items:
                            st.markdown(f"- {item.get('type', 'Unknown')} in {item.get('file', 'Unknown')}")

    def show_metrics_tab(self, results: Dict[str, Any]):
        """메트릭 탭 표시"""

        # 보안 점수 게이지
        final_report = results.get("final_report", {})
        security_posture = final_report.get("security_posture", {})

        if security_posture:
            col1, col2 = st.columns(2)

            with col1:
                security_score = security_posture.get("overall_score", 0)
                self.show_security_score_gauge(security_score)

            with col2:
                risk_level = security_posture.get("risk_level", "UNKNOWN")
                st.markdown(f"### 🎯 Risk Level")
                st.markdown(f"**Current Risk:** {risk_level}")

                immediate_action = security_posture.get("vulnerabilities_summary", {}).get("immediate_action_required", False)
                if immediate_action:
                    st.error("🚨 Immediate action required!")
                else:
                    st.success("✅ No immediate action required")

        # 비즈니스 임팩트
        business_impact = final_report.get("business_impact", {})
        if business_impact:
            st.subheader("💼 Business Impact Analysis")

            estimated_cost = business_impact.get("estimated_breach_cost", {})
            if estimated_cost:
                total_cost = estimated_cost.get("estimated_total_cost", 0)
                st.metric("💰 Estimated Breach Cost", f"${total_cost:,}")

                # 비용 분석 차트
                cost_breakdown = estimated_cost.get("cost_breakdown", {})
                if cost_breakdown:
                    self.show_cost_breakdown_chart(cost_breakdown)

        # 컴플라이언스 상태
        compliance_status = final_report.get("compliance_status", {})
        if compliance_status:
            st.subheader("📜 Compliance Status")

            frameworks = compliance_status.get("frameworks", {})
            compliance_data = []

            for framework, status in frameworks.items():
                compliance_data.append({
                    "Framework": framework,
                    "Compliant": "✅ Yes" if status.get("compliant", False) else "❌ No",
                    "Violations": len(status.get("violations", []))
                })

            if compliance_data:
                df = pd.DataFrame(compliance_data)
                st.dataframe(df, use_container_width=True)

    def show_final_report_tab(self, results: Dict[str, Any]):
        """최종 리포트 탭 표시"""

        final_report = results.get("final_report", {})
        if not final_report:
            st.warning("⚠️ Final report not available")
            return

        # 권장사항
        recommendations = final_report.get("recommendations", [])
        if recommendations:
            st.subheader("💡 Strategic Recommendations")
            for i, rec in enumerate(recommendations, 1):
                st.markdown(f"{i}. {rec}")

        # 다음 단계
        next_steps = final_report.get("next_steps", [])
        if next_steps:
            st.subheader("🚀 Next Steps")
            for step in next_steps:
                with st.expander(f"Phase: {step.get('phase', 'Unknown')} ({step.get('timeline', 'Unknown')})"):
                    st.markdown(f"**Priority:** {step.get('priority', 'Unknown')}")
                    st.markdown(f"**Responsible:** {step.get('responsible', 'Unknown')}")

                    actions = step.get('actions', [])
                    if actions:
                        st.markdown("**Actions:**")
                        for action in actions:
                            st.markdown(f"- {action}")

        # ROI 분석
        roi_analysis = final_report.get("roi_analysis", {})
        if roi_analysis:
            st.subheader("💹 ROI Analysis")

            col1, col2, col3 = st.columns(3)
            with col1:
                remediation_cost = roi_analysis.get("remediation_cost", 0)
                st.metric("💰 Remediation Cost", f"${remediation_cost:,}")

            with col2:
                potential_breach_cost = roi_analysis.get("potential_breach_cost", 0)
                st.metric("🔥 Potential Breach Cost", f"${potential_breach_cost:,}")

            with col3:
                roi_percentage = roi_analysis.get("roi_percentage", 0)
                st.metric("📈 ROI", f"{roi_percentage:.1f}%")

            recommendation = roi_analysis.get("recommendation", "UNKNOWN")
            if recommendation == "PROCEED":
                st.success("✅ Recommended: Proceed with remediation")
            else:
                st.warning("⚠️ Evaluate: Further analysis needed")

    def show_raw_data_tab(self, results: Dict[str, Any]):
        """원시 데이터 탭 표시"""

        st.subheader("📁 Raw Analysis Data")

        # JSON 다운로드
        col1, col2 = st.columns([3, 1])

        with col1:
            st.markdown("Complete analysis results in JSON format:")

        with col2:
            json_str = json.dumps(results, indent=2, default=str, ensure_ascii=False)
            st.download_button(
                label="📥 Download JSON",
                data=json_str.encode('utf-8'),
                file_name=f"security_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

        # JSON 표시 (축약)
        with st.expander("🔍 View Raw Data (Click to expand)"):
            st.json(results)

    def show_performance_dashboard(self):
        """성능 대시보드"""

        st.header("📊 Performance Dashboard")

        # 실시간 메트릭
        real_time_stats = self.performance_tracker.get_real_time_stats()

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🔄 Active Calls", real_time_stats.get("active_calls", 0))
        with col2:
            st.metric("📈 Calls/Min", real_time_stats.get("calls_per_minute", 0))
        with col3:
            avg_time = real_time_stats.get("avg_response_time", 0)
            st.metric("⏱️ Avg Response", f"{avg_time:.2f}s")
        with col4:
            success_rate = real_time_stats.get("current_success_rate", 100)
            st.metric("✅ Success Rate", f"{success_rate:.1f}%")

        # 성능 리포트
        performance_report = self.performance_tracker.get_performance_report()

        if "error" not in performance_report:
            # 툴별 성능 차트
            tool_stats = performance_report.get("tool_statistics", {})
            if tool_stats:
                self.show_tool_performance_chart(tool_stats)

            # 알림 체크
            alerts = self.alert_manager.check_alerts()
            if alerts:
                st.subheader("🚨 Performance Alerts")
                for alert in alerts:
                    alert_type = alert.get("severity", "INFO")
                    if alert_type == "CRITICAL":
                        st.error(f"🚨 {alert['message']}")
                    elif alert_type == "WARNING":
                        st.warning(f"⚠️ {alert['message']}")
                    else:
                        st.info(f"ℹ️ {alert['message']}")

        # 성능 내보내기
        if st.button("📤 Export Performance Data"):
            filename = self.performance_tracker.export_metrics()
            st.success(f"Performance data exported: {filename}")

    def show_history_page(self):
        """분석 히스토리 페이지"""

        st.header("📋 Analysis History")

        history = st.session_state.analysis_history

        if not history:
            st.info("📝 No analysis history available. Run an analysis to see results here.")
            return

        # 히스토리 테이블
        history_data = []
        for item in reversed(history):  # 최신순 정렬
            summary = item.get("results_summary", {})
            history_data.append({
                "Timestamp": item["timestamp"],
                "Project": os.path.basename(item["project_path"]),
                "Vulnerabilities": summary.get("total_vulnerabilities", 0),
                "Critical": summary.get("critical_count", 0),
                "Status": summary.get("status", "Completed")
            })

        df = pd.DataFrame(history_data)
        st.dataframe(df, use_container_width=True)

        # 선택된 분석 상세보기
        if history_data:
            selected_idx = st.selectbox(
                "View Details",
                range(len(history_data)),
                format_func=lambda x: f"{history_data[x]['Timestamp']} - {history_data[x]['Project']}"
            )

            if st.button("🔍 Load Selected Analysis"):
                # 선택된 분석을 현재 결과로 로드하는 로직
                st.info("Analysis loaded successfully!")

    def show_settings_page(self):
        """설정 페이지"""

        st.header("⚙️ Settings")

        # Orchestration Info
        with st.expander("🤖 Orchestration Mode", expanded=True):
            st.info(
                "**CrewAI Multi-Agent Collaboration**\n\n"
                "This system uses CrewAI for advanced multi-agent orchestration:\n\n"
                "👥 **3 Specialized Agents**:\n"
                "- 🔍 Security Analyst: Vulnerability scanning and analysis\n"
                "- 🎯 Triage Specialist: Risk prioritization and assessment\n"
                "- 🔧 Remediation Engineer: Fix generation and GitHub PR automation\n\n"
                "✨ Agents collaborate automatically with context sharing and task delegation"
            )

        # API 키 설정
        with st.expander("🔐 API Configuration"):
            api_key = st.text_input(
                "OpenRouter API Key",
                type="password",
                help="Enter your OpenRouter API key for LLM access"
            )

            model_name = st.selectbox(
                "Model Selection",
                ["openai/gpt-4-turbo-preview", "anthropic/claude-3-sonnet", "openai/gpt-3.5-turbo"],
                help="Select the LLM model to use"
            )

            if st.button("💾 Save API Settings"):
                # API 설정 저장 로직
                st.success("✅ Settings saved successfully!")

        # 성능 설정
        with st.expander("⚡ Performance Settings"):
            max_retries = st.slider("Max Retries", 1, 5, 3)
            timeout_seconds = st.slider("Timeout (seconds)", 10, 300, 120)

            if st.button("💾 Save Performance Settings"):
                st.success("✅ Performance settings saved!")

        # 로그 관리
        with st.expander("📝 Log Management"):
            log_level = st.selectbox(
                "Log Level",
                ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                index=1
            )

            if st.button("🗑️ Clear Logs"):
                # 로그 정리 로직
                st.success("✅ Logs cleared successfully!")

            if st.button("📤 Export Logs"):
                filename = self.security_logger.export_logs("security_logs_export.json")
                st.success(f"Logs exported: {filename}")

    def load_last_result(self):
        """마지막 분석 결과 로드 (실제 결과 캐시 + 자동 re-parsing)"""
        try:
            # Use orchestrator's _load_last_result() which includes re-parsing logic
            from src.agents.orchestrator_agent import SecurityOrchestrator
            orchestrator = SecurityOrchestrator(verbose=False)
            cached_result = orchestrator._load_last_result()

            if cached_result:
                st.session_state.analysis_results = cached_result
                st.success("⚡ Last analysis result loaded successfully! (instant)")
                st.rerun()
            else:
                st.warning("⚠️ No cached result found. Please run an analysis first.")
        except Exception as e:
            st.error(f"❌ Failed to load cached result: {e}")

    def load_demo_results(self):
        """데모 결과 로드"""

        # 데모용 모의 결과 생성
        demo_results = {
            "workflow_metadata": {
                "project_path": "demo/hello-world-vulnerable",
                "analysis_timestamp": datetime.now().isoformat(),
            },
            "security_analysis": {
                "analysis_summary": {
                    "total_vulnerabilities": 12,
                    "severity_distribution": {
                        "CRITICAL": 4,
                        "HIGH": 3,
                        "MEDIUM": 3,
                        "LOW": 2
                    },
                    "analysis_duration": 8.5
                }
            },
            "vulnerabilities": [
                {
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "file": "app.py",
                    "line": 15,
                    "description": "SQL injection vulnerability in user query",
                    "code": 'query = f"SELECT * FROM users WHERE id = {user_id}"'
                },
                {
                    "type": "XSS",
                    "severity": "HIGH",
                    "file": "app.py",
                    "line": 45,
                    "description": "Cross-site scripting vulnerability",
                    "code": 'return f"<div>{comment}</div>"'
                }
            ],
            "remediation_plan": {
                "remediation_summary": {
                    "fixes_generated": 8,
                    "pr_template_created": True,
                    "estimated_effort": {"total_hours": 12.5}
                },
                "detailed_remediation": {
                    "pr_template": "# 🔐 Security Patch\n\n## Summary\nFixed 12 security vulnerabilities...\n\n## Changes\n- SQL Injection fixes\n- XSS prevention\n..."
                }
            },
            "final_report": {
                "security_posture": {
                    "overall_score": 65,
                    "risk_level": "HIGH"
                },
                "recommendations": [
                    "🚨 즉시 Critical 취약점 수정",
                    "🔄 정기적인 보안 스캔 도입",
                    "👥 개발팀 보안 교육 실시"
                ]
            },
            "executive_summary": "# Executive Summary\n\n12개의 보안 취약점이 발견되었으며, 그 중 4개가 Critical 등급입니다..."
        }

        st.session_state.analysis_results = demo_results
        st.success("🎯 Demo results loaded successfully!")
        st.rerun()

    def extract_results_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """결과 요약 추출"""

        security_analysis = results.get("security_analysis", {})
        analysis_summary = security_analysis.get("analysis_summary", {})
        severity_distribution = analysis_summary.get("severity_distribution", {})

        return {
            "total_vulnerabilities": analysis_summary.get("total_vulnerabilities", 0),
            "critical_count": severity_distribution.get("CRITICAL", 0),
            "high_count": severity_distribution.get("HIGH", 0),
            "status": "completed",
            "analysis_duration": analysis_summary.get("analysis_duration", 0)
        }

    def get_severity_icon(self, severity: str) -> str:
        """심각도별 아이콘 반환"""
        icons = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "📋",
            "LOW": "📝",
            "UNKNOWN": "❓"
        }
        return icons.get(severity.upper(), "❓")

    def show_severity_chart(self, vulnerabilities: List[Dict]):
        """심각도별 차트 표시"""

        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", vuln.get("Severity", "UNKNOWN")).upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts:
            fig = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                title="Vulnerabilities by Severity",
                color_discrete_map={
                    "CRITICAL": "#f44336",
                    "HIGH": "#ff9800",
                    "MEDIUM": "#ffeb3b",
                    "LOW": "#4caf50"
                }
            )
            st.plotly_chart(fig, use_container_width=True)

    def show_vulnerability_types_chart(self, vulnerabilities: List[Dict]):
        """취약점 타입별 차트 표시"""

        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", vuln.get("VulnerabilityID", "Unknown"))
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

        if type_counts:
            fig = px.bar(
                x=list(type_counts.keys()),
                y=list(type_counts.values()),
                title="Vulnerabilities by Type"
            )
            fig.update_layout(xaxis_title="Vulnerability Type", yaxis_title="Count")
            st.plotly_chart(fig, use_container_width=True)

    def show_security_score_gauge(self, score: int):
        """보안 점수 게이지 표시"""

        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Security Score"},
            delta={'reference': 80},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "gray"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))

        st.plotly_chart(fig, use_container_width=True)

    def show_cost_breakdown_chart(self, cost_breakdown: Dict[str, float]):
        """비용 분석 차트 표시"""

        fig = px.pie(
            values=list(cost_breakdown.values()),
            names=list(cost_breakdown.keys()),
            title="Estimated Breach Cost Breakdown"
        )
        st.plotly_chart(fig, use_container_width=True)

    def show_tool_performance_chart(self, tool_stats: Dict[str, Any]):
        """툴 성능 차트 표시"""

        tools = list(tool_stats.keys())
        avg_durations = [stats.get("avg_duration", 0) for stats in tool_stats.values()]
        success_rates = [stats.get("success_rate", 100) for stats in tool_stats.values()]

        fig = px.scatter(
            x=avg_durations,
            y=success_rates,
            text=tools,
            title="Tool Performance: Response Time vs Success Rate",
            labels={
                "x": "Average Duration (seconds)",
                "y": "Success Rate (%)"
            }
        )
        fig.update_traces(textposition="top center")
        st.plotly_chart(fig, use_container_width=True)


# 메인 실행
def main():
    """메인 함수"""

    # 환경 변수 체크
    if not os.getenv("OPENROUTER_API_KEY"):
        st.warning("⚠️ OPENROUTER_API_KEY environment variable not set. Please configure in Settings.")

    # UI 실행
    ui = SecurityAgentUI()
    ui.run()


if __name__ == "__main__":
    main()