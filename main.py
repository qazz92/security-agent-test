#!/usr/bin/env python3
"""
SecurityAgent Portfolio - Main CLI Entry Point
Tool Calling 기반 보안 취약점 분석 및 수정 방안 생성 시스템
"""

import asyncio
import argparse
import sys
import os
import json
from typing import Optional
from datetime import datetime

# 경로 설정
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.orchestrator_agent import SecurityOrchestrator
from src.utils.logger import get_security_logger
from src.utils.performance import get_performance_tracker


def create_cli_parser() -> argparse.ArgumentParser:
    """CLI 인자 파서 생성"""

    parser = argparse.ArgumentParser(
        description="🔐 SecurityAgent Portfolio - AI-Powered Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze demo/hello-world-vulnerable
  %(prog)s analyze /path/to/project --query "Focus on SQL injection"
  %(prog)s analyze . --output results.json --verbose
  %(prog)s demo --load-results
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # analyze 명령어
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze project for security vulnerabilities'
    )
    analyze_parser.add_argument(
        'project_path',
        help='Path to the project to analyze'
    )
    analyze_parser.add_argument(
        '--query', '-q',
        default='Comprehensive security analysis and remediation',
        help='Specific analysis query (default: comprehensive analysis)'
    )
    analyze_parser.add_argument(
        '--output', '-o',
        help='Output file for results (JSON format)'
    )
    analyze_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    # demo 명령어
    demo_parser = subparsers.add_parser(
        'demo',
        help='Run demo analysis on vulnerable project'
    )
    demo_parser.add_argument(
        '--load-results',
        action='store_true',
        help='Load pre-generated demo results instead of running analysis'
    )

    # ui 명령어
    ui_parser = subparsers.add_parser(
        'ui',
        help='Launch Streamlit web interface'
    )
    ui_parser.add_argument(
        '--port',
        type=int,
        default=8501,
        help='Port for Streamlit server (default: 8501)'
    )

    # performance 명령어
    perf_parser = subparsers.add_parser(
        'performance',
        help='Show performance metrics'
    )
    perf_parser.add_argument(
        '--export',
        help='Export performance data to file'
    )

    return parser


async def run_analysis(project_path: str, query: str, verbose: bool = False) -> dict:
    """보안 분석 실행"""

    if not os.path.exists(project_path):
        raise FileNotFoundError(f"Project path does not exist: {project_path}")

    logger = get_security_logger()
    logger.set_session_id(f"cli_{int(datetime.now().timestamp())}")

    print("🔐 SecurityAgent Portfolio")
    print("=" * 50)
    print(f"📁 Project: {project_path}")
    print(f"📝 Query: {query}")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 오케스트레이터 초기화
    orchestrator = SecurityOrchestrator(verbose=verbose)

    try:
        # 분석 실행
        if verbose:
            print("🚀 Initializing security analysis workflow...")

        result = await orchestrator.analyze_and_remediate(project_path, query)

        if "error" in result:
            print(f"❌ Analysis failed: {result['error']}")
            return result

        # 결과 요약 출력
        print("\n" + "=" * 50)
        print("✅ ANALYSIS COMPLETED")
        print("=" * 50)
        print(orchestrator._get_workflow_summary())

        # Executive Summary 출력
        if "executive_summary" in result:
            print("\n📋 EXECUTIVE SUMMARY")
            print("-" * 30)
            # Markdown을 간단한 텍스트로 변환
            summary = result["executive_summary"].replace("# ", "").replace("## ", "  ").replace("**", "")
            print(summary)

        return result

    except KeyboardInterrupt:
        print("\n⏹️ Analysis interrupted by user")
        return {"error": "Analysis interrupted by user"}

    except Exception as e:
        logger.log_security_event(
            logger.SecurityEventType.ERROR_OCCURRED,
            f"CLI analysis failed: {str(e)}",
            {"project_path": project_path, "query": query}
        )
        print(f"\n❌ Unexpected error: {str(e)}")
        return {"error": str(e)}


def load_demo_results() -> dict:
    """데모 결과 로드"""

    demo_results = {
        "workflow_metadata": {
            "project_path": "demo/hello-world-vulnerable",
            "analysis_timestamp": datetime.now().isoformat(),
            "demo_mode": True
        },
        "security_analysis": {
            "analysis_summary": {
                "total_vulnerabilities": 15,
                "severity_distribution": {
                    "CRITICAL": 4,
                    "HIGH": 6,
                    "MEDIUM": 3,
                    "LOW": 2
                },
                "analysis_duration": 8.3,
                "tools_used": [
                    "fetch_project_info",
                    "scan_with_trivy",
                    "analyze_dependencies",
                    "check_security_configs"
                ]
            }
        },
        "vulnerabilities": [
            {
                "type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "file": "app.py",
                "line": 15,
                "description": "SQL injection vulnerability in user query"
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "file": "app.py",
                "line": 25,
                "description": "Cross-site scripting vulnerability"
            },
            {
                "type": "HARDCODED_SECRET",
                "severity": "HIGH",
                "file": "app.py",
                "line": 8,
                "description": "Hardcoded secret key"
            }
        ],
        "remediation_plan": {
            "remediation_summary": {
                "total_vulnerabilities": 15,
                "fixes_generated": 12,
                "pr_template_created": True,
                "estimated_effort": {"total_hours": 12.5, "total_days": 1.6}
            }
        },
        "executive_summary": """# Executive Security Summary

## Key Findings
- **Total Security Issues**: 15
- **Critical Issues**: 4 (require immediate attention)
- **High Priority Issues**: 6
- **Overall Risk Level**: HIGH

## Business Impact
- **Immediate Action Required**: YES
- **Estimated Remediation Time**: 1.6 days
- **Recommended Team Size**: 2 developers

## Recommended Actions
1. **Immediate** (24-48 hours): Fix 4 critical issues
2. **Short-term** (1-2 weeks): Address 6 high-priority issues
3. **Medium-term** (1-3 months): Implement security process improvements

**Next Step**: Approve immediate resource allocation for critical issue remediation.
"""
    }

    return demo_results


def save_results(results: dict, output_file: str) -> None:
    """결과를 파일로 저장"""

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"💾 Results saved to: {output_file}")
    except Exception as e:
        print(f"❌ Failed to save results: {str(e)}")


def show_performance_metrics(export_file: Optional[str] = None) -> None:
    """성능 메트릭 표시"""

    tracker = get_performance_tracker()
    report = tracker.get_performance_report()

    if "error" in report:
        print("📊 No performance data available yet.")
        print("Run an analysis first to see performance metrics.")
        return

    print("📊 PERFORMANCE METRICS")
    print("=" * 40)

    summary = report["summary"]
    print(f"Total Tool Calls: {summary['total_tool_calls']}")
    print(f"Success Rate: {summary['success_rate']:.1f}%")
    print(f"Average Duration: {summary['average_duration']:.2f}s")
    print(f"Total Errors: {summary['total_errors']}")

    # 상위 느린 툴들
    slow_tools = report.get("top_slow_tools", [])
    if slow_tools:
        print(f"\n🐌 Slowest Tools:")
        for tool in slow_tools[:3]:
            print(f"  {tool['tool_name']}: {tool['avg_duration']:.2f}s")

    # 권장사항
    recommendations = report.get("recommendations", [])
    if recommendations:
        print(f"\n💡 Recommendations:")
        for rec in recommendations:
            print(f"  • {rec}")

    if export_file:
        export_result = tracker.export_metrics(export_file)
        print(f"\n{export_result}")


def launch_ui(port: int = 8501) -> None:
    """Streamlit UI 실행"""

    print(f"🌐 Launching Streamlit UI on port {port}...")
    print(f"📱 Open your browser to: http://localhost:{port}")

    try:
        import subprocess
        subprocess.run([
            "streamlit", "run", "streamlit_app.py",
            "--server.port", str(port),
            "--server.headless", "true"
        ])
    except KeyboardInterrupt:
        print("\n⏹️ UI server stopped")
    except Exception as e:
        print(f"❌ Failed to launch UI: {str(e)}")
        print("Make sure Streamlit is installed: pip install streamlit")


def main():
    """메인 함수"""

    parser = create_cli_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'analyze':
            # 분석 실행
            result = asyncio.run(run_analysis(
                args.project_path,
                args.query,
                args.verbose
            ))

            # 결과 저장
            if args.output and "error" not in result:
                save_results(result, args.output)

        elif args.command == 'demo':
            if args.load_results:
                # 미리 생성된 데모 결과 로드
                print("🎯 Loading demo results...")
                result = load_demo_results()

                print("\n🔐 SecurityAgent Portfolio - Demo Results")
                print("=" * 50)
                print("📁 Project: demo/hello-world-vulnerable")
                print("📊 Analysis Summary:")
                summary = result["security_analysis"]["analysis_summary"]
                print(f"  • Total Vulnerabilities: {summary['total_vulnerabilities']}")
                print(f"  • Critical: {summary['severity_distribution']['CRITICAL']}")
                print(f"  • High: {summary['severity_distribution']['HIGH']}")
                print(f"  • Analysis Time: {summary['analysis_duration']}s")

                print("\n" + result["executive_summary"])
            else:
                # 실제 데모 분석 실행
                demo_path = "demo/hello-world-vulnerable"
                if not os.path.exists(demo_path):
                    print(f"❌ Demo project not found: {demo_path}")
                    print("Make sure you're running from the project root directory.")
                    return

                result = asyncio.run(run_analysis(
                    demo_path,
                    "Comprehensive security analysis of vulnerable demo project",
                    verbose=True
                ))

        elif args.command == 'ui':
            launch_ui(args.port)

        elif args.command == 'performance':
            show_performance_metrics(args.export)

    except KeyboardInterrupt:
        print("\n⏹️ Operation cancelled by user")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()