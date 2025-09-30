"""
Progress 로깅 테스트
"""
import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.agents.orchestrator_agent import SecurityOrchestrator


async def main():
    """메인 테스트 함수"""

    orchestrator = SecurityOrchestrator(verbose=True)

    result = await orchestrator.analyze_and_remediate(
        'demo/hello-world-vulnerable',
        'Comprehensive security analysis and remediation'
    )

    print("\n" + "="*70)
    print("📄 FINAL RESULTS SUMMARY")
    print("="*70)

    if "error" not in result:
        analysis_summary = result.get("security_analysis", {}).get("analysis_summary", {})
        remediation_summary = result.get("remediation_plan", {}).get("remediation_summary", {})

        print(f"✅ Total Vulnerabilities Found: {analysis_summary.get('total_vulnerabilities', 0)}")
        print(f"✅ PR Template Created: {remediation_summary.get('pr_template_created', False)}")
        print(f"✅ Documentation Created: {remediation_summary.get('documentation_created', False)}")
    else:
        print(f"❌ Error: {result.get('error')}")

    print("="*70)


if __name__ == "__main__":
    asyncio.run(main())