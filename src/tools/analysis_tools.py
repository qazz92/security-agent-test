"""
분석 툴들
취약점 데이터 분석, 우선순위 계산 등
"""

import time
from typing import Dict, List, Any, Optional
from langchain_core.tools import tool
import json


@tool
def calculate_priority_score(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    취약점의 우선순위 점수를 계산합니다.

    Args:
        vulnerability: 취약점 정보 딕셔너리

    Returns:
        우선순위 점수 및 메타데이터
    """
    try:
        # CVSS 기본 점수 매핑
        cvss_scores = {
            "CRITICAL": 9.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 2.0,
            "UNKNOWN": 1.0
        }

        severity = vulnerability.get('severity', 'MEDIUM')
        base_score = cvss_scores.get(severity, 4.0)

        # 취약점 타입별 가중치
        type_weights = {
            "SQL_INJECTION": 1.0,
            "COMMAND_INJECTION": 1.0,
            "UNSAFE_DESERIALIZATION": 0.9,
            "XSS": 0.8,
            "HARDCODED_SECRET": 0.7,
            "HARDCODED_CREDENTIALS": 0.7,
            "DEBUG_MODE": 0.5,
            "INSECURE_NETWORK": 0.6
        }

        vuln_type = vulnerability.get('type', 'UNKNOWN')
        type_weight = type_weights.get(vuln_type, 0.5)

        # 환경별 가중치
        environment = vulnerability.get('environment', 'development')
        env_weight = 1.0 if environment == 'production' else 0.7

        # Exploitability 계산
        exploitability = 0.8 if vuln_type in ["SQL_INJECTION", "COMMAND_INJECTION"] else 0.5

        # 최종 점수 계산
        final_score = base_score * type_weight * env_weight * exploitability

        # 우선순위 결정
        if final_score >= 7.0:
            priority = "P0"
            estimated_fix_time = "2-4 hours"
        elif final_score >= 5.0:
            priority = "P1"
            estimated_fix_time = "1-2 hours"
        elif final_score >= 3.0:
            priority = "P2"
            estimated_fix_time = "30min-1hr"
        else:
            priority = "P3"
            estimated_fix_time = "15-30min"

        return {
            "vulnerability_id": vulnerability.get('id', 'unknown'),
            "vulnerability_type": vuln_type,
            "base_score": base_score,
            "type_weight": type_weight,
            "env_weight": env_weight,
            "exploitability": exploitability,
            "final_score": round(final_score, 2),
            "priority": priority,
            "estimated_fix_time": estimated_fix_time,
            "severity": severity,
            "calculation_timestamp": time.time(),
            "factors": {
                "severity_impact": base_score,
                "type_criticality": type_weight,
                "environment_factor": env_weight,
                "exploit_difficulty": exploitability
            }
        }

    except Exception as e:
        return {"error": f"Priority calculation failed: {str(e)}"}


@tool
def analyze_vulnerability_trends(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    취약점 목록을 분석하여 트렌드와 패턴을 찾습니다.

    Args:
        vulnerabilities: 취약점 목록

    Returns:
        트렌드 분석 결과
    """
    try:
        if not vulnerabilities:
            return {"error": "No vulnerabilities provided for analysis"}

        # 심각도별 분포
        severity_distribution = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

        # 타입별 분포
        type_distribution = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'UNKNOWN')
            type_distribution[vuln_type] = type_distribution.get(vuln_type, 0) + 1

        # 파일별 분포
        file_distribution = {}
        for vuln in vulnerabilities:
            file_path = vuln.get('file', 'unknown')
            file_distribution[file_path] = file_distribution.get(file_path, 0) + 1

        # 가장 위험한 파일들 식별
        risky_files = sorted(file_distribution.items(), key=lambda x: x[1], reverse=True)[:5]

        # 수정 복잡도 분석
        fix_complexity = {
            "easy": 0,    # 설정 변경, 버전 업그레이드
            "medium": 0,  # 코드 일부 수정
            "hard": 0     # 아키텍처 변경 필요
        }

        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'UNKNOWN')
            if vuln_type in ["DEBUG_MODE", "HARDCODED_SECRET"]:
                fix_complexity["easy"] += 1
            elif vuln_type in ["XSS", "INSECURE_NETWORK"]:
                fix_complexity["medium"] += 1
            else:
                fix_complexity["hard"] += 1

        # 전체 위험 점수 계산
        total_risk_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            if severity == 'CRITICAL':
                total_risk_score += 9
            elif severity == 'HIGH':
                total_risk_score += 7
            elif severity == 'MEDIUM':
                total_risk_score += 4
            else:
                total_risk_score += 2

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_distribution": severity_distribution,
            "type_distribution": type_distribution,
            "file_distribution": file_distribution,
            "risky_files": risky_files,
            "fix_complexity": fix_complexity,
            "total_risk_score": total_risk_score,
            "average_risk_per_vuln": round(total_risk_score / len(vulnerabilities), 2),
            "analysis_timestamp": time.time(),
            "recommendations": {
                "immediate_action_required": severity_distribution.get('CRITICAL', 0) > 0,
                "priority_files": [file for file, count in risky_files[:3]],
                "estimated_total_fix_time": f"{len(vulnerabilities) * 0.5:.1f}-{len(vulnerabilities) * 2:.1f} hours"
            }
        }

    except Exception as e:
        return {"error": f"Vulnerability trend analysis failed: {str(e)}"}


@tool
def generate_security_metrics(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    스캔 결과를 기반으로 보안 메트릭을 생성합니다.

    Args:
        scan_results: 전체 스캔 결과

    Returns:
        보안 메트릭 및 KPI
    """
    try:
        # 기본 메트릭 초기화
        metrics = {
            "vulnerability_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "dependency_vulns": 0,
            "code_vulns": 0,
            "config_vulns": 0
        }

        # Trivy 결과 처리
        if 'trivy_scan' in scan_results and 'filesystem_scan' in scan_results['trivy_scan']:
            trivy_data = scan_results['trivy_scan']['filesystem_scan']
            if 'Results' in trivy_data:
                for result in trivy_data['Results']:
                    if 'Vulnerabilities' in result:
                        for vuln in result['Vulnerabilities']:
                            metrics["vulnerability_count"] += 1
                            metrics["dependency_vulns"] += 1

                            severity = vuln.get('Severity', 'UNKNOWN').upper()
                            if severity == 'CRITICAL':
                                metrics["critical_count"] += 1
                            elif severity == 'HIGH':
                                metrics["high_count"] += 1
                            elif severity == 'MEDIUM':
                                metrics["medium_count"] += 1
                            elif severity == 'LOW':
                                metrics["low_count"] += 1

        # 정적 분석 결과 처리
        if 'security_config_scan' in scan_results and 'security_issues' in scan_results['security_config_scan']:
            for issue in scan_results['security_config_scan']['security_issues']:
                metrics["vulnerability_count"] += 1
                metrics["code_vulns"] += 1

                severity = issue.get('severity', 'UNKNOWN').upper()
                if severity == 'CRITICAL':
                    metrics["critical_count"] += 1
                elif severity == 'HIGH':
                    metrics["high_count"] += 1
                elif severity == 'MEDIUM':
                    metrics["medium_count"] += 1
                elif severity == 'LOW':
                    metrics["low_count"] += 1

        # 보안 점수 계산 (100점 만점)
        total_vulns = metrics["vulnerability_count"]
        if total_vulns == 0:
            security_score = 100
        else:
            # 심각도에 따른 가중치 적용
            weighted_score = (
                metrics["critical_count"] * 25 +
                metrics["high_count"] * 15 +
                metrics["medium_count"] * 8 +
                metrics["low_count"] * 3
            )
            # 최대 100점에서 차감
            security_score = max(0, 100 - weighted_score)

        # 보안 등급 결정
        if security_score >= 90:
            security_grade = "A"
        elif security_score >= 80:
            security_grade = "B"
        elif security_score >= 70:
            security_grade = "C"
        elif security_score >= 60:
            security_grade = "D"
        else:
            security_grade = "F"

        # 개선 제안
        improvement_suggestions = []
        if metrics["critical_count"] > 0:
            improvement_suggestions.append("즉시 Critical 취약점 수정 필요")
        if metrics["dependency_vulns"] > 0:
            improvement_suggestions.append("종속성 패키지 업데이트 권장")
        if metrics["code_vulns"] > 5:
            improvement_suggestions.append("코드 리뷰 및 보안 테스트 강화 필요")

        return {
            "metrics": metrics,
            "security_score": security_score,
            "security_grade": security_grade,
            "vulnerability_density": round(total_vulns / max(1, scan_results.get('files_scanned', 1)), 2),
            "risk_level": "HIGH" if metrics["critical_count"] > 0 else "MEDIUM" if metrics["high_count"] > 0 else "LOW",
            "improvement_suggestions": improvement_suggestions,
            "benchmark": {
                "industry_average_score": 75,
                "best_practice_score": 95,
                "your_position": "above" if security_score > 75 else "below"
            },
            "metrics_timestamp": time.time()
        }

    except Exception as e:
        return {"error": f"Security metrics generation failed: {str(e)}"}


@tool
def generate_compliance_report(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    취약점을 기반으로 컴플라이언스 리포트를 생성합니다.

    Args:
        vulnerabilities: 취약점 목록

    Returns:
        컴플라이언스 체크 결과
    """
    try:
        # 주요 컴플라이언스 프레임워크 체크
        compliance_checks = {
            "OWASP_Top_10": {
                "total_checks": 10,
                "passed": 0,
                "failed": 0,
                "issues": []
            },
            "CWE_Top_25": {
                "total_checks": 25,
                "passed": 0,
                "failed": 0,
                "issues": []
            },
            "PCI_DSS": {
                "total_checks": 12,
                "passed": 0,
                "failed": 0,
                "issues": []
            }
        }

        # OWASP Top 10 매핑
        owasp_mapping = {
            "SQL_INJECTION": "A03:2021 – Injection",
            "XSS": "A03:2021 – Injection",
            "UNSAFE_DESERIALIZATION": "A08:2021 – Software and Data Integrity Failures",
            "HARDCODED_SECRET": "A07:2021 – Identification and Authentication Failures",
            "COMMAND_INJECTION": "A03:2021 – Injection",
            "DEBUG_MODE": "A05:2021 – Security Misconfiguration",
            "INSECURE_NETWORK": "A05:2021 – Security Misconfiguration"
        }

        # 취약점별 컴플라이언스 체크
        owasp_violations = set()
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'UNKNOWN')
            if vuln_type in owasp_mapping:
                owasp_category = owasp_mapping[vuln_type]
                owasp_violations.add(owasp_category)
                compliance_checks["OWASP_Top_10"]["issues"].append({
                    "category": owasp_category,
                    "vulnerability": vuln_type,
                    "file": vuln.get('file', 'unknown'),
                    "severity": vuln.get('severity', 'UNKNOWN')
                })

        # 컴플라이언스 점수 계산
        compliance_checks["OWASP_Top_10"]["failed"] = len(owasp_violations)
        compliance_checks["OWASP_Top_10"]["passed"] = 10 - len(owasp_violations)

        # 전체 컴플라이언스 점수
        owasp_score = (compliance_checks["OWASP_Top_10"]["passed"] / 10) * 100

        return {
            "compliance_checks": compliance_checks,
            "overall_compliance_score": round(owasp_score, 1),
            "owasp_violations": len(owasp_violations),
            "recommendations": [
                f"OWASP Top 10 위반사항 {len(owasp_violations)}개 수정 필요",
                "보안 코딩 가이드라인 적용 권장",
                "정기적인 보안 스캔 프로세스 구축 필요"
            ],
            "certification_readiness": {
                "SOC2": "PARTIAL" if owasp_score > 70 else "NOT_READY",
                "ISO27001": "PARTIAL" if owasp_score > 80 else "NOT_READY",
                "PCI_DSS": "NOT_READY"  # 추가 검사 필요
            },
            "report_timestamp": time.time()
        }

    except Exception as e:
        return {"error": f"Compliance report generation failed: {str(e)}"}