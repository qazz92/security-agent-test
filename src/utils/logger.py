"""
로깅 설정 및 보안 이벤트 추적
"""

import logging
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from enum import Enum
from functools import wraps


class LogLevel(Enum):
    """로그 레벨 정의"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SecurityEventType(Enum):
    """보안 이벤트 타입"""
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    FIX_GENERATED = "fix_generated"
    TOOL_EXECUTION = "tool_execution"
    AGENT_SESSION = "agent_session"
    ERROR_OCCURRED = "error_occurred"
    PERFORMANCE_ALERT = "performance_alert"


class SecurityLogger:
    """보안 이벤트 전용 로거"""

    def __init__(self, log_dir: str = "logs", max_bytes: int = 10*1024*1024, backup_count: int = 5):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # 메인 로거 설정
        self.logger = logging.getLogger("security_agent")
        self.logger.setLevel(logging.INFO)

        # 핸들러 중복 방지
        if not self.logger.handlers:
            self._setup_handlers(max_bytes, backup_count)

        # 보안 이벤트 추적
        self.security_events = []

    def _setup_handlers(self, max_bytes: int, backup_count: int):
        """로그 핸들러 설정"""

        # 포맷터 설정
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        json_formatter = JsonFormatter()

        # 1. 콘솔 핸들러
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(detailed_formatter)

        # 2. 파일 핸들러 (일반 로그)
        file_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "security_agent.log"),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)

        # 3. 에러 전용 핸들러
        error_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "error.log"),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)

        # 4. 보안 이벤트 JSON 핸들러
        security_handler = TimedRotatingFileHandler(
            os.path.join(self.log_dir, "security_events.json"),
            when='midnight',
            interval=1,
            backupCount=30,
            encoding='utf-8'
        )
        security_handler.setLevel(logging.INFO)
        security_handler.setFormatter(json_formatter)

        # 5. 성능 로그 핸들러
        performance_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "performance.log"),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        performance_handler.setLevel(logging.INFO)
        performance_handler.setFormatter(json_formatter)

        # 핸들러 추가
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(error_handler)

        # 별도 로거들
        self.security_logger = logging.getLogger("security_events")
        self.security_logger.addHandler(security_handler)
        self.security_logger.setLevel(logging.INFO)

        self.performance_logger = logging.getLogger("performance")
        self.performance_logger.addHandler(performance_handler)
        self.performance_logger.setLevel(logging.INFO)

    def log_security_event(
        self,
        event_type: SecurityEventType,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "INFO"
    ):
        """보안 이벤트 로그"""

        event_data = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type.value,
            "severity": severity,
            "message": message,
            "details": details or {},
            "session_id": getattr(self, '_session_id', 'unknown')
        }

        # 메모리에 저장
        self.security_events.append(event_data)

        # 파일에 로그
        self.security_logger.info(json.dumps(event_data, ensure_ascii=False))

        # 메인 로거에도 기록
        log_level = getattr(logging, severity.upper(), logging.INFO)
        self.logger.log(log_level, f"[{event_type.value}] {message}")

    def log_vulnerability_detected(
        self,
        vulnerability_type: str,
        severity: str,
        file_path: str,
        line_number: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """취약점 발견 로그"""

        vuln_details = {
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "file_path": file_path,
            "line_number": line_number,
            **(details or {})
        }

        self.log_security_event(
            SecurityEventType.VULNERABILITY_DETECTED,
            f"Vulnerability detected: {vulnerability_type} in {file_path}",
            vuln_details,
            severity
        )

    def log_scan_started(self, project_path: str, scan_type: str):
        """스캔 시작 로그"""
        self.log_security_event(
            SecurityEventType.SCAN_STARTED,
            f"Security scan started: {scan_type}",
            {"project_path": project_path, "scan_type": scan_type}
        )

    def log_scan_completed(
        self,
        project_path: str,
        scan_type: str,
        duration: float,
        vulnerabilities_found: int
    ):
        """스캔 완료 로그"""
        self.log_security_event(
            SecurityEventType.SCAN_COMPLETED,
            f"Security scan completed: {vulnerabilities_found} vulnerabilities found",
            {
                "project_path": project_path,
                "scan_type": scan_type,
                "duration": duration,
                "vulnerabilities_found": vulnerabilities_found
            }
        )

    def log_tool_execution(
        self,
        tool_name: str,
        duration: float,
        success: bool,
        result_size: Optional[int] = None,
        error_message: Optional[str] = None
    ):
        """툴 실행 로그"""

        details = {
            "tool_name": tool_name,
            "duration": duration,
            "success": success,
            "result_size": result_size
        }

        if error_message:
            details["error_message"] = error_message

        severity = "INFO" if success else "ERROR"
        message = f"Tool {tool_name} {'completed' if success else 'failed'} in {duration:.2f}s"

        self.log_security_event(
            SecurityEventType.TOOL_EXECUTION,
            message,
            details,
            severity
        )

    def log_agent_session(
        self,
        agent_name: str,
        session_duration: float,
        tools_used: List[str],
        success: bool,
        vulnerabilities_processed: int = 0
    ):
        """에이전트 세션 로그"""

        self.log_security_event(
            SecurityEventType.AGENT_SESSION,
            f"Agent {agent_name} session {'completed' if success else 'failed'}",
            {
                "agent_name": agent_name,
                "session_duration": session_duration,
                "tools_used": tools_used,
                "success": success,
                "vulnerabilities_processed": vulnerabilities_processed
            },
            "INFO" if success else "ERROR"
        )

    def log_fix_generated(
        self,
        vulnerability_type: str,
        fix_type: str,
        estimated_effort: float,
        file_path: str
    ):
        """수정 방안 생성 로그"""

        self.log_security_event(
            SecurityEventType.FIX_GENERATED,
            f"Fix generated for {vulnerability_type}",
            {
                "vulnerability_type": vulnerability_type,
                "fix_type": fix_type,
                "estimated_effort": estimated_effort,
                "file_path": file_path
            }
        )

    def log_performance_data(self, performance_data: Dict[str, Any]):
        """성능 데이터 로그"""
        self.performance_logger.info(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "type": "performance_snapshot",
            **performance_data
        }, ensure_ascii=False))

    def log_performance_alert(self, alert_data: Dict[str, Any]):
        """성능 알림 로그"""
        self.log_security_event(
            SecurityEventType.PERFORMANCE_ALERT,
            f"Performance alert: {alert_data.get('message', 'Unknown')}",
            alert_data,
            alert_data.get('severity', 'WARNING')
        )

    def set_session_id(self, session_id: str):
        """세션 ID 설정"""
        self._session_id = session_id

    def get_security_events(
        self,
        event_type: Optional[SecurityEventType] = None,
        since: Optional[datetime] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """보안 이벤트 조회"""

        events = self.security_events.copy()

        # 이벤트 타입 필터
        if event_type:
            events = [e for e in events if e["event_type"] == event_type.value]

        # 시간 필터
        if since:
            since_iso = since.isoformat()
            events = [e for e in events if e["timestamp"] >= since_iso]

        # 최신 순 정렬
        events.sort(key=lambda x: x["timestamp"], reverse=True)

        # 제한
        if limit:
            events = events[:limit]

        return events

    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """취약점 요약 통계"""

        vuln_events = [
            e for e in self.security_events
            if e["event_type"] == SecurityEventType.VULNERABILITY_DETECTED.value
        ]

        if not vuln_events:
            return {"total": 0, "by_severity": {}, "by_type": {}}

        # 심각도별 분류
        by_severity = {}
        by_type = {}

        for event in vuln_events:
            details = event.get("details", {})
            severity = details.get("severity", "UNKNOWN")
            vuln_type = details.get("vulnerability_type", "UNKNOWN")

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        return {
            "total": len(vuln_events),
            "by_severity": by_severity,
            "by_type": by_type,
            "latest_detection": vuln_events[-1]["timestamp"] if vuln_events else None
        }

    def export_logs(self, output_file: str, format_type: str = "json") -> str:
        """로그 내보내기"""

        try:
            if format_type.lower() == "json":
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        "export_timestamp": datetime.now().isoformat(),
                        "security_events": self.security_events,
                        "vulnerability_summary": self.get_vulnerability_summary()
                    }, f, indent=2, ensure_ascii=False)

            return f"Logs exported to {output_file}"

        except Exception as e:
            self.logger.error(f"Failed to export logs: {str(e)}")
            return f"Export failed: {str(e)}"

    def cleanup_old_events(self, days: int = 30):
        """오래된 이벤트 정리"""

        cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
        cutoff_iso = datetime.fromtimestamp(cutoff_time).isoformat()

        original_count = len(self.security_events)
        self.security_events = [
            e for e in self.security_events
            if e["timestamp"] >= cutoff_iso
        ]

        cleaned_count = original_count - len(self.security_events)
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} old security events")

        return cleaned_count


class JsonFormatter(logging.Formatter):
    """JSON 형식 로그 포맷터"""

    def format(self, record):
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage()
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, ensure_ascii=False)


class ContextManager:
    """로깅 컨텍스트 관리자"""

    def __init__(self, logger: SecurityLogger, context: Dict[str, Any]):
        self.logger = logger
        self.context = context
        self.start_time = time.time()

    def __enter__(self):
        # 컨텍스트 시작 로그
        self.logger.logger.info(f"Starting context: {self.context}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 컨텍스트 종료 로그
        duration = time.time() - self.start_time
        if exc_type:
            self.logger.logger.error(
                f"Context failed after {duration:.2f}s: {self.context}, Error: {exc_val}"
            )
        else:
            self.logger.logger.info(
                f"Context completed in {duration:.2f}s: {self.context}"
            )


# 전역 로거 인스턴스
_security_logger = None

def get_security_logger() -> SecurityLogger:
    """전역 보안 로거 인스턴스 반환"""
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityLogger()
    return _security_logger

def log_context(context: Dict[str, Any]):
    """로깅 컨텍스트 데코레이터"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_security_logger()
            with ContextManager(logger, context):
                return func(*args, **kwargs)
        return wrapper
    return decorator