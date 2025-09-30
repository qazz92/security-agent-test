"""
성능 측정 및 모니터링 유틸리티
Tool 호출 시간, 토큰 사용량, 성공률 등을 추적
"""

import time
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict, deque
import asyncio
import threading


class PerformanceTracker:
    """성능 추적 및 분석 클래스"""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.lock = threading.Lock()
        self.reset_metrics()

    def reset_metrics(self):
        """메트릭 초기화"""
        with self.lock:
            self.tool_calls = deque(maxlen=self.max_history)
            self.agent_sessions = deque(maxlen=self.max_history)
            self.token_usage = {
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_cost": 0.0
            }
            self.error_log = deque(maxlen=self.max_history)
            self.session_start = time.time()

    def track_tool_call(self, tool_name: str):
        """툴 호출 추적 데코레이터"""
        def decorator(func: Callable):
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self._execute_with_tracking(func, tool_name, False, *args, **kwargs)

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                return await self._execute_with_tracking(func, tool_name, True, *args, **kwargs)

            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            else:
                return sync_wrapper

        return decorator

    def _execute_with_tracking(self, func: Callable, tool_name: str, is_async: bool, *args, **kwargs):
        """실제 실행 및 추적 로직"""
        start_time = time.time()
        success = False
        error_message = None
        result = None

        try:
            if is_async:
                result = func(*args, **kwargs)  # 이미 awaited된 상태로 전달됨
            else:
                result = func(*args, **kwargs)
            success = True
            return result

        except Exception as e:
            error_message = str(e)
            logging.error(f"Tool {tool_name} failed: {e}")
            raise

        finally:
            end_time = time.time()
            duration = end_time - start_time

            # 결과 크기 계산
            result_size = self._calculate_result_size(result)

            call_data = {
                "tool_name": tool_name,
                "start_time": start_time,
                "end_time": end_time,
                "duration": duration,
                "success": success,
                "error_message": error_message,
                "result_size": result_size,
                "timestamp": datetime.now().isoformat(),
                "args_count": len(args),
                "kwargs_count": len(kwargs)
            }

            with self.lock:
                self.tool_calls.append(call_data)

                if not success:
                    self.error_log.append({
                        "tool_name": tool_name,
                        "error": error_message,
                        "timestamp": datetime.now().isoformat(),
                        "duration": duration
                    })

    def _calculate_result_size(self, result: Any) -> int:
        """결과 데이터 크기 계산 (바이트)"""
        try:
            if result is None:
                return 0
            return len(json.dumps(result, default=str).encode('utf-8'))
        except:
            return 0

    def track_agent_session(self, agent_name: str, session_data: Dict[str, Any]):
        """에이전트 세션 추적"""
        with self.lock:
            session_info = {
                "agent_name": agent_name,
                "timestamp": datetime.now().isoformat(),
                "duration": session_data.get("duration", 0),
                "tools_used": session_data.get("tools_used", []),
                "success": session_data.get("success", True),
                "token_usage": session_data.get("token_usage", {}),
                "vulnerabilities_found": session_data.get("vulnerabilities_found", 0),
                "fixes_generated": session_data.get("fixes_generated", 0)
            }
            self.agent_sessions.append(session_info)

    def update_token_usage(self, prompt_tokens: int, completion_tokens: int, cost: float = 0.0):
        """토큰 사용량 업데이트"""
        with self.lock:
            self.token_usage["prompt_tokens"] += prompt_tokens
            self.token_usage["completion_tokens"] += completion_tokens
            self.token_usage["total_tokens"] += prompt_tokens + completion_tokens
            self.token_usage["total_cost"] += cost

    def get_performance_report(self) -> Dict[str, Any]:
        """종합 성능 리포트 생성"""
        with self.lock:
            total_calls = len(self.tool_calls)
            if total_calls == 0:
                return {"error": "No performance data available"}

            # 기본 통계
            successful_calls = sum(1 for call in self.tool_calls if call["success"])
            total_duration = sum(call["duration"] for call in self.tool_calls)
            avg_duration = total_duration / total_calls

            # 툴별 통계
            tool_stats = defaultdict(lambda: {
                "calls": 0,
                "total_duration": 0,
                "failures": 0,
                "avg_duration": 0,
                "total_result_size": 0
            })

            for call in self.tool_calls:
                tool_name = call["tool_name"]
                tool_stats[tool_name]["calls"] += 1
                tool_stats[tool_name]["total_duration"] += call["duration"]
                tool_stats[tool_name]["total_result_size"] += call.get("result_size", 0)
                if not call["success"]:
                    tool_stats[tool_name]["failures"] += 1

            # 평균 계산
            for tool_name, stats in tool_stats.items():
                if stats["calls"] > 0:
                    stats["avg_duration"] = stats["total_duration"] / stats["calls"]
                    stats["success_rate"] = (stats["calls"] - stats["failures"]) / stats["calls"] * 100

            # 시간대별 성능
            hourly_performance = self._calculate_hourly_performance()

            # 최근 트렌드
            recent_performance = self._calculate_recent_trends()

            return {
                "summary": {
                    "total_tool_calls": total_calls,
                    "successful_calls": successful_calls,
                    "success_rate": (successful_calls / total_calls * 100) if total_calls > 0 else 0,
                    "total_duration": total_duration,
                    "average_duration": avg_duration,
                    "total_errors": len(self.error_log),
                    "session_uptime": time.time() - self.session_start
                },
                "tool_statistics": dict(tool_stats),
                "token_usage": self.token_usage.copy(),
                "hourly_performance": hourly_performance,
                "recent_trends": recent_performance,
                "top_slow_tools": self._get_slowest_tools(),
                "error_analysis": self._analyze_errors(),
                "recommendations": self._generate_performance_recommendations(),
                "report_timestamp": datetime.now().isoformat()
            }

    def _calculate_hourly_performance(self) -> Dict[str, Any]:
        """시간대별 성능 계산"""
        hourly_data = defaultdict(lambda: {"calls": 0, "duration": 0, "errors": 0})

        for call in self.tool_calls:
            hour = datetime.fromtimestamp(call["start_time"]).strftime("%Y-%m-%d %H:00")
            hourly_data[hour]["calls"] += 1
            hourly_data[hour]["duration"] += call["duration"]
            if not call["success"]:
                hourly_data[hour]["errors"] += 1

        # 평균 계산
        for hour_data in hourly_data.values():
            if hour_data["calls"] > 0:
                hour_data["avg_duration"] = hour_data["duration"] / hour_data["calls"]
                hour_data["error_rate"] = hour_data["errors"] / hour_data["calls"] * 100

        return dict(hourly_data)

    def _calculate_recent_trends(self, window_minutes: int = 10) -> Dict[str, Any]:
        """최근 트렌드 계산"""
        cutoff_time = time.time() - (window_minutes * 60)
        recent_calls = [call for call in self.tool_calls if call["start_time"] > cutoff_time]

        if not recent_calls:
            return {"no_recent_data": True}

        return {
            "window_minutes": window_minutes,
            "recent_calls": len(recent_calls),
            "recent_success_rate": sum(1 for call in recent_calls if call["success"]) / len(recent_calls) * 100,
            "recent_avg_duration": sum(call["duration"] for call in recent_calls) / len(recent_calls),
            "recent_errors": sum(1 for call in recent_calls if not call["success"]),
            "trending_tools": self._get_trending_tools(recent_calls)
        }

    def _get_trending_tools(self, recent_calls: List[Dict]) -> List[Dict[str, Any]]:
        """최근 많이 사용된 툴들"""
        tool_usage = defaultdict(int)
        for call in recent_calls:
            tool_usage[call["tool_name"]] += 1

        return [
            {"tool_name": tool, "usage_count": count}
            for tool, count in sorted(tool_usage.items(), key=lambda x: x[1], reverse=True)
        ][:5]

    def _get_slowest_tools(self) -> List[Dict[str, Any]]:
        """가장 느린 툴들"""
        tool_avg_duration = {}
        tool_calls_count = defaultdict(int)

        for call in self.tool_calls:
            tool_name = call["tool_name"]
            if tool_name not in tool_avg_duration:
                tool_avg_duration[tool_name] = 0
            tool_avg_duration[tool_name] += call["duration"]
            tool_calls_count[tool_name] += 1

        # 평균 계산
        for tool_name in tool_avg_duration:
            tool_avg_duration[tool_name] /= tool_calls_count[tool_name]

        # 상위 5개 반환
        slowest = sorted(tool_avg_duration.items(), key=lambda x: x[1], reverse=True)[:5]
        return [
            {"tool_name": tool, "avg_duration": duration, "call_count": tool_calls_count[tool]}
            for tool, duration in slowest
        ]

    def _analyze_errors(self) -> Dict[str, Any]:
        """에러 분석"""
        if not self.error_log:
            return {"no_errors": True}

        error_by_tool = defaultdict(int)
        error_types = defaultdict(int)

        for error in self.error_log:
            error_by_tool[error["tool_name"]] += 1
            # 에러 타입 추출 (간단하게 첫 번째 단어)
            error_type = error["error"].split(':')[0] if ':' in error["error"] else "Unknown"
            error_types[error_type] += 1

        return {
            "total_errors": len(self.error_log),
            "errors_by_tool": dict(error_by_tool),
            "error_types": dict(error_types),
            "error_rate_by_tool": {
                tool: (errors / sum(1 for call in self.tool_calls if call["tool_name"] == tool) * 100)
                for tool, errors in error_by_tool.items()
            }
        }

    def _generate_performance_recommendations(self) -> List[str]:
        """성능 개선 권장사항"""
        recommendations = []

        # 성공률 기반 권장사항
        total_calls = len(self.tool_calls)
        if total_calls > 0:
            success_rate = sum(1 for call in self.tool_calls if call["success"]) / total_calls * 100

            if success_rate < 90:
                recommendations.append(f"전체 성공률이 {success_rate:.1f}%로 낮습니다. 에러 처리 개선이 필요합니다.")

        # 응답 시간 기반 권장사항
        if self.tool_calls:
            avg_duration = sum(call["duration"] for call in self.tool_calls) / len(self.tool_calls)
            if avg_duration > 5.0:
                recommendations.append(f"평균 응답시간이 {avg_duration:.1f}초로 깁니다. 성능 최적화를 고려해보세요.")

        # 에러 패턴 기반 권장사항
        if len(self.error_log) > total_calls * 0.1:
            recommendations.append("에러 발생률이 높습니다. 로그를 검토하고 안정성을 개선하세요.")

        # 토큰 사용량 기반 권장사항
        if self.token_usage["total_tokens"] > 50000:
            recommendations.append("토큰 사용량이 많습니다. 프롬프트 최적화를 고려해보세요.")

        if not recommendations:
            recommendations.append("성능이 양호합니다. 현재 상태를 유지하세요.")

        return recommendations

    def export_metrics(self, filename: Optional[str] = None) -> str:
        """메트릭을 JSON 파일로 내보내기"""
        if filename is None:
            filename = f"performance_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        try:
            report = self.get_performance_report()
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)

            return f"Performance metrics exported to {filename}"

        except Exception as e:
            return f"Failed to export metrics: {str(e)}"

    def get_real_time_stats(self) -> Dict[str, Any]:
        """실시간 통계 (최근 1분)"""
        one_minute_ago = time.time() - 60
        recent_calls = [call for call in self.tool_calls if call["start_time"] > one_minute_ago]

        if not recent_calls:
            return {
                "active_calls": 0,
                "calls_per_minute": 0,
                "avg_response_time": 0,
                "current_success_rate": 100
            }

        return {
            "active_calls": len(recent_calls),
            "calls_per_minute": len(recent_calls),
            "avg_response_time": sum(call["duration"] for call in recent_calls) / len(recent_calls),
            "current_success_rate": sum(1 for call in recent_calls if call["success"]) / len(recent_calls) * 100,
            "most_used_tool": max(set(call["tool_name"] for call in recent_calls),
                                key=lambda x: sum(1 for call in recent_calls if call["tool_name"] == x))
        }


class AlertManager:
    """성능 알림 관리자"""

    def __init__(self, performance_tracker: PerformanceTracker):
        self.tracker = performance_tracker
        self.thresholds = {
            "max_response_time": 10.0,  # 초
            "min_success_rate": 85.0,   # %
            "max_error_rate": 15.0,     # %
            "max_tokens_per_hour": 10000
        }
        self.alerts_sent = set()

    def check_alerts(self) -> List[Dict[str, Any]]:
        """알림 조건 체크"""
        alerts = []
        current_time = datetime.now()

        # 최근 성능 데이터 가져오기
        real_time_stats = self.tracker.get_real_time_stats()

        # 응답시간 알림
        if real_time_stats["avg_response_time"] > self.thresholds["max_response_time"]:
            alert_key = f"slow_response_{current_time.strftime('%H')}"
            if alert_key not in self.alerts_sent:
                alerts.append({
                    "type": "PERFORMANCE",
                    "severity": "WARNING",
                    "message": f"Average response time is {real_time_stats['avg_response_time']:.1f}s",
                    "threshold": self.thresholds["max_response_time"],
                    "timestamp": current_time.isoformat()
                })
                self.alerts_sent.add(alert_key)

        # 성공률 알림
        if real_time_stats["current_success_rate"] < self.thresholds["min_success_rate"]:
            alert_key = f"low_success_{current_time.strftime('%H')}"
            if alert_key not in self.alerts_sent:
                alerts.append({
                    "type": "RELIABILITY",
                    "severity": "CRITICAL",
                    "message": f"Success rate dropped to {real_time_stats['current_success_rate']:.1f}%",
                    "threshold": self.thresholds["min_success_rate"],
                    "timestamp": current_time.isoformat()
                })
                self.alerts_sent.add(alert_key)

        return alerts


# 전역 성능 추적기 인스턴스
_performance_tracker = None
_alert_manager = None

def get_performance_tracker() -> PerformanceTracker:
    """전역 성능 추적기 인스턴스 반환"""
    global _performance_tracker
    if _performance_tracker is None:
        _performance_tracker = PerformanceTracker()
    return _performance_tracker

def get_alert_manager() -> AlertManager:
    """전역 알림 관리자 인스턴스 반환"""
    global _alert_manager, _performance_tracker
    if _alert_manager is None:
        if _performance_tracker is None:
            _performance_tracker = PerformanceTracker()
        _alert_manager = AlertManager(_performance_tracker)
    return _alert_manager