"""
Dual Model Selector for Cost Optimization
추론 모델(Thinking) vs 지시 모델(Instruct) 자동 선택
"""

import os
import logging
from enum import Enum
from typing import Dict, Any, Optional
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)


class TaskComplexity(Enum):
    """작업 복잡도"""

    # 복잡한 추론 필요 (Thinking Model)
    CRITICAL_ANALYSIS = "critical_analysis"      # 취약점 심각도 평가
    RISK_ASSESSMENT = "risk_assessment"          # 비즈니스 리스크 평가
    VULNERABILITY_TRIAGE = "vulnerability_triage" # 취약점 우선순위 결정
    SECURITY_DESIGN = "security_design"          # 보안 설계 및 아키텍처
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"  # 근본 원인 분석

    # 단순 실행 (Instruct Model)
    TOOL_CALLING = "tool_calling"                # Tool 호출 결정
    DATA_FORMATTING = "data_formatting"          # 데이터 포맷 변환
    TEMPLATE_GENERATION = "template_generation"  # 템플릿 생성
    CODE_FORMATTING = "code_formatting"          # 코드 포맷팅
    SIMPLE_EXTRACTION = "simple_extraction"      # 단순 데이터 추출


class ModelConfig:
    """모델 설정"""

    # Thinking Model (복잡한 추론)
    THINKING = {
        "model": os.getenv('MODEL_THINKING', 'qwen/qwen3-next-80b-a3b-thinking'),
        "temperature": 0.2,  # 더 보수적
        "max_tokens": 16384,  # 긴 추론 가능 (배치 처리 고려)
        "description": "Complex reasoning and analysis"
    }

    # Instruct Model (단순 실행)
    INSTRUCT = {
        "model": os.getenv('MODEL_INSTRUCT', 'qwen/qwen3-next-80b-a3b-instruct'),
        "temperature": 0.1,  # 결정적
        "max_tokens": 8192,  # 배치 처리를 위한 충분한 크기 (Qwen3-Next: 256K context window)
        "description": "Tool calling and simple tasks"
    }


class ModelSelector:
    """
    작업 유형에 따라 최적의 모델 선택

    사용 예:
        selector = ModelSelector()
        llm = selector.get_llm(TaskComplexity.CRITICAL_ANALYSIS)
    """

    # 작업별 모델 매핑
    TASK_MODEL_MAPPING = {
        # Thinking Model 사용 (복잡한 추론)
        # OpenRouter reasoning parameter 지원 (2025-09-30 확인)
        # LiteLLM 1.74.9+ supports reasoning_content extraction
        TaskComplexity.CRITICAL_ANALYSIS: "thinking",
        TaskComplexity.RISK_ASSESSMENT: "thinking",
        TaskComplexity.VULNERABILITY_TRIAGE: "thinking",
        TaskComplexity.SECURITY_DESIGN: "thinking",
        TaskComplexity.ROOT_CAUSE_ANALYSIS: "thinking",

        # Instruct Model 사용 (단순 실행 작업)
        TaskComplexity.TOOL_CALLING: "instruct",
        TaskComplexity.DATA_FORMATTING: "instruct",
        TaskComplexity.TEMPLATE_GENERATION: "instruct",
        TaskComplexity.CODE_FORMATTING: "instruct",
        TaskComplexity.SIMPLE_EXTRACTION: "instruct",
    }

    def __init__(self, api_key: str = None, api_base: str = None):
        self.api_key = api_key or os.getenv('OPENROUTER_API_KEY')
        self.api_base = api_base or os.getenv('OPENAI_API_BASE', 'https://openrouter.ai/api/v1')

        # 비용 추적
        self.usage_stats = {
            "thinking": {"calls": 0, "tokens": 0},
            "instruct": {"calls": 0, "tokens": 0}
        }

    def get_llm(
        self,
        task_complexity: TaskComplexity,
        callbacks: list = None,
        override_params: Dict[str, Any] = None
    ) -> ChatOpenAI:
        """
        작업 복잡도에 따라 적절한 LLM 반환

        Args:
            task_complexity: 작업 복잡도 (Enum)
            callbacks: LangChain callbacks (Langfuse 등)
            override_params: 모델 파라미터 오버라이드

        Returns:
            설정된 ChatOpenAI 인스턴스
        """

        # 모델 타입 결정
        model_type = self.TASK_MODEL_MAPPING.get(task_complexity, "instruct")
        config = ModelConfig.THINKING if model_type == "thinking" else ModelConfig.INSTRUCT

        # 파라미터 설정
        # CrewAI/LiteLLM requires 'openrouter/' prefix, but Langfuse doesn't accept it
        # Use prefix for API calls, but store original name for Langfuse metadata
        base_model_name = config['model']
        model_name_with_prefix = f"openrouter/{base_model_name}"

        params = {
            "model": model_name_with_prefix,  # CrewAI/LiteLLM needs prefix
            "temperature": config["temperature"],
            "max_tokens": config["max_tokens"],
            "openai_api_key": self.api_key,
            "openai_api_base": self.api_base,
            "callbacks": callbacks or [],
            "model_kwargs": {
                "extra_headers": {
                    "HTTP-Referer": "https://github.com/security-agent-portfolio",
                    "X-Title": f"SecurityAgent-{task_complexity.value}",
                },
                # Pass original model name for Langfuse (without prefix)
                "metadata": {
                    "model_name": base_model_name,  # Langfuse will use this
                }
            }
        }

        # OpenRouter Thinking 모델 설정: reasoning parameter 추가
        if model_type == "thinking":
            params["model_kwargs"]["extra_body"] = {
                "reasoning": {
                    "max_tokens": 2000,  # 추론 과정에 충분한 토큰 제공
                    "enabled": True      # 명시적으로 reasoning 활성화
                }
            }
            logger.info(f"   🧠 Reasoning enabled: max_tokens=2000")

        # 오버라이드 적용
        if override_params:
            params.update(override_params)

        # 통계 업데이트
        self.usage_stats[model_type]["calls"] += 1

        # 로깅
        logger.info(
            f"🤖 Selected {model_type.upper()} model for {task_complexity.value}: "
            f"{config['model']} (temp={config['temperature']})"
        )
        logger.info(f"   📞 Callbacks: {len(callbacks or [])} configured")

        llm = ChatOpenAI(**params)

        # Verify callbacks are set
        if hasattr(llm, 'callbacks') and llm.callbacks:
            logger.info(f"   ✅ LLM callbacks verified: {len(llm.callbacks)} callbacks")
        elif callbacks:
            logger.warning(f"   ⚠️ Callbacks provided but not set on LLM!")

        return llm

    def get_model_for_agent(self, agent_name: str, callbacks: list = None) -> ChatOpenAI:
        """
        Agent 이름에 따라 적절한 모델 반환 (편의 함수)

        Args:
            agent_name: 'security_analyst', 'triage_specialist', 'remediation_engineer'
            callbacks: LangChain callbacks

        Returns:
            설정된 ChatOpenAI 인스턴스
        """

        agent_task_mapping = {
            "security_analyst": TaskComplexity.CRITICAL_ANALYSIS,  # Thinking
            "triage_specialist": TaskComplexity.VULNERABILITY_TRIAGE,  # Thinking
            "remediation_engineer": TaskComplexity.TOOL_CALLING,  # Instruct
        }

        task = agent_task_mapping.get(agent_name, TaskComplexity.TOOL_CALLING)
        return self.get_llm(task, callbacks)

    def get_usage_report(self) -> Dict[str, Any]:
        """비용 최적화 보고서"""

        thinking_calls = self.usage_stats["thinking"]["calls"]
        instruct_calls = self.usage_stats["instruct"]["calls"]
        total_calls = thinking_calls + instruct_calls

        if total_calls == 0:
            return {"message": "No LLM calls yet"}

        # 예상 비용 (가상의 가격 - OpenRouter 실제 가격으로 대체 필요)
        THINKING_COST_PER_CALL = 0.02  # $0.02 per call (예시)
        INSTRUCT_COST_PER_CALL = 0.005  # $0.005 per call (예시)

        thinking_cost = thinking_calls * THINKING_COST_PER_CALL
        instruct_cost = instruct_calls * INSTRUCT_COST_PER_CALL
        total_cost = thinking_cost + instruct_cost

        # 만약 전부 Thinking 모델을 사용했다면?
        all_thinking_cost = total_calls * THINKING_COST_PER_CALL
        savings = all_thinking_cost - total_cost
        savings_pct = (savings / all_thinking_cost * 100) if all_thinking_cost > 0 else 0

        return {
            "total_calls": total_calls,
            "thinking_calls": thinking_calls,
            "instruct_calls": instruct_calls,
            "thinking_percentage": round(thinking_calls / total_calls * 100, 1),
            "instruct_percentage": round(instruct_calls / total_calls * 100, 1),
            "estimated_cost": {
                "thinking": round(thinking_cost, 4),
                "instruct": round(instruct_cost, 4),
                "total": round(total_cost, 4),
                "currency": "USD"
            },
            "cost_savings": {
                "amount": round(savings, 4),
                "percentage": round(savings_pct, 1),
                "vs": "all-thinking-model"
            }
        }

    def print_usage_report(self):
        """비용 보고서 출력"""
        report = self.get_usage_report()

        if "message" in report:
            logger.info(report["message"])
            return

        logger.info("="*70)
        logger.info("💰 MODEL USAGE & COST OPTIMIZATION REPORT")
        logger.info("="*70)
        logger.info(f"Total LLM Calls: {report['total_calls']}")
        logger.info(f"  🧠 Thinking Model: {report['thinking_calls']} ({report['thinking_percentage']}%)")
        logger.info(f"  ⚡ Instruct Model: {report['instruct_calls']} ({report['instruct_percentage']}%)")
        logger.info("")
        logger.info(f"Estimated Cost:")
        logger.info(f"  Thinking: ${report['estimated_cost']['thinking']}")
        logger.info(f"  Instruct: ${report['estimated_cost']['instruct']}")
        logger.info(f"  Total: ${report['estimated_cost']['total']}")
        logger.info("")
        logger.info(f"💵 Cost Savings vs All-Thinking:")
        logger.info(f"  Amount: ${report['cost_savings']['amount']}")
        logger.info(f"  Percentage: {report['cost_savings']['percentage']}%")
        logger.info("="*70)


# 싱글톤 인스턴스
_model_selector = None


def get_model_selector() -> ModelSelector:
    """전역 ModelSelector 인스턴스 반환"""
    global _model_selector
    if _model_selector is None:
        _model_selector = ModelSelector()
    return _model_selector