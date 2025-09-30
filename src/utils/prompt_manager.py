"""
프롬프트 관리 유틸리티
MD 파일 기반 프롬프트 로딩 및 Jinja2 템플릿 렌더링 지원
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from jinja2 import Template, TemplateSyntaxError, UndefinedError

logger = logging.getLogger(__name__)


class PromptLoadError(Exception):
    """프롬프트 로딩 실패 시 발생하는 예외"""
    pass


class PromptManager:
    """
    프롬프트 파일 관리자

    기능:
    - MD 파일에서 프롬프트 로드
    - YAML frontmatter 파싱 (버전, 메타데이터)
    - Jinja2 템플릿 변수 치환
    - 누락된 변수 검증
    - 프롬프트 캐싱 (핫 리로드 지원)
    """

    def __init__(self, prompts_base_dir: Optional[str] = None):
        """
        Args:
            prompts_base_dir: 프롬프트 디렉토리 경로 (기본값: src/prompts)
        """
        if prompts_base_dir is None:
            # 현재 파일 기준으로 prompts 디렉토리 찾기
            current_file = Path(__file__).resolve()
            prompts_base_dir = current_file.parent.parent / "prompts"

        self.prompts_base_dir = Path(prompts_base_dir)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._enable_cache = True

        if not self.prompts_base_dir.exists():
            logger.warning(f"Prompts directory not found: {self.prompts_base_dir}")

    def load_prompt(
        self,
        agent_name: str,
        prompt_type: str,
        variables: Optional[Dict[str, Any]] = None,
        use_cache: bool = True
    ) -> str:
        """
        프롬프트 로드 및 렌더링

        Args:
            agent_name: 에이전트 이름 (예: 'security_agent', 'remediation_agent')
            prompt_type: 프롬프트 타입 (예: 'system', 'user')
            variables: Jinja2 템플릿 변수 딕셔너리
            use_cache: 캐시 사용 여부

        Returns:
            렌더링된 프롬프트 문자열

        Raises:
            PromptLoadError: 프롬프트 로드 실패 시
        """
        cache_key = f"{agent_name}/{prompt_type}"

        # 캐시 확인
        if use_cache and self._enable_cache and cache_key in self._cache:
            prompt_data = self._cache[cache_key]
        else:
            # 파일에서 로드
            prompt_path = self.prompts_base_dir / agent_name / f"{prompt_type}.md"

            if not prompt_path.exists():
                raise PromptLoadError(
                    f"Prompt file not found: {prompt_path}\n"
                    f"Expected location: {self.prompts_base_dir}/{agent_name}/{prompt_type}.md"
                )

            try:
                with open(prompt_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # frontmatter와 본문 분리
                metadata, body = self._parse_frontmatter(content)

                prompt_data = {
                    'body': body,
                    'metadata': metadata,
                    'path': str(prompt_path)
                }

                # 캐시 저장
                if self._enable_cache:
                    self._cache[cache_key] = prompt_data

            except Exception as e:
                raise PromptLoadError(f"Failed to read prompt file {prompt_path}: {e}")

        # 변수 치환 (Jinja2)
        if variables:
            try:
                rendered = self._render_template(prompt_data['body'], variables, prompt_data['metadata'])
                return rendered
            except Exception as e:
                logger.error(f"Template rendering failed for {cache_key}: {e}")
                raise PromptLoadError(f"Template rendering failed: {e}")

        return prompt_data['body']

    def _parse_frontmatter(self, content: str) -> tuple[Dict[str, Any], str]:
        """
        YAML frontmatter 파싱

        Args:
            content: MD 파일 전체 내용

        Returns:
            (metadata, body) 튜플
        """
        # frontmatter 패턴: ---\n...\n---
        pattern = r'^---\s*\n(.*?)\n---\s*\n(.*)$'
        match = re.match(pattern, content, re.DOTALL)

        if not match:
            # frontmatter 없으면 전체를 본문으로
            return {}, content.strip()

        frontmatter_raw = match.group(1)
        body = match.group(2).strip()

        # 간단한 YAML 파싱 (key: value 형식만)
        metadata = {}
        for line in frontmatter_raw.split('\n'):
            line = line.strip()
            if ':' in line and not line.startswith('#'):
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                # 리스트 처리 (간단한 버전)
                if key == 'variables' and value.startswith('['):
                    continue  # 변수 목록은 다음 줄들에서 처리
                elif line.startswith('- '):
                    # 리스트 아이템
                    if 'variables' not in metadata:
                        metadata['variables'] = []
                    metadata['variables'].append(line[2:].strip())
                else:
                    metadata[key] = value

        return metadata, body

    def _render_template(
        self,
        template_str: str,
        variables: Dict[str, Any],
        metadata: Dict[str, Any]
    ) -> str:
        """
        Jinja2 템플릿 렌더링

        Args:
            template_str: 템플릿 문자열
            variables: 치환할 변수들
            metadata: 프롬프트 메타데이터 (검증용)

        Returns:
            렌더링된 문자열
        """
        try:
            template = Template(template_str)

            # 필수 변수 검증 (메타데이터에 정의된 경우)
            if 'variables' in metadata:
                expected_vars = metadata['variables']
                if isinstance(expected_vars, list):
                    missing_vars = [var for var in expected_vars if var not in variables]
                    if missing_vars:
                        logger.warning(f"Missing template variables: {missing_vars}")

            rendered = template.render(**variables)
            return rendered

        except TemplateSyntaxError as e:
            raise PromptLoadError(f"Template syntax error: {e}")
        except UndefinedError as e:
            raise PromptLoadError(f"Undefined variable in template: {e}")

    def get_prompt_metadata(self, agent_name: str, prompt_type: str) -> Dict[str, Any]:
        """
        프롬프트 메타데이터만 조회

        Args:
            agent_name: 에이전트 이름
            prompt_type: 프롬프트 타입

        Returns:
            메타데이터 딕셔너리
        """
        cache_key = f"{agent_name}/{prompt_type}"

        if cache_key in self._cache:
            return self._cache[cache_key]['metadata']

        # 캐시에 없으면 로드
        self.load_prompt(agent_name, prompt_type, use_cache=True)
        return self._cache.get(cache_key, {}).get('metadata', {})

    def list_prompts(self, agent_name: Optional[str] = None) -> List[Dict[str, str]]:
        """
        사용 가능한 프롬프트 목록 조회

        Args:
            agent_name: 특정 에이전트만 조회 (None이면 전체)

        Returns:
            프롬프트 정보 리스트
        """
        prompts = []

        if agent_name:
            agent_dirs = [self.prompts_base_dir / agent_name]
        else:
            agent_dirs = [d for d in self.prompts_base_dir.iterdir() if d.is_dir()]

        for agent_dir in agent_dirs:
            if not agent_dir.exists():
                continue

            for prompt_file in agent_dir.glob("*.md"):
                prompts.append({
                    'agent': agent_dir.name,
                    'type': prompt_file.stem,
                    'path': str(prompt_file),
                    'size': prompt_file.stat().st_size
                })

        return prompts

    def clear_cache(self):
        """캐시 초기화 (핫 리로드 시 사용)"""
        self._cache.clear()
        logger.info("Prompt cache cleared")

    def disable_cache(self):
        """캐시 비활성화 (개발/디버깅용)"""
        self._enable_cache = False
        self.clear_cache()
        logger.info("Prompt cache disabled")

    def enable_cache(self):
        """캐시 활성화"""
        self._enable_cache = True
        logger.info("Prompt cache enabled")


# 싱글톤 인스턴스
_default_manager: Optional[PromptManager] = None


def get_prompt_manager() -> PromptManager:
    """기본 PromptManager 인스턴스 반환 (싱글톤)"""
    global _default_manager
    if _default_manager is None:
        _default_manager = PromptManager()
    return _default_manager


def load_prompt(
    agent_name: str,
    prompt_type: str,
    variables: Optional[Dict[str, Any]] = None
) -> str:
    """
    편의 함수: 프롬프트 로드

    Args:
        agent_name: 에이전트 이름
        prompt_type: 프롬프트 타입
        variables: 템플릿 변수

    Returns:
        렌더링된 프롬프트
    """
    manager = get_prompt_manager()
    return manager.load_prompt(agent_name, prompt_type, variables)