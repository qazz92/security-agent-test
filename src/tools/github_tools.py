"""
GitHub 연동 툴
실제 GitHub Repository에 PR, Issue 생성

인증 방법:
1. GitHub CLI (gh) - 자동 인증 (권장)
2. GitHub PAT - 환경 변수로 제공
"""

import os
import json
import subprocess
import requests
from typing import Dict, Any, Optional, List
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field


class CreateGitHubPRInput(BaseModel):
    """Input schema for create_github_pr tool"""
    repo_url: str = Field(
        description="GitHub 저장소 URL (예: https://github.com/qazz92/security-agent-test)"
    )
    branch_name: str = Field(
        default="security-fixes",
        description="PR을 위한 새 브랜치 이름"
    )
    pr_title: str = Field(
        description="PR 제목"
    )
    pr_body: str = Field(
        description="PR 본문 (마크다운)"
    )
    base_branch: str = Field(
        default="main",
        description="베이스 브랜치 (main, master 등)"
    )


class CreateGitHubPRTool(BaseTool):
    """GitHub에 실제 Pull Request를 생성하는 도구"""

    name: str = "create_github_pr"
    description: str = """
    GitHub Repository에 실제 Pull Request를 생성합니다.

    사용 방법:
    1. 로컬 변경사항을 커밋
    2. 새 브랜치 생성
    3. 원격 저장소에 푸시
    4. GitHub API로 PR 생성

    인증 방법:
    - 옵션 1: GitHub CLI (gh) - 자동 인증 (권장)
    - 옵션 2: GITHUB_TOKEN 환경 변수 설정
    """
    args_schema: type[BaseModel] = CreateGitHubPRInput

    def _run(
        self,
        repo_url: str,
        pr_title: str,
        pr_body: str,
        branch_name: str = "security-fixes",
        base_branch: str = "main"
    ) -> Dict[str, Any]:
        """
        GitHub PR 생성 실행

        Args:
            repo_url: GitHub 저장소 URL
            pr_title: PR 제목
            pr_body: PR 본문
            branch_name: 새 브랜치 이름
            base_branch: 베이스 브랜치

        Returns:
            PR 생성 결과
        """
        try:
            # 인증 방법 확인
            use_github_cli = self._check_github_cli()
            github_token = os.environ.get('GITHUB_TOKEN')

            if not use_github_cli and not github_token:
                return {
                    "success": False,
                    "error": "No authentication method available",
                    "message": "Please either:\n1. Install GitHub CLI: brew install gh && gh auth login\n2. Set GITHUB_TOKEN environment variable",
                    "installation_guide": "https://cli.github.com/manual/installation"
                }

            # 저장소에서 owner/repo 추출
            repo_path = self._extract_repo_path(repo_url)

            # 현재 브랜치 확인
            current_branch = subprocess.run(
                ['git', 'branch', '--show-current'],
                capture_output=True,
                text=True,
                timeout=5
            ).stdout.strip()

            # 새 브랜치 생성 (이미 있으면 전환)
            print(f"📝 Creating/switching to branch: {branch_name}")
            branch_result = subprocess.run(
                ['git', 'checkout', '-B', branch_name],
                capture_output=True,
                text=True,
                timeout=10
            )

            if branch_result.returncode != 0:
                return {
                    "success": False,
                    "error": "Failed to create/switch branch",
                    "details": branch_result.stderr
                }

            # 변경사항이 있는지 확인
            status_result = subprocess.run(
                ['git', 'status', '--porcelain'],
                capture_output=True,
                text=True,
                timeout=5
            )

            has_changes = bool(status_result.stdout.strip())

            if has_changes:
                print("📦 Staging changes...")
                subprocess.run(['git', 'add', '.'], check=True, timeout=10)

                print("💾 Creating commit...")
                commit_message = f"{pr_title}\n\n{pr_body[:200]}..."
                subprocess.run(
                    ['git', 'commit', '-m', commit_message],
                    check=True,
                    timeout=10
                )

            # 원격 브랜치에 푸시
            print(f"🚀 Pushing to remote: {branch_name}")
            push_result = subprocess.run(
                ['git', 'push', '-u', 'origin', branch_name, '--force'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if push_result.returncode != 0:
                return {
                    "success": False,
                    "error": "Failed to push to remote",
                    "details": push_result.stderr
                }

            # PR 생성 - 인증 방법에 따라 분기
            print(f"🔀 Creating Pull Request on GitHub...")

            if use_github_cli:
                # 방법 1: GitHub CLI 사용
                return self._create_pr_with_cli(
                    repo_path, base_branch, branch_name, pr_title, pr_body, has_changes
                )
            else:
                # 방법 2: GitHub API 직접 호출
                return self._create_pr_with_api(
                    repo_path, base_branch, branch_name, pr_title, pr_body, github_token, has_changes
                )

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Operation timed out",
                "message": "Git/GitHub operation took too long"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "message": "An unexpected error occurred while creating PR"
            }

    def _check_github_cli(self) -> bool:
        """GitHub CLI 사용 가능 여부 확인"""
        try:
            # gh 설치 확인
            subprocess.run(['gh', '--version'], capture_output=True, check=True, timeout=5)

            # 인증 확인
            auth_check = subprocess.run(
                ['gh', 'auth', 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )

            return auth_check.returncode == 0

        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

    def _create_pr_with_cli(
        self,
        repo_path: str,
        base_branch: str,
        branch_name: str,
        pr_title: str,
        pr_body: str,
        has_changes: bool
    ) -> Dict[str, Any]:
        """GitHub CLI로 PR 생성"""
        import tempfile

        # PR 본문을 임시 파일로 저장
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(pr_body)
            body_file = f.name

        try:
            pr_result = subprocess.run(
                [
                    'gh', 'pr', 'create',
                    '--repo', repo_path,
                    '--base', base_branch,
                    '--head', branch_name,
                    '--title', pr_title,
                    '--body-file', body_file
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            if pr_result.returncode == 0:
                pr_url = pr_result.stdout.strip()
                return {
                    "success": True,
                    "pr_url": pr_url,
                    "branch": branch_name,
                    "base_branch": base_branch,
                    "message": f"Pull Request created successfully: {pr_url}",
                    "commits": 1 if has_changes else 0,
                    "method": "github_cli"
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to create PR with GitHub CLI",
                    "details": pr_result.stderr,
                    "branch_pushed": True,
                    "message": f"Branch '{branch_name}' was pushed but PR creation failed."
                }

        finally:
            os.unlink(body_file)

    def _create_pr_with_api(
        self,
        repo_path: str,
        base_branch: str,
        branch_name: str,
        pr_title: str,
        pr_body: str,
        github_token: str,
        has_changes: bool
    ) -> Dict[str, Any]:
        """GitHub API로 직접 PR 생성"""

        # API endpoint
        api_url = f"https://api.github.com/repos/{repo_path}/pulls"

        # Headers
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SecurityAgent"
        }

        # Request body
        data = {
            "title": pr_title,
            "body": pr_body,
            "head": branch_name,
            "base": base_branch
        }

        try:
            response = requests.post(api_url, headers=headers, json=data, timeout=30)

            if response.status_code == 201:
                pr_data = response.json()
                return {
                    "success": True,
                    "pr_url": pr_data["html_url"],
                    "pr_number": pr_data["number"],
                    "branch": branch_name,
                    "base_branch": base_branch,
                    "message": f"Pull Request created successfully: {pr_data['html_url']}",
                    "commits": 1 if has_changes else 0,
                    "method": "github_api"
                }
            elif response.status_code == 422:
                # PR이 이미 존재하는 경우
                error_data = response.json()
                return {
                    "success": False,
                    "error": "PR already exists or validation failed",
                    "details": error_data.get("message", ""),
                    "errors": error_data.get("errors", []),
                    "branch_pushed": True,
                    "message": "Branch was pushed but PR creation failed. A PR might already exist for this branch."
                }
            else:
                return {
                    "success": False,
                    "error": f"GitHub API returned {response.status_code}",
                    "details": response.text,
                    "branch_pushed": True
                }

        except requests.RequestException as e:
            return {
                "success": False,
                "error": "Failed to create PR via GitHub API",
                "details": str(e),
                "branch_pushed": True
            }

    def _extract_repo_path(self, repo_url: str) -> str:
        """
        GitHub URL에서 owner/repo 추출

        Args:
            repo_url: GitHub 저장소 URL

        Returns:
            owner/repo 형식 문자열
        """
        # https://github.com/qazz92/security-agent-test → qazz92/security-agent-test
        # git@github.com:qazz92/security-agent-test.git → qazz92/security-agent-test

        repo_url = repo_url.rstrip('/')

        if repo_url.startswith('https://github.com/'):
            path = repo_url.replace('https://github.com/', '')
        elif repo_url.startswith('git@github.com:'):
            path = repo_url.replace('git@github.com:', '')
        else:
            # 이미 owner/repo 형식이라고 가정
            return repo_url

        # .git 제거
        path = path.replace('.git', '')

        return path


class CreateGitHubIssueInput(BaseModel):
    """Input schema for create_github_issue tool"""
    repo_url: str = Field(
        description="GitHub 저장소 URL"
    )
    issue_title: str = Field(
        description="Issue 제목"
    )
    issue_body: str = Field(
        description="Issue 본문 (마크다운)"
    )
    labels: Optional[List[str]] = Field(
        default=None,
        description="Issue 라벨 리스트 (예: ['security', 'bug'])"
    )


class CreateGitHubIssueTool(BaseTool):
    """GitHub에 Issue를 생성하는 도구"""

    name: str = "create_github_issue"
    description: str = "GitHub Repository에 Issue를 생성합니다. 보안 취약점 보고 등에 사용."
    args_schema: type[BaseModel] = CreateGitHubIssueInput

    def _run(
        self,
        repo_url: str,
        issue_title: str,
        issue_body: str,
        labels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        GitHub Issue 생성

        Args:
            repo_url: GitHub 저장소 URL
            issue_title: Issue 제목
            issue_body: Issue 본문
            labels: 라벨 리스트

        Returns:
            Issue 생성 결과
        """
        try:
            # GitHub CLI 확인
            try:
                subprocess.run(['gh', '--version'], capture_output=True, check=True, timeout=5)
            except (FileNotFoundError, subprocess.CalledProcessError):
                return {
                    "success": False,
                    "error": "GitHub CLI (gh) not installed"
                }

            # 저장소 경로 추출
            pr_tool = CreateGitHubPRTool()
            repo_path = pr_tool._extract_repo_path(repo_url)

            # Issue 본문을 임시 파일로 저장
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
                f.write(issue_body)
                body_file = f.name

            try:
                # GitHub CLI로 Issue 생성
                cmd = [
                    'gh', 'issue', 'create',
                    '--repo', repo_path,
                    '--title', issue_title,
                    '--body-file', body_file
                ]

                # 라벨 추가
                if labels:
                    for label in labels:
                        cmd.extend(['--label', label])

                issue_result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if issue_result.returncode == 0:
                    issue_url = issue_result.stdout.strip()
                    return {
                        "success": True,
                        "issue_url": issue_url,
                        "message": f"Issue created successfully: {issue_url}"
                    }
                else:
                    return {
                        "success": False,
                        "error": "Failed to create issue",
                        "details": issue_result.stderr
                    }

            finally:
                os.unlink(body_file)

        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }


# Tool instances for backward compatibility
_create_github_pr_tool = CreateGitHubPRTool()
_create_github_issue_tool = CreateGitHubIssueTool()

# CrewAI-compatible tool wrappers
from crewai.tools import tool

@tool("Create GitHub PR")
def create_github_pr(
    repo_url: str,
    pr_title: str,
    pr_body: str,
    branch_name: str = "security-fixes",
    base_branch: str = "main"
) -> dict:
    """GitHub Repository에 Pull Request를 생성합니다. 보안 패치를 위한 브랜치 생성, 커밋, 푸시 및 PR 생성까지 자동으로 처리합니다. GitHub CLI 또는 GITHUB_TOKEN 환경 변수를 통해 인증합니다."""
    return _create_github_pr_tool._run(
        repo_url=repo_url,
        pr_title=pr_title,
        pr_body=pr_body,
        branch_name=branch_name,
        base_branch=base_branch
    )

@tool("Create GitHub Issue")
def create_github_issue(
    repo_url: str,
    issue_title: str,
    issue_body: str,
    labels: Optional[List[str]] = None
) -> dict:
    """GitHub Repository에 Issue를 생성합니다. 보안 취약점 보고나 개선 제안 등을 이슈로 등록할 때 사용합니다. GitHub CLI를 통해 인증합니다."""
    return _create_github_issue_tool._run(
        repo_url=repo_url,
        issue_title=issue_title,
        issue_body=issue_body,
        labels=labels
    )