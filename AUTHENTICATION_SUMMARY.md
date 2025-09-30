# 🔐 GitHub 인증 요약

## 질문: "github api는 pat 토큰이 필요한거 아니야?"

**답: 맞습니다!** 하지만 두 가지 방법이 있습니다.

---

## 🎯 인증 방법 비교

### 방법 1: GitHub CLI (권장) ⭐

```bash
gh auth login
```

**내부 동작:**
- GitHub CLI가 **자동으로 PAT 생성 및 관리**
- `~/.config/gh/hosts.yml`에 토큰 안전하게 저장
- 브라우저 OAuth로 간편 인증

**장점:**
- ✅ 토큰 직접 관리 불필요
- ✅ 자동 갱신
- ✅ 보안 관리 자동화

**단점:**
- ❌ GitHub CLI 설치 필요

---

### 방법 2: Personal Access Token (PAT)

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
```

**직접 PAT 생성:**
1. GitHub → Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. `repo` 권한 선택
4. 환경 변수로 제공

**장점:**
- ✅ GitHub CLI 불필요
- ✅ CI/CD 파이프라인에 적합
- ✅ 세밀한 권한 제어

**단점:**
- ❌ 수동 관리 필요
- ❌ 만료 시 재생성

---

## 🔄 SecurityAgent의 인증 처리

### 자동 감지 로직

```python
# 1단계: GitHub CLI 확인
if gh_cli_available and gh_authenticated:
    use_github_cli = True
    # GitHub CLI 사용

# 2단계: GITHUB_TOKEN 환경 변수 확인
elif GITHUB_TOKEN in environment:
    use_github_api = True
    # GitHub API 직접 호출

# 3단계: 인증 실패
else:
    return "인증 방법이 없습니다. gh auth login 또는 GITHUB_TOKEN 설정 필요"
```

### 실제 구현

```python
# src/tools/github_tools.py

def _run(self, ...):
    # 인증 방법 자동 감지
    use_github_cli = self._check_github_cli()
    github_token = os.environ.get('GITHUB_TOKEN')

    if use_github_cli:
        # GitHub CLI로 PR 생성
        return self._create_pr_with_cli(...)
    elif github_token:
        # GitHub API로 직접 PR 생성
        return self._create_pr_with_api(..., github_token)
    else:
        return {"error": "No authentication available"}
```

---

## 📊 방법별 특징

| 특징 | GitHub CLI | PAT Token |
|-----|-----------|-----------|
| 설치 필요 | ✅ gh 설치 | ❌ 불필요 |
| 토큰 관리 | 자동 | 수동 |
| 인증 방식 | OAuth (브라우저) | Token 직접 입력 |
| 토큰 만료 | 자동 갱신 | 수동 재생성 |
| CI/CD 적합성 | 보통 | 높음 |
| 보안성 | 높음 | 중간 (관리 필요) |
| 사용 편의성 | 매우 높음 | 중간 |

---

## 🧪 테스트

### GitHub CLI 테스트
```bash
gh auth status
# ✓ Logged in to github.com as qazz92
```

### PAT 테스트
```bash
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/user
```

### SecurityAgent 테스트
```bash
python test_github_pr.py --direct
```

---

## 💻 사용 예시

### 시나리오 1: 개발 환경 (GitHub CLI)

```bash
# 1회 설정
brew install gh
gh auth login

# 이후 계속 사용 가능
python test_github_pr.py
```

### 시나리오 2: CI/CD (PAT)

```yaml
# .github/workflows/security-scan.yml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

steps:
  - run: python test_github_pr.py
```

### 시나리오 3: 서버 환경 (PAT)

```bash
# 환경 변수 설정
export GITHUB_TOKEN=ghp_xxx

# 크론잡 등록
0 2 * * * cd /app && python test_github_pr.py
```

---

## 🔑 GitHub CLI가 저장하는 토큰

GitHub CLI는 내부적으로 **OAuth token**을 사용합니다:

```yaml
# ~/.config/gh/hosts.yml
github.com:
    oauth_token: gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    user: qazz92
    git_protocol: https
```

이것도 일종의 **access token**이지만:
- ✅ 자동 관리
- ✅ 자동 갱신
- ✅ 만료 걱정 없음

---

## 🚀 권장 워크플로우

### 로컬 개발:
```bash
gh auth login  # 1회만
python test_github_pr.py  # 계속 사용
```

### 프로덕션/CI:
```bash
export GITHUB_TOKEN=ghp_xxx  # 서버 환경 변수
python test_github_pr.py
```

---

## 📚 추가 리소스

- **상세 가이드**: [`GITHUB_PAT_SETUP.md`](GITHUB_PAT_SETUP.md)
- **빠른 시작**: [`QUICK_START_PR.md`](QUICK_START_PR.md)
- **전체 가이드**: [`GITHUB_PR_GUIDE.md`](GITHUB_PR_GUIDE.md)

---

## ✅ 결론

> **"GitHub API는 PAT 토큰이 필요한가?"**
>
> **답:** 네, 맞습니다! 하지만:
> - **GitHub CLI 사용 시**: 자동으로 관리 (권장)
> - **직접 사용 시**: `GITHUB_TOKEN` 환경 변수 설정
>
> SecurityAgent는 **둘 다 지원**합니다! 🎉

---

**어떤 방법을 선택하든 SecurityAgent가 자동으로 감지하고 사용합니다!** ✨