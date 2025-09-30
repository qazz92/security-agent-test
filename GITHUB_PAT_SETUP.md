# 🔑 GitHub Personal Access Token (PAT) 설정 가이드

SecurityAgent에서 GitHub PR을 자동 생성하려면 **인증**이 필요합니다.

두 가지 방법 중 선택하세요:

---

## 🎯 옵션 1: GitHub CLI (권장) ⭐

**장점:**
- ✅ 자동 토큰 관리
- ✅ 토큰 저장 걱정 없음
- ✅ 만료 자동 갱신
- ✅ 브라우저 OAuth 인증

**설치 & 인증:**
```bash
# 설치
brew install gh  # macOS
sudo apt install gh  # Ubuntu

# 인증
gh auth login
```

인터랙티브 프롬프트:
```
? What account do you want to log into?
  > GitHub.com

? What is your preferred protocol for Git operations?
  > HTTPS

? Authenticate Git with your GitHub credentials?
  > Yes

? How would you like to authenticate GitHub CLI?
  > Login with a web browser
```

브라우저에서 승인하면 **완료!**

---

## 🎯 옵션 2: Personal Access Token (PAT)

**언제 사용?**
- GitHub CLI 설치 불가능한 환경
- CI/CD 파이프라인
- 서버/컨테이너 환경

### Step 1: PAT 생성

1. **GitHub → Settings 이동**
   ```
   https://github.com/settings/tokens
   ```

2. **"Generate new token" → "Generate new token (classic)" 클릭**

3. **토큰 설정:**
   ```
   Note: SecurityAgent PR Automation
   Expiration: 90 days (또는 원하는 기간)

   ✅ Scopes (권한 선택):
   ✅ repo (전체)
      ✅ repo:status
      ✅ repo_deployment
      ✅ public_repo
      ✅ repo:invite
      ✅ security_events

   선택사항:
   □ workflow (GitHub Actions 수정 시)
   □ write:packages (패키지 배포 시)
   ```

4. **"Generate token" 클릭**

5. **토큰 복사 (중요! 다시 볼 수 없음)**
   ```
   ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

### Step 2: 환경 변수 설정

#### macOS/Linux (임시):
```bash
export GITHUB_TOKEN=ghp_your_token_here
```

#### macOS/Linux (영구):
```bash
# ~/.bashrc 또는 ~/.zshrc에 추가
echo 'export GITHUB_TOKEN=ghp_your_token_here' >> ~/.zshrc
source ~/.zshrc
```

#### Windows (PowerShell):
```powershell
$env:GITHUB_TOKEN = "ghp_your_token_here"
```

#### .env 파일 (권장):
```bash
# .env 파일 생성
cp .env.example .env

# .env 파일 편집
GITHUB_TOKEN=ghp_your_token_here
```

### Step 3: 확인

```bash
echo $GITHUB_TOKEN
# ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

또는 Python에서:
```python
import os
print(os.environ.get('GITHUB_TOKEN'))
```

---

## 🔐 보안 Best Practices

### ✅ DO (해야 할 것)
- ✅ **짧은 만료 기간** (30-90일)
- ✅ **최소 권한 원칙** (필요한 scope만)
- ✅ **.env 파일을 .gitignore에 추가**
- ✅ **정기적으로 토큰 교체**
- ✅ **토큰 이름에 용도 명시**

### ❌ DON'T (하지 말아야 할 것)
- ❌ **코드에 하드코딩**
- ❌ **공개 저장소에 커밋**
- ❌ **슬랙/이메일로 공유**
- ❌ **만료 없는 토큰 생성**
- ❌ **불필요한 권한 부여**

---

## 🧪 테스트

### GitHub CLI 테스트:
```bash
gh auth status
# ✓ Logged in to github.com as qazz92 (oauth_token)
```

### PAT 테스트:
```bash
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/user

# 응답에 당신의 GitHub 정보가 나오면 성공!
```

### SecurityAgent에서 테스트:
```bash
python test_github_pr.py --direct
```

---

## 🔄 인증 방법 우선순위

SecurityAgent는 다음 순서로 인증을 시도합니다:

```
1. GitHub CLI 인증 확인
   ↓ (없으면)
2. GITHUB_TOKEN 환경 변수 확인
   ↓ (없으면)
3. 에러 반환 (인증 방법 안내)
```

---

## ❌ 문제 해결

### "401 Unauthorized"
**원인:** 토큰이 만료되었거나 잘못됨

**해결:**
```bash
# 새 토큰 생성 후
export GITHUB_TOKEN=new_token_here
```

### "403 Forbidden"
**원인:** 권한 부족

**해결:** `repo` scope가 있는 토큰으로 재생성

### "404 Not Found"
**원인:** 저장소가 존재하지 않거나 접근 권한 없음

**해결:**
```bash
# 저장소 접근 테스트
gh repo view qazz92/security-agent-test
```

### "422 Validation Failed"
**원인:** PR이 이미 존재하거나 브랜치 문제

**해결:** 다른 브랜치 이름 사용
```python
branch_name="security-fixes-v2"
```

---

## 📊 권한별 기능 매트릭스

| 기능 | 필요 권한 | GitHub CLI | PAT |
|-----|---------|-----------|-----|
| PR 생성 | `repo` | ✅ | ✅ |
| Issue 생성 | `repo` | ✅ | ✅ |
| PR 코멘트 | `repo` | ✅ | ✅ |
| Actions 트리거 | `workflow` | ✅ | ✅ |
| 패키지 배포 | `write:packages` | ✅ | ✅ |

---

## 🔗 참고 링크

- [GitHub CLI 공식 문서](https://cli.github.com/)
- [GitHub PAT 문서](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
- [GitHub API 문서](https://docs.github.com/en/rest)
- [OAuth Apps vs PAT](https://docs.github.com/en/developers/apps/getting-started-with-apps/about-apps)

---

## 💡 FAQ

### Q: GitHub CLI와 PAT 둘 다 설정하면?
**A:** GitHub CLI가 우선 사용됩니다.

### Q: 토큰이 만료되면?
**A:**
- GitHub CLI: `gh auth refresh` 자동 갱신
- PAT: 새 토큰 생성 필요

### Q: Fine-grained PAT vs Classic PAT?
**A:** Classic PAT 권장 (더 간단하고 널리 지원됨)

### Q: 여러 저장소에 사용 가능?
**A:** 네, 하나의 토큰으로 모든 저장소 접근 가능 (권한만 있으면)

---

**이제 SecurityAgent가 GitHub과 완벽하게 연동됩니다!** 🎉