# 🚀 GitHub PR 자동 생성 - 빠른 시작

## 3단계로 시작하기

### 1️⃣ GitHub CLI 설치 & 인증

```bash
# 설치
brew install gh  # macOS

# 인증
gh auth login
```

### 2️⃣ Git 저장소 연결

```bash
cd security-agent-portfolio
git remote add origin https://github.com/qazz92/security-agent-test.git
```

### 3️⃣ 실행

```bash
python test_github_pr.py
```

---

## 🎯 결과

프로그램이 자동으로:
- ✅ 보안 취약점 분석
- ✅ 수정 방안 생성
- ✅ **GitHub에 PR 생성** ← 이게 핵심!

생성된 PR: `https://github.com/qazz92/security-agent-test/pull/1`

---

## 💡 직접 PR 생성 테스트

Tool을 직접 호출:

```bash
python test_github_pr.py --direct
```

---

## ❓ 문제 해결

### "gh not found"
```bash
brew install gh
```

### "not authenticated"
```bash
gh auth login
```

### "remote not found"
```bash
git remote add origin https://github.com/qazz92/security-agent-test.git
```

---

**더 자세한 내용:** [`GITHUB_PR_GUIDE.md`](GITHUB_PR_GUIDE.md) 참고