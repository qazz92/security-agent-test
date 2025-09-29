# Hello World - Vulnerable Demo Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational and demonstration purposes only. Do NOT use in production!**

## 포함된 취약점들

### 애플리케이션 레벨 (app.py)
1. **SQL Injection** - f-string을 사용한 쿼리 생성
2. **XSS (Cross-Site Scripting)** - 사용자 입력 직접 렌더링
3. **Command Injection** - subprocess에 사용자 입력 직접 전달
4. **Directory Traversal** - 파일 경로 검증 없음
5. **Unsafe Deserialization** - pickle.loads() 사용
6. **YAML Deserialization** - yaml.load() 사용
7. **하드코딩된 시크릿** - 소스코드에 API 키, 비밀번호 등
8. **약한 세션 관리** - 단순 쿠키 기반 인증
9. **정보 노출** - 환경변수 덤프
10. **파일 업로드 취약점** - 파일 타입 검증 없음

### 종속성 취약점 (requirements.txt)
- Flask==1.0.0 (CVE-2019-1010083)
- requests==2.19.0 (CVE-2018-18074)
- PyYAML==3.13 (CVE-2017-18342)
- Jinja2==2.10 (CVE-2019-10906)
- 기타 EOL 패키지들

### 인프라 취약점 (Dockerfile, docker-compose.yml)
- EOL 베이스 이미지 (python:3.6)
- Root 사용자로 실행
- 모든 포트 외부 노출
- 특권 모드 실행
- 하드코딩된 환경변수

## 실행 방법

```bash
cd demo/hello-world-vulnerable
pip install -r requirements.txt
python app.py
```

또는 Docker로:

```bash
docker-compose up
```

## 취약점 테스트 예시

### SQL Injection
```
GET /user/1; DROP TABLE users; --
GET /search?q='; DROP TABLE users; --
```

### XSS
```
POST /comment
comment=<script>alert('XSS')</script>
```

### Directory Traversal
```
GET /read_file?file=../../etc/passwd
```

### Command Injection
```
GET /ping?host=localhost; cat /etc/passwd
```

이 애플리케이션은 SecurityAgent가 탐지하고 수정할 취약점들의 샘플입니다.