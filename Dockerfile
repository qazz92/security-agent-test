# SecurityAgent Portfolio - Production Dockerfile
FROM python:3.12-slim

# 메타데이터
LABEL maintainer="SecurityAgent Portfolio" \
      description="AI-Powered Security Vulnerability Analysis System" \
      version="1.0.0"

# 보안 강화: 비루트 사용자 생성 (홈 디렉토리 포함)
RUN groupadd -r appuser && useradd -r -g appuser -m -d /home/appuser appuser

# 시스템 패키지 업데이트 및 필수 도구 설치
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Trivy 설치 (보안 스캐너) - 최신 방법
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# Semgrep 설치 (SAST 코드 분석)
RUN pip install --no-cache-dir semgrep

# 작업 디렉토리 설정
WORKDIR /app

# Python 의존성 파일 복사
COPY requirements.txt .

# Python 패키지 설치
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드 복사
COPY src/ ./src/
COPY demo/ ./demo/
COPY tests/ ./tests/
COPY streamlit_app.py .
COPY main.py .
COPY pytest.ini .
COPY .env.example .

# 로그 및 결과 디렉토리 생성
RUN mkdir -p logs results \
    && chown -R appuser:appuser /app \
    && mkdir -p /home/appuser/.streamlit \
    && chown -R appuser:appuser /home/appuser

# Streamlit 설정 파일 생성
RUN echo '[general]\nemail = ""\n' > /home/appuser/.streamlit/credentials.toml \
    && echo '[server]\nheadless = true\nenableCORS = false\n' > /home/appuser/.streamlit/config.toml \
    && chown -R appuser:appuser /home/appuser/.streamlit

# 보안: 비루트 사용자로 전환
USER appuser

# 헬스체크
HEALTHCHECK --interval=30s --timeout=30s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# 포트 노출
EXPOSE 8501

# 기본 명령어
CMD ["streamlit", "run", "streamlit_app.py", "--server.address", "0.0.0.0", "--server.port", "8501"]

# 대안 실행 방법들
# CLI 모드: docker run security-agent python main.py analyze demo/hello-world-vulnerable
# UI 모드: docker run -p 8501:8501 security-agent (기본값)