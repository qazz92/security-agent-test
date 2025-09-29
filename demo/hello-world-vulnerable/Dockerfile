# 취약한 Dockerfile 예시 (교육 목적)

# 취약점 1: EOL(End of Life) 베이스 이미지 사용
FROM python:3.6-slim

# 취약점 2: root 사용자로 실행
USER root

# 취약점 3: 불필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    vim \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# 취약점 4: 작업 디렉토리를 root에 생성
WORKDIR /app

# 취약점 5: 모든 파일을 복사 (민감한 파일 포함 가능)
COPY . /app/

# 취약점 6: requirements.txt의 취약한 패키지들 설치
RUN pip install --no-cache-dir -r requirements.txt

# 취약점 7: 하드코딩된 환경 변수
ENV SECRET_KEY=my-super-secret-key
ENV DB_PASSWORD=admin123
ENV DEBUG=True

# 취약점 8: 모든 포트 노출
EXPOSE 5000

# 취약점 9: root 권한으로 애플리케이션 실행
CMD ["python", "app.py"]