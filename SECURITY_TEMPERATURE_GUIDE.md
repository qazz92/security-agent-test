# 🔐 Security-First Temperature Management Guide

## 🎯 핵심 철학: "보안에서는 타협이 없다"

SecurityAgent는 **보안 도메인의 특수성**을 고려하여 극도로 정교한 Temperature 관리 시스템을 구현했습니다. 각 작업의 보안 중요도에 따라 **0.03부터 0.65까지** 세밀하게 조정된 Temperature를 사용합니다.

## 📊 Security Temperature Matrix

### 🔴 CRITICAL - 절대 정확성 (Temperature: 0.03-0.08)

**거의 결정적 동작이 필요한 영역**

| 작업 | Temperature | 이유 | 예시 |
|------|-------------|------|------|
| `vulnerability_classification` | **0.05** | CVE 분류는 100% 정확해야 함 | "이것은 SQL Injection입니다" |
| `exploit_confirmation` | **0.03** | 공격 가능성 판단에 애매함 금지 | "실제 공격 가능: Yes/No" |
| `severity_assessment` | **0.08** | CVSS 점수는 일관된 기준 필요 | "CVSS 9.8 Critical" |

```python
# CRITICAL 레벨 사용 예시
llm = create_security_llm(
    task_type="vulnerability_classification",
    security_level="CRITICAL"  # Temperature: 0.05
)

# 결과: 항상 일관된 분류
response = llm.invoke("SELECT * FROM users WHERE id = {user_input}")
# → "SQL Injection vulnerability detected" (매번 동일)
```

### 🟠 HIGH - 높은 일관성 (Temperature: 0.10-0.15)

**패턴 인식과 규정 준수**

| 작업 | Temperature | 이유 | 예시 |
|------|-------------|------|------|
| `pattern_detection` | **0.12** | 공격 패턴 인식의 정확성 | XSS, SQLi 패턴 감지 |
| `compliance_check` | **0.10** | OWASP, PCI-DSS 기준 적용 | 규정 위반 여부 판단 |
| `risk_calculation` | **0.15** | 비즈니스 리스크 평가 | 손실 비용 계산 |

```python
# HIGH 레벨 - 패턴 인식
llm = create_security_llm(
    task_type="pattern_detection",
    security_level="HIGH"  # Temperature: 0.12
)

# 일관된 패턴 인식
malicious_patterns = [
    "'; DROP TABLE users; --",
    "<script>alert('xss')</script>",
    "../../../../etc/passwd"
]
# → 모든 패턴을 일관되게 위험으로 분류
```

### 🟡 MEDIUM - 균형점 (Temperature: 0.18-0.25)

**분석과 평가의 균형**

| 작업 | Temperature | 이유 | 예시 |
|------|-------------|------|------|
| `general_analysis` | **0.20** | 종합 분석에 약간의 유연성 허용 | 전체적 보안 상태 평가 |
| `impact_assessment` | **0.18** | 비즈니스 영향 분석 | 시나리오별 손실 추정 |
| `trend_analysis` | **0.25** | 트렌드 파악에 해석 여지 허용 | 취약점 증가 경향 분석 |

### 🟢 LOW - 제한적 창의성 (Temperature: 0.35-0.45)

**해결책 생성 영역**

| 작업 | Temperature | 이유 | 예시 |
|------|-------------|------|------|
| `fix_code_generation` | **0.35** | 수정 코드에 다양한 접근 허용 | 여러 수정 방안 제시 |
| `explanation_generation` | **0.40** | 설명에 교육적 창의성 허용 | 이해하기 쉬운 설명 |
| `documentation_writing` | **0.45** | 문서화에 표현력 허용 | 명확한 기술 문서 |

### 🔵 CREATIVE - 창의성 필요 (Temperature: 0.55-0.65)

**아이디어와 교육 컨텐츠**

| 작업 | Temperature | 이유 | 예시 |
|------|-------------|------|------|
| `report_formatting` | **0.55** | 보고서 형식에 창의성 허용 | 읽기 쉬운 리포트 구성 |
| `remediation_brainstorming` | **0.60** | 새로운 해결책 아이디어 | 혁신적 보안 접근법 |
| `training_content` | **0.65** | 교육 자료의 흥미도 | 재미있는 보안 교육 |

## 🛡️ 보안 강화 매개변수

Temperature 외에도 추가적인 보안 매개변수를 적용:

### Top-P (Nucleus Sampling)

```python
SECURITY_PARAMS = {
    "CRITICAL": {"top_p": 0.1},    # 가장 확실한 선택만
    "HIGH":     {"top_p": 0.2},    # 제한적 선택
    "MEDIUM":   {"top_p": 0.3},    # 균형
    "LOW":      {"top_p": 0.4},    # 약간의 다양성
    "CREATIVE": {"top_p": 0.6}     # 창의적 표현
}
```

### Penalty Parameters

```python
# 패턴 인식용: 반복 허용 (같은 패턴을 계속 찾아야 함)
"pattern_detection": {
    "frequency_penalty": -0.1,  # 반복 장려
    "presence_penalty": 0.0
}

# 수정 생성용: 다양성 추구
"fix_code_generation": {
    "frequency_penalty": 0.2,   # 반복 억제
    "presence_penalty": 0.3     # 새로운 아이디어
}
```

## 🚀 실제 적용 예시

### 1. SQL Injection 분석

```python
# Step 1: 취약점 분류 (Temperature: 0.05)
classification_llm = create_security_llm(
    "vulnerability_classification", "CRITICAL"
)
result = classification_llm.invoke(suspicious_code)
# → "SQL Injection" (항상 동일한 분류)

# Step 2: 심각도 평가 (Temperature: 0.08)
severity_llm = create_security_llm(
    "severity_assessment", "CRITICAL"
)
cvss_score = severity_llm.invoke(vulnerability_details)
# → "CVSS: 9.8 Critical" (일관된 점수)

# Step 3: 수정 코드 생성 (Temperature: 0.35)
fix_llm = create_security_llm(
    "fix_code_generation", "LOW"
)
fix_code = fix_llm.invoke(vulnerability_context)
# → 다양한 수정 방안 제시 (파라미터화, ORM, 검증 등)
```

### 2. 계층적 Fallback 시스템

```python
def create_security_llm(task_type, security_level):
    try:
        # Primary 모델로 시도
        return create_primary_model(task_type, security_level)
    except Exception:
        # Fallback: 더욱 보수적 설정으로
        fallback_temp = original_temp * 0.8  # 20% 더 보수적
        return create_fallback_model(task_type, fallback_temp)
```

## 📈 성능 vs 보안 트레이드오프

| 측면 | CRITICAL (0.05) | MEDIUM (0.20) | CREATIVE (0.60) |
|------|-----------------|---------------|-----------------|
| **정확성** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **일관성** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |
| **창의성** | ⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **응답 시간** | 빠름 | 보통 | 보통 |
| **토큰 효율** | 높음 | 보통 | 낮음 |

## 🔍 모니터링 및 검증

### Temperature 효과 추적

```python
class TemperatureTracker:
    def track_consistency(self, task_type: str, inputs: List[str]):
        """같은 입력에 대한 일관성 측정"""
        results = []
        llm = create_security_llm(task_type, "CRITICAL")

        for input_text in inputs:
            # 동일 입력 5번 실행
            responses = [llm.invoke(input_text) for _ in range(5)]
            consistency_score = calculate_similarity(responses)
            results.append(consistency_score)

        return np.mean(results)

# 예상 결과:
# vulnerability_classification (T=0.05): 98% 일관성
# fix_code_generation (T=0.35): 75% 일관성
# training_content (T=0.65): 45% 일관성
```

### 자동 Temperature 조정

```python
class AdaptiveTemperature:
    def adjust_based_on_accuracy(self, task_type: str, accuracy: float):
        """정확도에 따른 Temperature 자동 조정"""
        current_temp = get_security_temperature(task_type)

        if accuracy < 0.95:  # 정확도가 95% 미만이면
            new_temp = max(0.03, current_temp * 0.8)  # 더 보수적으로
        elif accuracy > 0.99:  # 정확도가 99% 초과면
            new_temp = min(0.25, current_temp * 1.1)  # 약간 완화

        return new_temp
```

## ⚡ 성능 최적화

### 캐싱 전략

```python
# 동일한 취약점 패턴에 대해서는 결과 캐시
@cache_security_result(ttl=3600)  # 1시간 캐시
def classify_vulnerability(code_pattern: str):
    llm = create_security_llm("vulnerability_classification", "CRITICAL")
    return llm.invoke(code_pattern)
```

### 배치 처리

```python
# 유사한 작업들을 배치로 처리하여 효율성 증대
def batch_security_analysis(code_samples: List[str]):
    classification_llm = create_security_llm(
        "vulnerability_classification",
        "CRITICAL"
    )

    # 배치 처리로 토큰 효율성 증대
    batch_prompt = create_batch_prompt(code_samples)
    return classification_llm.invoke(batch_prompt)
```

## 🎯 결론

**SecurityAgent의 Temperature 관리는 단순한 매개변수 조정이 아닌, 보안 전문가의 사고방식을 AI에 구현한 것입니다.**

- **절대 정확성이 필요한 영역**: Temperature 0.03-0.08
- **일관성이 중요한 영역**: Temperature 0.10-0.15
- **균형이 필요한 영역**: Temperature 0.18-0.25
- **창의성이 허용되는 영역**: Temperature 0.35-0.65

이러한 세밀한 조정을 통해 **보안의 정확성을 보장하면서도 실용적인 해결책을 제공**하는 것이 SecurityAgent의 핵심 차별화 포인트입니다! 🛡️