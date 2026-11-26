# SecCheck – LLM Agent

## 1. 개요

Analyzer에서 추출한 정적 분석 결과를 기반으로 LangChain과 LLM을 활용하여 HTTP 테스트 요청을 자동으로 생성하는 모듈이다.

Pydantic 기반 Structured Output을 적용하여 LLM의 출력 형식을 일관되게 유지하며, 생성된 HTTP 요청이 Analyzer에서 제공한 규격을 준수하는지 검증한다.

## 2. 기술 스택

| 기술 | 사용 목적 |
|---|---|
| Python | LLM Agent 및 검증 로직 구현 |
| LangChain | 프롬프트 구성 및 LLM 실행 파이프라인 구축 |
| Ollama | 로컬 LLM 실행 |
| Qwen2.5:7B | HTTP 테스트 요청 생성 모델 |
| Pydantic | 입력 데이터 및 Structured Output 스키마 정의 |

## 3. 디렉터리 구조

```text
SecCheck/
├── sample_finding.json
└── poc_agent/
    ├── __init__.py
    ├── schemas.py
    ├── prompts.py
    ├── agent.py
    ├── test_llm.py
    ├── test_agent.py
    ├── test_validation.py
    └── README.md
```

| 파일 | 역할 |
|---|---|
| `schemas.py` | Analyzer 입력 및 HTTP 요청 출력 스키마 정의 |
| `prompts.py` | 공통 생성 규칙 및 취약점 유형별 프롬프트 관리 |
| `agent.py` | LLM 호출, Structured Output 생성 및 HTTP 요청 검증 |
| `test_llm.py` | LLM 연결 및 Structured Output 테스트 |
| `test_agent.py` | Analyzer JSON 기반 HTTP 요청 생성 테스트 |
| `test_validation.py` | HTTP 요청 검증 로직 테스트 |
| `sample_finding.json` | Analyzer 출력 규격 기반 Mock 데이터 |

## 4. 전체 동작 흐름

```text
Analyzer JSON
    ↓
Pydantic 입력 데이터 검증
    ↓
ChatPromptTemplate을 활용한 프롬프트 구성
    ↓
LangChain Chain 실행
    ↓
Ollama LLM 추론
    ↓
Structured Output 생성
    ↓
메타데이터 보정
    ↓
HTTP 요청 검증
    ↓
HTTP 요청 객체 반환
```

## 5. 입력 데이터 규격

Analyzer 출력 JSON v1.1 규격을 기반으로 입력 데이터를 처리한다.

| 필드 | 설명 |
|---|---|
| `schemaVersion` | JSON 규격 버전 |
| `project` | 분석 대상 프로젝트 |
| `findings` | 취약점 분석 결과 목록 |
| `findingId` | 개별 취약점 식별자 |
| `vulnType` | 취약점 유형 |
| `endpoint` | HTTP Method, 경로 및 파라미터 정보 |
| `location` | 취약 코드 위치 |
| `sink` | 위험 함수 호출 정보 |
| `taintPath` | Source에서 Sink까지의 데이터 흐름 |
| `methodSource` | 취약 메서드의 소스코드 |

### 지원 취약점 유형

- COMMAND_INJECTION
- SPEL_INJECTION
- SQL_INJECTION

### 지원 파라미터 유형

| 유형 | 설명 |
|---|---|
| `query` | URL 쿼리 파라미터 |
| `path` | URL 경로 파라미터 |
| `body` | HTTP 요청 본문 |
| `header` | HTTP 요청 헤더 |
| `cookie` | HTTP 쿠키 |

기존 v1.0 규격에서 v1.1로 변경됨에 따라 Header 및 Cookie 파라미터 지원을 추가하였다.

## 6. 출력 데이터 규격

Pydantic의 `PoCRequest` 클래스를 기반으로 LLM의 출력 형식을 정의한다.

### 정상 비교 요청 생성 결과 예시

```json
{
  "findingId": "F-002",
  "vulnType": "SPEL_INJECTION",
  "method": "GET",
  "endpoint": "/vuln/spel",
  "headers": {},
  "queryParams": {
    "expr": "1+1"
  },
  "body": null
}
```

| 필드 | 설명 |
|---|---|
| `findingId` | 원본 취약점 식별자 |
| `vulnType` | 원본 취약점 유형 |
| `method` | HTTP 요청 메서드 |
| `endpoint` | HTTP 요청 경로 |
| `headers` | HTTP 헤더 및 쿠키 |
| `queryParams` | 쿼리 파라미터 |
| `body` | HTTP 요청 본문 |

LLM이 식별자 및 취약점 유형을 잘못 생성하는 문제를 방지하기 위해 `findingId`와 `vulnType`은 Analyzer의 원본 데이터로 보정한다.

## 7. HTTP 요청 검증

LLM이 생성한 요청과 Analyzer의 분석 결과를 비교하여 요청 구조의 유효성을 검증한다.

| 검증 항목 | 검증 내용 |
|---|---|
| HTTP Method | 허용된 HTTP Method 일치 여부 |
| Endpoint | Analyzer에서 추출한 경로 일치 여부 |
| Query | 필수 쿼리 파라미터 누락 여부 |
| Path | 경로 변수 존재 및 기본 형식 검증 |
| Body | 필수 요청 본문 존재 여부 |
| DTO | 요청 본문 객체 구조 및 허용 필드 검증 |
| Content-Type | 허용된 요청 본문 형식 일치 여부 |
| Header | 필수 헤더 존재 여부 |
| Cookie | 필수 쿠키 존재 여부 |

검증 실패 시 `ValueError`를 발생시켜 잘못된 요청이 이후 단계로 전달되는 것을 방지한다.

## 8. 실행 방법

### 8.1 개발 환경 설정

```bash
python -m venv .venv
source .venv/bin/activate

pip install langchain langchain-ollama pydantic
```

### 8.2 Ollama 모델 설치 및 실행

```bash
ollama pull qwen2.5:7b
ollama serve
```

이미 Ollama 서버가 실행 중인 경우 `ollama serve` 실행 생략

### 8.3 LLM 연결 테스트

```bash
python -m poc_agent.test_llm
```

### 8.4 Mock JSON 기반 Agent 테스트

```bash
python -m poc_agent.test_agent
```

### 8.5 HTTP 요청 검증 테스트

```bash
python -m poc_agent.test_validation
```

### 8.6 외부 Analyzer JSON 입력

```bash
python -m poc_agent.test_agent analyzer_result.json
```

실제 Analyzer 출력 파일의 경로를 인자로 전달하는 방식이며, Analyzer 구현 완료 후 연동 테스트 진행 예정

## 9. 테스트 결과

### 9.1 LLM Agent 생성 테스트

Analyzer 출력 규격을 기반으로 Mock JSON을 제작하여 세 가지 취약점 유형의 정상 비교 요청 생성 테스트를 진행하였다.

| 취약점 유형 | 정상 비교 요청 파라미터 | 결과 |
|---|---|---|
| Command Injection | `host=localhost` | PASS |
| SpEL Injection | `expr=1+1` | PASS |
| SQL Injection | `name=testuser` | PASS |

### 9.2 HTTP 요청 검증 테스트

| 테스트 항목 | 결과 |
|---|---|
| 정상 HTTP 요청 허용 | PASS |
| 잘못된 HTTP Method 차단 | PASS |
| 필수 Body 누락 차단 | PASS |
| 잘못된 Content-Type 차단 | PASS |
| 정상 Header 및 Cookie 허용 | PASS |
| 필수 Header 누락 차단 | PASS |
| 필수 Cookie 누락 차단 | PASS |

## 10. 현재 구현 현황

- [x] LangChain 및 Ollama 개발 환경 구축
- [x] Analyzer 입력 JSON v1.1 스키마 정의
- [x] Pydantic 기반 Structured Output 구현
- [x] 공통 및 취약점 유형별 프롬프트 작성
- [x] LangChain 기반 LLM Agent 구현
- [x] HTTP 요청 구조 검증 기능 구현
- [x] 3가지 취약점 유형별 정상 비교 요청 생성 테스트
- [x] Header 및 Cookie 검증 테스트
- [ ] 취약점 유형별 프롬프트와 Agent 연동
- [ ] 실제 취약점 검증용 PoC 생성 테스트
- [ ] 실제 Analyzer JSON 연동 테스트
- [ ] Header 및 Cookie 포함 LLM 요청 생성 테스트
- [ ] 생성 결과 JSON 파일 저장

## 11. 향후 개발 계획

- 실제 Analyzer 출력 JSON 기반 LLM Agent 연동
- 취약점 검증용 요청 생성 기능 완성
- Docker 샌드박스 기반 HTTP 요청 실행
- HTTP 응답 및 ByteBuddy 모니터링 이벤트 기반 취약점 판정
- 검증 실패 시 LLM 요청 재생성 및 Retry 로직 구현
- OpenAI API 연동