
# Sandbox

Spring Boot 취약 애플리케이션을 Docker 컨테이너에서 실행하고
취약점 검증 및 패치 재검증을 수행하기 위한 샌드박스 환경.

## Runtime

- Java: 21
- Build Tool: Gradle
- Database: H2

## Applications

| App | Port |
| --- | --- |
| Command Injection App | 8081 |
| SpEL Injection App | 8082 |
| SQL Injection App | 8083 |

## Health Check

- Endpoint: /actuator/health
- Method: GET
- Success: HTTP 200 + status UP

## Docker

- Resource Limit: 추후 결정
- Network Policy: 검증에 필요한 통신만 허용
- Timeout: 추후 결정
