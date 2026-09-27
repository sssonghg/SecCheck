Command Injection
- Source: cmd
- Sink: Runtime.getRuntime().exec(cmd)

SpEL Injection
- Source: expr
- Sink: parser.parseExpression(expr)

SQL Injection
- Source: name
- Sink: jdbcTemplate.queryForList(sql)

| 취약점 | Endpoint | Method | Source | Sink |
|---|---|---|---|---|
| Command Injection | `/vuln/command` | GET | `cmd` | `Runtime.getRuntime().exec(cmd)` |
| SpEL Injection | `/vuln/spel` | GET | `expr` | `parser.parseExpression(expr)` |
| SQL Injection | `/vuln/sql` | GET | `name` | `jdbcTemplate.queryForList(sql)` |


## Analyzer Output Format

Analyzer의 분석 결과는 JSON 형식으로 전달한다.

```json
{
  "variableName": "cmd",
  "type": "String",
  "lineNumber": 13,
  "sourceAnnotation": "@RequestParam"
}