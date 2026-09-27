Command Injection
- Source: cmd
- Sink: Runtime.getRuntime().exec(cmd)

SpEL Injection
- Source: expr
- Sink: parser.parseExpression(expr)

SQL Injection
- Source: name
- Sink: jdbcTemplate.queryForList(sql)