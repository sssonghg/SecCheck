package com.vulnapp.spel_vuln_app.controller;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpelController {

    @GetMapping("/vuln/spel")
    public String calculate(@RequestParam String expr) {
        // 취약점: 사용자 입력을 검증 없이 그대로 SpEL 표현식으로 실행
        ExpressionParser parser = new SpelExpressionParser();
        Expression expression = parser.parseExpression(expr);
        Object result = expression.getValue();
        return String.valueOf(result);
    }
}