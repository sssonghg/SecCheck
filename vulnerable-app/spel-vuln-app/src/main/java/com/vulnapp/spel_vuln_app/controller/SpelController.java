package com.vulnapp.spel_vuln_app.controller;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

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


    @PostMapping("/vuln/spel/body")
    public String calculateFromBody(@RequestBody String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression expression = parser.parseExpression(expr);
        Object result = expression.getValue();
        return String.valueOf(result);
    }

    // [4번-7] 이름표 + 공격 대상 아닌 파라미터
    @GetMapping("/vuln/spel/named")
    public String calculateNamed(@RequestParam("q") String expression,
                                 @RequestParam(defaultValue = "1") int repeat) {
        ExpressionParser parser = new SpelExpressionParser();
        Object result = parser.parseExpression(expression).getValue();
        return String.valueOf(result).repeat(Math.max(1, Math.min(repeat, 3)));
    }
}