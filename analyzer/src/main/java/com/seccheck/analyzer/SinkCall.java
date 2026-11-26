package com.seccheck.analyzer;

import com.github.javaparser.ast.expr.Expression;

public class SinkCall {
    private final String methodName;        // 위험 함수 이름 (exec, parseExpression ...)
    private final String vulnerabilityType;
    private final String argumentName;      // 위험한 인자의 코드 원문 (sql, sb.toString(), "..." + name)
    private final int lineNumber;
    private final String enclosingMethod;   // 이 호출이 들어있는 메서드 이름 (= 몇 반인지)
    private final transient Expression argumentExpr;   // 위험한 인자의 식 그대로 (taint 판단용, JSON 에는 안 나옴)

    public SinkCall(String methodName, String vulnerabilityType, String argumentName,
                    int lineNumber, String enclosingMethod, Expression argumentExpr) {
        this.methodName = methodName;
        this.vulnerabilityType = vulnerabilityType;
        this.argumentName = argumentName;
        this.lineNumber = lineNumber;
        this.enclosingMethod = enclosingMethod;
        this.argumentExpr = argumentExpr;
    }

    public String getMethodName() { return methodName; }
    public String getVulnerabilityType() { return vulnerabilityType; }
    public String getArgumentName() { return argumentName; }
    public int getLineNumber() { return lineNumber; }
    public String getEnclosingMethod() { return enclosingMethod; }
    public Expression getArgumentExpr() { return argumentExpr; }

    @Override
    public String toString() {
        return String.format("[Line %d] %s(%s) -> %s, in %s",
                lineNumber, methodName, argumentName, vulnerabilityType, enclosingMethod);
    }
}