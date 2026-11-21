package com.seccheck.analyzer;

public class SinkCall {
    private final String methodName;        // 위험 함수 이름 (exec, parseExpression ...)
    private final String vulnerabilityType;
    private final String argumentName;
    private final int lineNumber;
    private final String enclosingMethod;   // 이 호출이 들어있는 메서드 이름 (= 몇 반인지)

    public SinkCall(String methodName, String vulnerabilityType, String argumentName,
                    int lineNumber, String enclosingMethod) {
        this.methodName = methodName;
        this.vulnerabilityType = vulnerabilityType;
        this.argumentName = argumentName;
        this.lineNumber = lineNumber;
        this.enclosingMethod = enclosingMethod;
    }

    public String getMethodName() { return methodName; }
    public String getVulnerabilityType() { return vulnerabilityType; }
    public String getArgumentName() { return argumentName; }
    public int getLineNumber() { return lineNumber; }
    public String getEnclosingMethod() { return enclosingMethod; }

    @Override
    public String toString() {
        return String.format("[Line %d] %s(%s) -> %s, in %s",
                lineNumber, methodName, argumentName, vulnerabilityType, enclosingMethod);
    }
}