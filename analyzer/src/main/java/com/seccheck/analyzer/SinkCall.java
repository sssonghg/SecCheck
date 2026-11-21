// SinkCall.java
package com.seccheck.analyzer;

public class SinkCall {
    private final String methodName;
    private final String vulnerabilityType;
    private final String argumentName;
    private final int lineNumber;

    public SinkCall(String methodName, String vulnerabilityType, String argumentName, int lineNumber) {
        this.methodName = methodName;
        this.vulnerabilityType = vulnerabilityType;
        this.argumentName = argumentName;
        this.lineNumber = lineNumber;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public String getArgumentName() {
        return argumentName;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    @Override
    public String toString() {
        return String.format("[Line %d] %s(%s) -> %s",
                lineNumber, methodName, argumentName, vulnerabilityType);
    }
}