package com.seccheck.analyzer;

public class TaintedVariable {
    private final String variableName;
    private final String type;
    private final int lineNumber;
    private final String sourceAnnotation;
    private final String enclosingMethod; // 이 변수가 들어있는 메서드 이름 (= 몇 반인지)

    public TaintedVariable(String variableName, String type, int lineNumber,
                           String sourceAnnotation, String enclosingMethod) {
        this.variableName = variableName;
        this.type = type;
        this.lineNumber = lineNumber;
        this.sourceAnnotation = sourceAnnotation;
        this.enclosingMethod = enclosingMethod;
    }

    @Override
    public String toString() {
        return String.format("[Line %d] %s %s (from @%s, in %s)",
                lineNumber, type, variableName, sourceAnnotation, enclosingMethod);
    }

    public String getVariableName() { return variableName; }
    public String getSourceAnnotation() { return sourceAnnotation; }
    public String getEnclosingMethod() { return enclosingMethod; }
}