package com.seccheck.analyzer;

public class TaintedVariable {
    private final String variableName;
    private final String type;
    private final int lineNumber;
    private final String sourceAnnotation;
    private final String enclosingMethod; // 이 변수가 들어있는 메서드 이름 (= 몇 반인지)
    private final String rootSource;      // 오염이 처음 시작된 파라미터 이름 (예: sql 의 rootSource = name)
    private final String dtoField;        // DTO 에서 꺼낸 값이면 필드 이름 (예: req.getUsername() → username), 아니면 null

    public TaintedVariable(String variableName, String type, int lineNumber,
                           String sourceAnnotation, String enclosingMethod,
                           String rootSource, String dtoField) {
        this.variableName = variableName;
        this.type = type;
        this.lineNumber = lineNumber;
        this.sourceAnnotation = sourceAnnotation;
        this.enclosingMethod = enclosingMethod;
        this.rootSource = rootSource;
        this.dtoField = dtoField;
    }

    @Override
    public String toString() {
        return String.format("[Line %d] %s %s (from @%s, in %s, root=%s%s)",
                lineNumber, type, variableName, sourceAnnotation, enclosingMethod, rootSource,
                dtoField == null ? "" : ", field=" + dtoField);
    }

    public String getVariableName() { return variableName; }
    public String getType() { return type; }
    public int getLineNumber() { return lineNumber; }
    public String getSourceAnnotation() { return sourceAnnotation; }
    public String getEnclosingMethod() { return enclosingMethod; }
    public String getRootSource() { return rootSource; }
    public String getDtoField() { return dtoField; }
}