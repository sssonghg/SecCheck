package com.seccheck.analyzer;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class TaintedVariable {
    private final String variableName;
    private final String type;
    private final int lineNumber;
    private final String sourceAnnotation;
    private final String enclosingMethod; // 이 변수가 들어있는 메서드 이름 (= 몇 반인지)
    private final Set<String> rootSources; // 오염이 처음 시작된 파라미터들 (예: sql 의 rootSources = [name])
    private final Set<String> dtoFields;   // DTO 에서 꺼낸 필드들, "파라미터.필드" 형식 (예: [req.username, req.email])

    public TaintedVariable(String variableName, String type, int lineNumber,
                           String sourceAnnotation, String enclosingMethod,
                           Set<String> rootSources, Set<String> dtoFields) {
        this.variableName = variableName;
        this.type = type;
        this.lineNumber = lineNumber;
        this.sourceAnnotation = sourceAnnotation;
        this.enclosingMethod = enclosingMethod;
        this.rootSources = new LinkedHashSet<>(rootSources);
        this.dtoFields = new LinkedHashSet<>(dtoFields);
    }

    @Override
    public String toString() {
        return String.format("[Line %d] %s %s (from @%s, in %s, root=%s%s)",
                lineNumber, type, variableName, sourceAnnotation, enclosingMethod, rootSources,
                dtoFields.isEmpty() ? "" : ", fields=" + dtoFields);
    }

    public String getVariableName() { return variableName; }
    public String getType() { return type; }
    public int getLineNumber() { return lineNumber; }
    public String getSourceAnnotation() { return sourceAnnotation; }
    public String getEnclosingMethod() { return enclosingMethod; }
    public Set<String> getRootSources() { return Collections.unmodifiableSet(rootSources); }
    public Set<String> getDtoFields() { return Collections.unmodifiableSet(dtoFields); }
}