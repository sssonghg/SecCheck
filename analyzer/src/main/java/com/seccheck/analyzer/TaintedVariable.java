// TaintedVariable.java
package com.seccheck.analyzer;
public class TaintedVariable {
    private final String variableName;
    private final String type;
    private final int lineNumber;
    private final String sourceAnnotation;

    public TaintedVariable(String variableName, String type, int lineNumber, String sourceAnnotation) {
        this.variableName = variableName;
        this.type = type;
        this.lineNumber = lineNumber;
        this.sourceAnnotation = sourceAnnotation;
    }

    @Override
    public String toString() {
        return String.format("[Line %d] %s %s (from @%s)",
                lineNumber, type, variableName, sourceAnnotation);
    }

    public String getVariableName() { return variableName; }
    public String getSourceAnnotation() { return sourceAnnotation; }
}
