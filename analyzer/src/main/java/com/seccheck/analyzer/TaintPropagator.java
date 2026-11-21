// TaintPropagator.java
package com.seccheck.analyzer;

import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class TaintPropagator extends VoidVisitorAdapter<List<TaintedVariable>> {

    private final Set<String> taintedNames;

    public TaintPropagator(List<TaintedVariable> initialSources) {
        this.taintedNames = initialSources.stream()
                .map(TaintedVariable::getVariableName)
                .collect(Collectors.toSet());
    }

    @Override
    public void visit(VariableDeclarator declarator, List<TaintedVariable> collector) {
        super.visit(declarator, collector);

        if (declarator.getInitializer().isEmpty()) {
            return;
        }

        String newVarName = declarator.getNameAsString();
        if (taintedNames.contains(newVarName)) {
            return; // 이미 오염된 변수로 등록됨
        }

        Expression init = declarator.getInitializer().get();
        List<NameExpr> namesInExpr = init.findAll(NameExpr.class);

        for (NameExpr nameExpr : namesInExpr) {
            if (taintedNames.contains(nameExpr.getNameAsString())) {
                int line = declarator.getBegin().map(pos -> pos.line).orElse(-1);
                collector.add(new TaintedVariable(
                        newVarName,
                        declarator.getTypeAsString(),
                        line,
                        "derived from " + nameExpr.getNameAsString()
                ));
                taintedNames.add(newVarName); // 새로 오염된 변수도 다음 전파 대상에 포함
                break;
            }
        }
    }
}