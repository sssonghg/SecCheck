package com.seccheck.analyzer;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class TaintPropagator extends VoidVisitorAdapter<List<TaintedVariable>> {

    // "메서드이름#변수이름" 형태로 저장 → 1반 철수, 2반 철수를 구분
    private final Set<String> taintedKeys;

    public TaintPropagator(List<TaintedVariable> initialSources) {
        this.taintedKeys = initialSources.stream()
                .map(v -> key(v.getEnclosingMethod(), v.getVariableName()))
                .collect(Collectors.toCollection(HashSet::new));
    }

    private static String key(String method, String variable) {
        return method + "#" + variable;
    }

    @Override
    public void visit(VariableDeclarator declarator, List<TaintedVariable> collector) {
        super.visit(declarator, collector);

        if (declarator.getInitializer().isEmpty()) {
            return;
        }

        String method = declarator.findAncestor(MethodDeclaration.class)
                .map(MethodDeclaration::getNameAsString)
                .orElse("(unknown)");

        String newVarName = declarator.getNameAsString();
        if (taintedKeys.contains(key(method, newVarName))) {
            return; // 같은 메서드 안에서 이미 오염된 변수로 등록됨
        }

        Expression init = declarator.getInitializer().get();
        List<NameExpr> namesInExpr = init.findAll(NameExpr.class);

        for (NameExpr nameExpr : namesInExpr) {
            // 같은 메서드 안의 오염 변수인지 확인
            if (taintedKeys.contains(key(method, nameExpr.getNameAsString()))) {
                int line = declarator.getBegin().map(pos -> pos.line).orElse(-1);
                collector.add(new TaintedVariable(
                        newVarName,
                        declarator.getTypeAsString(),
                        line,
                        "derived from " + nameExpr.getNameAsString(),
                        method
                ));
                taintedKeys.add(key(method, newVarName));
                break;
            }
        }
    }
}