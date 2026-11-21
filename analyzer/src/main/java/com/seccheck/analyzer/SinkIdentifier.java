package com.seccheck.analyzer;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;
import java.util.Map;

public class SinkIdentifier extends VoidVisitorAdapter<List<SinkCall>> {

    private static final Map<String, String> SINK_METHODS = Map.of(
            "exec", "Command Injection",
            "parseExpression", "SpEL Injection",
            "queryForList", "SQL Injection",
            "query", "SQL Injection"
    );

    @Override
    public void visit(MethodCallExpr call, List<SinkCall> collector) {
        super.visit(call, collector);

        String methodName = call.getNameAsString();
        if (!SINK_METHODS.containsKey(methodName)) {
            return;
        }

        int line = call.getBegin().map(pos -> pos.line).orElse(-1);

        // 이 호출을 감싸고 있는 메서드를 트리에서 위로 올라가며 찾음
        String enclosingMethod = call.findAncestor(MethodDeclaration.class)
                .map(MethodDeclaration::getNameAsString)
                .orElse("(unknown)");

        for (Expression arg : call.getArguments()) {
            collector.add(new SinkCall(
                    methodName,
                    SINK_METHODS.get(methodName),
                    arg.toString(),
                    line,
                    enclosingMethod
            ));
        }
    }
}