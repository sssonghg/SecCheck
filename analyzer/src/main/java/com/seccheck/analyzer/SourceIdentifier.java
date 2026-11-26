package com.seccheck.analyzer;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;
import java.util.Set;

/**
 * 컨트롤러 메서드의 파라미터 중 "사용자가 보내는 값"을 Source 로 등록한다.
 * 판단 규칙은 ParamRules 에 있다 (ParamExtractor 와 공용).
 */
public class SourceIdentifier extends VoidVisitorAdapter<List<TaintedVariable>> {

    @Override
    public void visit(MethodDeclaration method, List<TaintedVariable> collector) {
        super.visit(method, collector);

        if (!ParamRules.isHandlerMethod(method)) {
            return;
        }

        int line = method.getBegin().map(pos -> pos.line).orElse(-1);

        for (Parameter param : method.getParameters()) {
            String sourceAnno = ParamRules.sourceAnnotation(param);
            if (sourceAnno == null) {
                continue;
            }
            collector.add(new TaintedVariable(
                    param.getNameAsString(),
                    param.getTypeAsString(),
                    line,
                    sourceAnno,
                    method.getNameAsString(),
                    Set.of(param.getNameAsString()),   // rootSources = 자기 자신
                    Set.of()
            ));
        }
    }
}