// SourceIdentifier.java
package com.seccheck.analyzer;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;

public class SourceIdentifier extends VoidVisitorAdapter<List<TaintedVariable>> {

    private static final List<String> METHOD_ANNOTATIONS =
            List.of("GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "RequestMapping");

    private static final List<String> PARAM_ANNOTATIONS =
            List.of("RequestParam", "RequestBody", "PathVariable");

    @Override
    public void visit(MethodDeclaration method, List<TaintedVariable> collector) {
        super.visit(method, collector);

        if (!hasControllerAnnotation(method)) {
            return;
        }

        int line = method.getBegin().map(pos -> pos.line).orElse(-1);

        for (Parameter param : method.getParameters()) {
            String sourceAnno = findSourceAnnotation(param);
            if (sourceAnno != null) {
                collector.add(new TaintedVariable(
                        param.getNameAsString(),
                        param.getTypeAsString(),
                        line,
                        sourceAnno
                ));
            }
        }
    }

    private boolean hasControllerAnnotation(MethodDeclaration method) {
        for (AnnotationExpr anno : method.getAnnotations()) {
            if (METHOD_ANNOTATIONS.contains(anno.getNameAsString())) {
                return true;
            }
        }
        return false;
    }

    private String findSourceAnnotation(Parameter param) {
        for (AnnotationExpr anno : param.getAnnotations()) {
            String name = anno.getNameAsString();
            if (PARAM_ANNOTATIONS.contains(name)) {
                return name;
            }
        }
        return null;
    }
}