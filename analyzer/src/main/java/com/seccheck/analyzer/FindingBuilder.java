package com.seccheck.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.seccheck.analyzer.endpoint.EndpointInfo;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 판정 결과(TaintedSink) 1건에 Endpoint, Params, 위치, 경로, 코드 원문을 붙여서 findings[] 한 건을 만든다.
 * 컨트롤러 파일(CompilationUnit) 하나당 하나씩 만든다.
 */
public class FindingBuilder {

    private final String relativeFile;
    private final CompilationUnit cu;
    private final List<TaintedVariable> taints;
    private final List<EndpointInfo> endpoints;
    private final ParamExtractor paramExtractor;

    /**
     * @param projectRoot    앱 폴더
     * @param file           이 컨트롤러 파일 경로
     * @param cu             이 컨트롤러 파일
     * @param taints         이 파일의 Source + 전파 결과
     * @param endpoints      이 파일의 EndpointExtractor 결과
     * @param paramExtractor 파라미터 추출기
     */
    public FindingBuilder(Path projectRoot, Path file, CompilationUnit cu, List<TaintedVariable> taints,
                          List<EndpointInfo> endpoints, ParamExtractor paramExtractor) {
        this.relativeFile = projectRoot.relativize(file).toString().replace('\\', '/');
        this.cu = cu;
        this.taints = taints;
        this.endpoints = endpoints;
        this.paramExtractor = paramExtractor;
    }

    /** 판정 결과 1건 → findings[] 1건. 컨트롤러 메서드를 못 찾으면 empty */
    @SuppressWarnings("unchecked")
    public Optional<Finding> build(TaintedSink ts, String findingId) {
        SinkCall sink = ts.sink();

        // Sink 가 들어 있는 메서드 (이름 + 줄 범위로 찾아서 오버로딩도 구분)
        MethodDeclaration method = findMethod(sink.getEnclosingMethod(), sink.getLineNumber()).orElse(null);
        if (method == null) {
            return Optional.empty();
        }
        int startLine = method.getBegin().map(p -> p.line).orElse(-1);
        int endLine = method.getEnd().map(p -> p.line).orElse(-1);
        String className = method.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(ClassOrInterfaceDeclaration::getNameAsString).orElse("(unknown)");

        // 2번 결과: 같은 클래스 + 메서드 이름 + 시작 줄
        EndpointInfo ep = endpoints.stream()
                .filter(e -> e.className().equals(className)
                        && e.methodName().equals(method.getNameAsString())
                        && e.methodLine() == startLine)
                .findFirst().orElse(null);
        if (ep == null) {
            return Optional.empty(); // 요청을 받는 메서드가 아님
        }

        // 3번 결과: 이 Sink 하나 기준으로 tainted 표시
        List<ParamInfo> params = paramExtractor.extract(method, List.of(ts));

        return Optional.of(new Finding(
                findingId,
                toVulnType(sink.getVulnerabilityType()),
                new Finding.Endpoint(ep.httpMethods(), ep.paths(), ep.consumes(), params),
                new Finding.Location(relativeFile, className, method.getNameAsString(), startLine, endLine),
                new Finding.Sink(sink.getMethodName(), sink.getLineNumber(), sinkCode(sink)),
                taintPath(ts),
                method.toString()
        ));
    }

    // ------------------------------------------------------------------ taintPath

    /**
     * Sink 인자에 들어간 변수(vias)에서 거꾸로 "derived from" 을 따라가서 경로를 만든다.
     *   sql (derived from name) ← name (RequestParam)
     *   → [name SOURCE] → [sql PROPAGATION] → [sql SINK_ARG]
     */
    private List<Finding.PathStep> taintPath(TaintedSink ts) {
        String method = ts.sink().getEnclosingMethod();
        List<TaintedVariable> involved = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>(ts.vias());

        while (!queue.isEmpty()) {
            String var = baseVar(queue.poll());          // "req.username" → "req"
            if (!visited.add(var)) {
                continue;
            }
            for (TaintedVariable v : taints) {
                if (v.getEnclosingMethod().equals(method) && v.getVariableName().equals(var)) {
                    involved.add(v);
                    String label = v.getSourceAnnotation();
                    if (label.startsWith("derived from ")) {
                        for (String parent : label.substring("derived from ".length()).split(",\\s*")) {
                            queue.add(parent);
                        }
                    }
                }
            }
        }

        List<Finding.PathStep> steps = new ArrayList<>();
        involved.stream()
                .sorted(Comparator.comparingInt(TaintedVariable::getLineNumber))
                .forEach(v -> steps.add(new Finding.PathStep(
                        v.getVariableName(), v.getLineNumber(),
                        v.getSourceAnnotation().startsWith("derived from ") ? "PROPAGATION" : "SOURCE")));
        steps.add(new Finding.PathStep(ts.sink().getArgumentName(), ts.sink().getLineNumber(), "SINK_ARG"));
        return steps;
    }

    private static String baseVar(String via) {
        int dot = via.indexOf('.');
        return dot < 0 ? via : via.substring(0, dot);
    }

    // ------------------------------------------------------------------ 유틸

    private Optional<MethodDeclaration> findMethod(String name, int line) {
        return cu.findAll(MethodDeclaration.class).stream()
                .filter(m -> m.getNameAsString().equals(name))
                .filter(m -> m.getBegin().map(p -> p.line <= line).orElse(false)
                        && m.getEnd().map(p -> p.line >= line).orElse(false))
                .findFirst();
    }

    /** Sink 호출 한 줄 코드: 인자 식의 부모 = 호출 식 (jdbcTemplate.queryForList(sql)) */
    private static String sinkCode(SinkCall sink) {
        if (sink.getArgumentExpr() == null) {
            return sink.getMethodName();
        }
        return sink.getArgumentExpr().getParentNode().map(Node::toString).orElse(sink.getArgumentName());
    }

    /** "SQL Injection" → "SQL_INJECTION" */
    private static String toVulnType(String type) {
        return type.trim().toUpperCase().replace(' ', '_');
    }
}