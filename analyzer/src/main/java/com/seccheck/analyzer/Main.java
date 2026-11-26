package com.seccheck.analyzer;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.seccheck.analyzer.endpoint.ContextPathResolver;
import com.seccheck.analyzer.endpoint.EndpointExtractor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * 실행: Main [앱 폴더] [결과 파일]
 *   - 앱 폴더를 안 주면 DEFAULT_APP
 *   - 결과 파일을 안 주면 analyzer/output/앱폴더이름-analysis.json
 */
public class Main {

    private static final String DEFAULT_APP =
            "C:\\Users\\seoyeon\\intellij\\SecCheck\\vulnerable-app\\sql-vuln-app";

    public static void main(String[] args) throws Exception {
        StaticJavaParser.getParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17);

        Path projectRoot = Path.of(args.length > 0 ? args[0] : DEFAULT_APP);
        String projectName = projectRoot.getFileName().toString();
        Path output = args.length > 1
                ? Path.of(args[1])
                : analyzerRoot().resolve("output").resolve(projectName + "-analysis.json");

        // 1. 앱 안의 모든 .java 파일 읽기 (파일 경로 ↔ 코드 트리)
        Map<Path, CompilationUnit> units = new LinkedHashMap<>();
        try (Stream<Path> files = Files.walk(projectRoot.resolve("src/main/java"))) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).sorted().toList()) {
                units.put(p, StaticJavaParser.parse(p));
            }
        }
        List<CompilationUnit> allUnits = new ArrayList<>(units.values());

        // 2. 앱 전체에서 한 번만 만들면 되는 것들
        DtoIndex dtoIndex = new DtoIndex(allUnits);
        ParamExtractor paramExtractor = new ParamExtractor(dtoIndex);
        String contextPath = ContextPathResolver.resolve(projectRoot);
        EndpointExtractor endpointExtractor = new EndpointExtractor(contextPath, allUnits);

        // 3. 요청을 받는 메서드가 있는 파일(컨트롤러)마다 분석
        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<Path, CompilationUnit> entry : units.entrySet()) {
            CompilationUnit cu = entry.getValue();
            boolean isController = cu.findAll(MethodDeclaration.class).stream()
                    .anyMatch(ParamRules::isHandlerMethod);
            if (!isController) {
                continue;
            }

            List<TaintedVariable> taints = new ArrayList<>();
            new SourceIdentifier().visit(cu, taints);
            TaintPropagator propagator = new TaintPropagator(taints, dtoIndex);
            propagator.visit(cu, taints);

            List<SinkCall> sinks = new ArrayList<>();
            new SinkIdentifier().visit(cu, sinks);
            List<TaintedSink> taintedSinks = propagator.evaluateSinks(sinks);

            FindingBuilder builder = new FindingBuilder(projectRoot, entry.getKey(), cu, taints,
                    endpointExtractor.extract(cu), paramExtractor);
            for (TaintedSink ts : taintedSinks) {
                String id = String.format("F-%03d", findings.size() + 1);
                builder.build(ts, id).ifPresent(findings::add);
            }
        }

        // 4. 결과 파일 저장
        Finding.AnalysisResult result = new Finding.AnalysisResult("1.1", projectName, findings);
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        if (output.toAbsolutePath().getParent() != null) {
            Files.createDirectories(output.toAbsolutePath().getParent());   // output 폴더 없으면 만들기
        }
        Files.writeString(output, gson.toJson(result));

        // 5. 콘솔 요약
        System.out.println("=== " + projectName + " 분석 결과: " + findings.size() + "건 ===");
        for (Finding f : findings) {
            System.out.printf("%s  %-17s %-6s %-28s %s.%s (Line %d)%n",
                    f.findingId(), f.vulnType(),
                    String.join(",", f.endpoint().httpMethods()),
                    String.join(", ", f.endpoint().paths()),
                    f.location().className(), f.location().method(), f.sink().line());
        }
        System.out.println("저장: " + output.toAbsolutePath());
    }

    /**
     * analyzer 프로젝트 폴더 찾기.
     * 실행 중인 Main.class 위치(analyzer/build/classes/...)에서 위로 올라가며
     * build.gradle 과 src 가 있는 폴더를 찾는다. 어디서 실행하든 결과가 analyzer/output 에 모이게.
     */
    private static Path analyzerRoot() {
        try {
            Path location = Path.of(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            for (Path cur = location; cur != null; cur = cur.getParent()) {
                if (Files.exists(cur.resolve("build.gradle")) && Files.isDirectory(cur.resolve("src"))) {
                    return cur;
                }
            }
        } catch (Exception ignored) {
            // 못 찾으면 현재 폴더
        }
        return Path.of("").toAbsolutePath();
    }
}