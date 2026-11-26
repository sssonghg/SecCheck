package com.seccheck.analyzer;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.github.javaparser.ParserConfiguration;
import com.seccheck.analyzer.endpoint.ContextPathResolver;
import com.seccheck.analyzer.endpoint.EndpointExtractor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public class Main {
    public static void main(String[] args) throws Exception {
        StaticJavaParser.getParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17);
        File targetFile = new File("C:\\Users\\seoyeon\\intellij\\SecCheck\\vulnerable-app\\spel-vuln-app\\src\\main\\java\\com\\vulnapp\\spel_vuln_app\\controller\\SpelController.java");
        CompilationUnit cu = StaticJavaParser.parse(targetFile);

        // Source 식별
        List<TaintedVariable> sourceResults = new ArrayList<>();
        new SourceIdentifier().visit(cu, sourceResults);

        // 변수 대입을 통해 전파된 오염 변수 추가 (예: name -> sql)
        new TaintPropagator(sourceResults).visit(cu, sourceResults);

        // Sink 식별
        List<SinkCall> sinkResults = new ArrayList<>();
        new SinkIdentifier().visit(cu, sinkResults);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        System.out.println("=== Source (전파 포함) ===");
        System.out.println(gson.toJson(sourceResults));
        System.out.println("=== Sink ===");
        System.out.println(gson.toJson(sinkResults));

        System.out.println("=== 취약점 판정 ===");
        boolean found = false;
        for (SinkCall sink : sinkResults) {
            for (TaintedVariable source : sourceResults) {
                // 같은 메서드 안에 있고(= 같은 반) + 변수 이름이 같을 때만 연결
                boolean sameMethod = sink.getEnclosingMethod().equals(source.getEnclosingMethod());
                boolean sameName = sink.getArgumentName().equals(source.getVariableName());

                if (sameMethod && sameName) {
                    System.out.println("취약점 발견: [" + sink.getEnclosingMethod() + "] "
                            + source.getVariableName()
                            + " (" + source.getSourceAnnotation() + ")"
                            + " -> " + sink.getMethodName()
                            + " (" + sink.getVulnerabilityType() + ", Line " + sink.getLineNumber() + ")");
                    found = true;
                }
            }
        }
        if (!found) {
            System.out.println("연결된 취약점 없음");
        }
        // ===== 4주차: Endpoint 추출 =====
        // 앱 폴더 (targetFile 이 속한 앱)
        Path projectRoot = Path.of("C:\\Users\\seoyeon\\intellij\\SecCheck\\vulnerable-app\\spel-vuln-app");

        // 앱 안의 모든 .java 파일 읽기 (다른 파일의 상수를 찾으려고)
        List<CompilationUnit> allUnits = new ArrayList<>();
        try (Stream<Path> files = Files.walk(projectRoot.resolve("src/main/java"))) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                allUnits.add(StaticJavaParser.parse(p));
            }
        }

        // 설정 파일에서 공통 경로 읽고 → 주소 뽑기
        String contextPath = ContextPathResolver.resolve(projectRoot);
        EndpointExtractor extractor = new EndpointExtractor(contextPath, allUnits);

        System.out.println("=== Endpoint ===");
        System.out.println("contextPath = \"" + contextPath + "\"");
        System.out.println(gson.toJson(extractor.extract(cu)));
    }
}