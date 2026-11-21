// Main.java
package com.seccheck.analyzer;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
        File targetFile = new File("C:\\Users\\이서연\\intellij\\SecCheck\\vulnerable-app\\sql-vuln-app\\src\\main\\java\\com\\vulnapp\\sql_vuln_app\\controller\\SqlController.java");
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
                if (sink.getArgumentName().equals(source.getVariableName())) {
                    System.out.println("취약점 발견: " + source.getVariableName()
                            + " (" + source.getSourceAnnotation() + ")"
                            + " -> " + sink.getMethodName()
                            + " (" + sink.getVulnerabilityType() + ")");
                    found = true;
                }
            }
        }
        if (!found) {
            System.out.println("연결된 취약점 없음");
        }
    }
}