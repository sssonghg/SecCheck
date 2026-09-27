// Main.java (테스트 실행용)
package com.seccheck.analyzer;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
        File targetFile = new File("C:\\Users\\이서연\\intellij\\SecCheck\\vulnerable-app\\cmd-vuln-app\\src\\main\\java\\com\\vulnapp\\cmd_vuln_app\\controller\\CommandController.java");
        CompilationUnit cu = StaticJavaParser.parse(targetFile);

        List<TaintedVariable> results = new ArrayList<>();
        new SourceIdentifier().visit(cu, results);

        results.forEach(System.out::println);
    }
}