package com.seccheck.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.RecordDeclaration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 프로젝트 안의 클래스/record 필드 목록.
 * TaintPropagator(getter 전파)와 ParamExtractor(DTO fields)가 같이 쓴다.
 */
public class DtoIndex {

    /** 클래스 이름 → (필드 이름 → 필드 타입) */
    private final Map<String, Map<String, String>> fieldsByType = new HashMap<>();
    /** 클래스 이름 → 부모 클래스 이름 */
    private final Map<String, String> parentByType = new HashMap<>();

    public DtoIndex(List<CompilationUnit> allUnits) {
        for (CompilationUnit cu : allUnits) {
            for (ClassOrInterfaceDeclaration c : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                if (c.isInterface()) {
                    continue;
                }
                Map<String, String> fields = new LinkedHashMap<>();
                for (FieldDeclaration f : c.getFields()) {
                    if (!f.isStatic()) {
                        f.getVariables().forEach(v -> fields.put(v.getNameAsString(), v.getTypeAsString()));
                    }
                }
                fieldsByType.put(c.getNameAsString(), fields);
                c.getExtendedTypes().stream().findFirst()
                        .ifPresent(parent -> parentByType.put(c.getNameAsString(), parent.getNameAsString()));
            }
            for (RecordDeclaration r : cu.findAll(RecordDeclaration.class)) {   // record JoinRequest(String username, ...)
                Map<String, String> fields = new LinkedHashMap<>();
                r.getParameters().forEach(p -> fields.put(p.getNameAsString(), p.getTypeAsString()));
                fieldsByType.put(r.getNameAsString(), fields);
            }
        }
    }

    /** 프로젝트 안에 있는 클래스인지 */
    public boolean isKnown(String type) {
        return fieldsByType.containsKey(ParamRules.simpleType(type));
    }

    /** 부모 클래스까지 올라가며 필드가 있는지 */
    public boolean hasField(String type, String field) {
        return fields(type).containsKey(field);
    }

    /** 필드 이름 → 타입. 부모 클래스 필드 먼저, 자기 필드 나중 */
    public Map<String, String> fields(String type) {
        List<String> chain = new ArrayList<>();
        String current = ParamRules.simpleType(type);
        for (int depth = 0; current != null && depth < 10; depth++) {
            chain.add(current);
            current = parentByType.get(current);
        }
        Collections.reverse(chain);

        Map<String, String> result = new LinkedHashMap<>();
        for (String t : chain) {
            result.putAll(fieldsByType.getOrDefault(t, Map.of()));
        }
        return result;
    }
}
