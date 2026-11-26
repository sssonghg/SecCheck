package com.seccheck.analyzer;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 컨트롤러 메서드 하나의 파라미터들을 JSON params[] 형태로 뽑는다.
 *
 * 파라미터마다:
 *   1. 사용자 입력인지 (ParamRules.sourceAnnotation) → 아니면 건너뜀
 *   2. in       : 어노테이션 종류 (없으면 query)
 *   3. name     : @RequestParam("q") / value= / name= / 없으면 변수명
 *   4. required : required=false, defaultValue, Optional 이면 false
 *   5. fields   : DTO 면 필드 목록
 *   6. tainted  : 오염된 Sink(TaintedSink)의 rootSources / dtoFields 에 들어 있는지
 */
public class ParamExtractor {

    /** 이름표를 어노테이션 value/name 으로 바꿀 수 있는 어노테이션 */
    private static final Set<String> NAMED_ANNOTATIONS = Set.of(
            "RequestParam", "PathVariable", "RequestHeader", "CookieValue", "RequestPart");

    /** DTO 로 풀어볼 수 있는 어노테이션 (값이 여러 칸으로 들어오는 경우) */
    private static final Set<String> DTO_CAPABLE = Set.of(
            "RequestBody", "ModelAttribute", ParamRules.IMPLICIT);

    /** 값 하나로 받는 타입 → DTO 아님 */
    private static final Set<String> SIMPLE_TYPES = Set.of(
            "String", "CharSequence", "Object",
            "Integer", "Long", "Double", "Float", "Short", "Byte", "Boolean", "Character",
            "int", "long", "double", "float", "short", "byte", "boolean", "char",
            "BigDecimal", "BigInteger", "UUID",
            "LocalDate", "LocalDateTime", "LocalTime", "Date", "Instant", "ZonedDateTime", "OffsetDateTime",
            "MultipartFile", "List", "Set", "Collection", "Optional", "Map", "JsonNode"
    );

    private final DtoIndex dtoIndex;

    public ParamExtractor(DtoIndex dtoIndex) {
        this.dtoIndex = dtoIndex;
    }

    /**
     * @param method       컨트롤러 메서드
     * @param taintedSinks TaintPropagator.evaluateSinks(...) 결과 (취약점 판정)
     */
    public List<ParamInfo> extract(MethodDeclaration method, List<TaintedSink> taintedSinks) {
        // 6번 준비: 이 메서드의 오염된 Sink 에 들어간 처음 파라미터 / DTO 필드
        String methodName = method.getNameAsString();
        Set<String> taintedRoots = new HashSet<>();
        Set<String> taintedFields = new HashSet<>();
        for (TaintedSink ts : taintedSinks) {
            if (ts.sink().getEnclosingMethod().equals(methodName)) {
                taintedRoots.addAll(ts.rootSources());
                taintedFields.addAll(ts.dtoFields());
            }
        }

        List<ParamInfo> result = new ArrayList<>();
        for (Parameter param : method.getParameters()) {
            String source = ParamRules.sourceAnnotation(param);                       // 1
            if (source == null) {
                continue;
            }
            AnnotationExpr anno = ParamRules.findAnnotation(param, source).orElse(null);
            String varName = param.getNameAsString();
            String type = param.getTypeAsString();

            String in = source.equals(ParamRules.IMPLICIT)                             // 2
                    ? "query" : ParamRules.IN_BY_ANNOTATION.get(source);
            String name = NAMED_ANNOTATIONS.contains(source)                           // 3
                    ? orElse(stringAttr(anno, "value", "name"), varName) : varName;
            String defaultValue = stringAttr(anno, "defaultValue");
            boolean required = isRequired(source, anno, defaultValue, type);           // 4
            List<ParamInfo.FieldInfo> fields = fieldsOf(source, type, varName, taintedFields);   // 5
            boolean tainted = taintedRoots.contains(varName);                          // 6

            result.add(new ParamInfo(name, in, type, required, defaultValue, tainted, fields));
        }
        return result;
    }

    // ------------------------------------------------------------------ 4. required

    private boolean isRequired(String source, AnnotationExpr anno, String defaultValue, String type) {
        if (ParamRules.simpleType(type).equals("Optional")) {
            return false;                                   // Optional<String> q
        }
        if (source.equals(ParamRules.IMPLICIT) || source.equals("ModelAttribute")) {
            return false;                                   // 어노테이션 없음 / DTO 바인딩은 필수 아님
        }
        Expression required = attr(anno, "required");
        if (required instanceof BooleanLiteralExpr b) {
            return b.getValue();                            // required = false
        }
        return defaultValue == null;                        // defaultValue 가 있으면 필수 아님
    }

    // ------------------------------------------------------------------ 5. DTO fields

    private List<ParamInfo.FieldInfo> fieldsOf(String source, String type, String varName, Set<String> taintedFields) {
        if (!DTO_CAPABLE.contains(source)) {
            return null;
        }
        String simple = ParamRules.simpleType(type);
        if (SIMPLE_TYPES.contains(simple) || type.endsWith("[]") || !dtoIndex.isKnown(simple)) {
            return null;   // @RequestBody String expr → 본문에 글자 그대로, 프로젝트 밖 클래스는 필드를 모름
        }
        List<ParamInfo.FieldInfo> fields = new ArrayList<>();
        for (Map.Entry<String, String> f : dtoIndex.fields(simple).entrySet()) {
            boolean tainted = taintedFields.contains(varName + "." + f.getKey());
            fields.add(new ParamInfo.FieldInfo(f.getKey(), f.getValue(), tainted));
        }
        return fields;
    }

    // ------------------------------------------------------------------ 어노테이션 속성 읽기

    /** {@code @RequestParam("q")} 처럼 이름 없이 쓴 값은 value 로 취급 */
    private Expression attr(AnnotationExpr anno, String... keys) {
        if (anno instanceof SingleMemberAnnotationExpr single) {
            return List.of(keys).contains("value") ? single.getMemberValue() : null;
        }
        if (anno instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                if (List.of(keys).contains(pair.getNameAsString())) {
                    return pair.getValue();
                }
            }
        }
        return null;
    }

    private String stringAttr(AnnotationExpr anno, String... keys) {
        Expression e = attr(anno, keys);
        if (e instanceof StringLiteralExpr s) {
            return s.getValue();
        }
        return e == null ? null : e.toString();   // 상수 등은 원문 그대로
    }

    private static String orElse(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }
}