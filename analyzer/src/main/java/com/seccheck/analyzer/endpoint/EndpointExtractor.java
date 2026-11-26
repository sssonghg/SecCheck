package com.seccheck.analyzer.endpoint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 컨트롤러 코드의 어노테이션을 읽어서 "어디로(경로), 어떻게(HTTP 메서드, body 형식)" 보내는지 뽑는다.
 *
 * 처리하는 형태:
 *  - 클래스 @RequestMapping + 메서드 매핑 경로 합치기
 *  - @GetMapping / @PostMapping / @PutMapping / @DeleteMapping / @PatchMapping
 *  - @RequestMapping(method = RequestMethod.POST), method 배열, method 없음(= 전부 허용)
 *  - value / path 속성, 경로 배열 {"/a", "/b"}
 *  - 상수로 쓴 경로 (같은 클래스 상수, 다른 클래스 상수 ApiPaths.USERS, "/a" + BASE 같은 문자열 더하기)
 *  - consumes (문자열, MediaType.APPLICATION_JSON_VALUE 같은 상수)
 *  - context-path (ContextPathResolver 결과를 생성자로 받음)
 */
public class EndpointExtractor {

    private static final List<String> ALL_METHODS = List.of("GET", "POST", "PUT", "DELETE", "PATCH");

    private static final Map<String, String> SHORTCUT_MAPPINGS = Map.of(
            "GetMapping", "GET",
            "PostMapping", "POST",
            "PutMapping", "PUT",
            "DeleteMapping", "DELETE",
            "PatchMapping", "PATCH"
    );

    /** Spring MediaType 상수 → 실제 문자열 */
    private static final Map<String, String> MEDIA_TYPES = Map.of(
            "APPLICATION_JSON_VALUE", "application/json",
            "APPLICATION_FORM_URLENCODED_VALUE", "application/x-www-form-urlencoded",
            "MULTIPART_FORM_DATA_VALUE", "multipart/form-data",
            "TEXT_PLAIN_VALUE", "text/plain",
            "APPLICATION_XML_VALUE", "application/xml"
    );

    private static final int MAX_CONSTANT_DEPTH = 10;

    private final String contextPath;
    /** "클래스명.상수명" → 초기값 표현식 */
    private final Map<String, Expression> constants = new HashMap<>();

    /**
     * @param contextPath ContextPathResolver.resolve(...) 결과 ("" 가능)
     * @param allUnits    프로젝트 전체 CompilationUnit (다른 클래스 상수를 찾으려고 필요)
     */
    public EndpointExtractor(String contextPath, List<CompilationUnit> allUnits) {
        this.contextPath = contextPath == null ? "" : contextPath;
        for (CompilationUnit cu : allUnits) {
            indexConstants(cu);
        }
    }

    /** 파일 1개에서 엔드포인트 목록 추출 */
    public List<EndpointInfo> extract(CompilationUnit cu) {
        List<EndpointInfo> result = new ArrayList<>();
        for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            if (!isController(clazz)) {
                continue;
            }
            String className = clazz.getNameAsString();
            Mapping classMapping = findMapping(clazz, className).orElse(Mapping.empty());

            for (MethodDeclaration method : clazz.getMethods()) {
                findMapping(method, className)
                        .ifPresent(m -> result.add(combine(className, method, classMapping, m)));
            }
        }
        return result;
    }

    // ------------------------------------------------------------------ 컨트롤러 판별

    private boolean isController(ClassOrInterfaceDeclaration clazz) {
        return clazz.getAnnotations().stream()
                .map(this::simpleName)
                .anyMatch(n -> n.equals("RestController") || n.equals("Controller"));
    }

    // ------------------------------------------------------------------ 매핑 어노테이션 읽기

    /** 어노테이션 1개에서 읽은 경로 / HTTP 메서드 / consumes */
    private record Mapping(List<String> paths, List<String> methods, List<String> consumes,
                           List<String> unresolved) {
        static Mapping empty() {
            return new Mapping(List.of(""), List.of(), List.of(), List.of());
        }
    }

    private Optional<Mapping> findMapping(NodeWithAnnotations<?> node, String className) {
        for (AnnotationExpr a : node.getAnnotations()) {
            String name = simpleName(a);
            boolean isShortcut = SHORTCUT_MAPPINGS.containsKey(name);
            if (!isShortcut && !name.equals("RequestMapping")) {
                continue;
            }

            List<String> unresolved = new ArrayList<>();

            // 경로: value 또는 path. 없으면 "" (클래스 경로 그대로)
            List<String> paths = attribute(a, "value", "path")
                    .map(e -> resolveStrings(e, className, unresolved, 0))
                    .orElse(List.of());
            if (paths.isEmpty()) {
                paths = List.of("");
            }

            // HTTP 메서드: 전용 어노테이션이면 이름으로, @RequestMapping 이면 method 속성으로
            List<String> methods = isShortcut
                    ? List.of(SHORTCUT_MAPPINGS.get(name))
                    : attribute(a, "method").map(this::resolveEnumNames).orElse(List.of());

            List<String> consumes = attribute(a, "consumes")
                    .map(e -> resolveStrings(e, className, unresolved, 0))
                    .orElse(List.of());

            return Optional.of(new Mapping(paths, methods, consumes, unresolved));
        }
        return Optional.empty();
    }

    /** {@code @GetMapping("/x")} 처럼 이름 없이 쓴 값은 value 로 취급 */
    private Optional<Expression> attribute(AnnotationExpr a, String... keys) {
        if (a instanceof SingleMemberAnnotationExpr single) {
            return List.of(keys).contains("value") ? Optional.of(single.getMemberValue()) : Optional.empty();
        }
        if (a instanceof NormalAnnotationExpr normal) {
            for (MemberValuePair pair : normal.getPairs()) {
                if (List.of(keys).contains(pair.getNameAsString())) {
                    return Optional.of(pair.getValue());
                }
            }
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------ 값 해석

    /** RequestMethod.POST / POST(static import) / {GET, POST} → ["POST"] ... */
    private List<String> resolveEnumNames(Expression e) {
        if (e instanceof ArrayInitializerExpr arr) {
            List<String> out = new ArrayList<>();
            arr.getValues().forEach(v -> out.addAll(resolveEnumNames(v)));
            return out;
        }
        if (e instanceof FieldAccessExpr fa) {
            return List.of(fa.getNameAsString());
        }
        if (e instanceof NameExpr ne) {
            return List.of(ne.getNameAsString());
        }
        return List.of();
    }

    /** 문자열 표현식을 실제 값으로. 못 알아내면 unresolved 에 기록하고 원문을 그대로 둔다. */
    private List<String> resolveStrings(Expression e, String currentClass, List<String> unresolved, int depth) {
        if (depth > MAX_CONSTANT_DEPTH) {
            unresolved.add(e.toString());
            return List.of(e.toString());
        }
        if (e instanceof StringLiteralExpr s) {
            return List.of(s.getValue());
        }
        if (e instanceof EnclosedExpr enc) {
            return resolveStrings(enc.getInner(), currentClass, unresolved, depth);
        }
        if (e instanceof ArrayInitializerExpr arr) {
            List<String> out = new ArrayList<>();
            arr.getValues().forEach(v -> out.addAll(resolveStrings(v, currentClass, unresolved, depth)));
            return out;
        }
        if (e instanceof BinaryExpr bin && bin.getOperator() == BinaryExpr.Operator.PLUS) {
            List<String> left = resolveStrings(bin.getLeft(), currentClass, unresolved, depth);
            List<String> right = resolveStrings(bin.getRight(), currentClass, unresolved, depth);
            List<String> out = new ArrayList<>();
            for (String l : left) {
                for (String r : right) {
                    out.add(l + r);
                }
            }
            return out;
        }
        if (e instanceof NameExpr || e instanceof FieldAccessExpr) {
            String fieldName = e instanceof NameExpr ne ? ne.getNameAsString()
                    : ((FieldAccessExpr) e).getNameAsString();

            if (MEDIA_TYPES.containsKey(fieldName)) {
                return List.of(MEDIA_TYPES.get(fieldName));
            }

            String ownerClass = e instanceof FieldAccessExpr fa ? lastIdentifier(fa.getScope().toString())
                    : currentClass;
            Expression init = constants.get(ownerClass + "." + fieldName);
            if (init == null && e instanceof NameExpr) {
                init = findUniqueConstant(fieldName); // static import 된 상수
            }
            if (init != null) {
                return resolveStrings(init, ownerClass, unresolved, depth + 1);
            }
        }
        unresolved.add(e.toString());
        return List.of(e.toString());
    }

    private void indexConstants(CompilationUnit cu) {
        for (ClassOrInterfaceDeclaration type : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            for (FieldDeclaration field : type.getFields()) {
                for (VariableDeclarator v : field.getVariables()) {
                    v.getInitializer().ifPresent(init ->
                            constants.put(type.getNameAsString() + "." + v.getNameAsString(), init));
                }
            }
        }
    }

    /** 상수 이름만으로 찾을 때: 프로젝트에 하나뿐일 때만 인정 (여러 개면 어느 건지 모름) */
    private Expression findUniqueConstant(String fieldName) {
        Expression found = null;
        for (Map.Entry<String, Expression> entry : constants.entrySet()) {
            if (entry.getKey().endsWith("." + fieldName)) {
                if (found != null) {
                    return null;
                }
                found = entry.getValue();
            }
        }
        return found;
    }

    // ------------------------------------------------------------------ 클래스 + 메서드 합치기

    private EndpointInfo combine(String className, MethodDeclaration method, Mapping classMapping, Mapping methodMapping) {
        // 경로: 클래스 경로 × 메서드 경로 (둘 다 여러 개일 수 있음)
        Set<String> paths = new LinkedHashSet<>();
        for (String cp : classMapping.paths()) {
            for (String mp : methodMapping.paths()) {
                paths.add(joinPath(contextPath, cp, mp));
            }
        }

        // HTTP 메서드: Spring 은 클래스 + 메서드 지정을 합친다. 둘 다 없으면 전부 허용
        Set<String> methods = new LinkedHashSet<>(classMapping.methods());
        methods.addAll(methodMapping.methods());
        List<String> httpMethods = methods.isEmpty() ? ALL_METHODS : List.copyOf(methods);

        // consumes: 메서드에 있으면 메서드 것, 없으면 클래스 것 (Spring 동작과 동일)
        List<String> consumes = !methodMapping.consumes().isEmpty()
                ? methodMapping.consumes() : classMapping.consumes();

        List<String> unresolved = new ArrayList<>(classMapping.unresolved());
        unresolved.addAll(methodMapping.unresolved());

        int line = method.getBegin().map(p -> p.line).orElse(-1);
        return new EndpointInfo(className, method.getNameAsString(), line,
                httpMethods, List.copyOf(paths), consumes, unresolved);
    }

    /** "/ctx", "api/", "/ping" → "/ctx/api/ping" (슬래시 중복·누락 정리) */
    static String joinPath(String... parts) {
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            if (part == null) {
                continue;
            }
            String trimmed = part.replaceAll("^/+", "").replaceAll("/+$", "");
            if (!trimmed.isEmpty()) {
                sb.append('/').append(trimmed);
            }
        }
        return sb.isEmpty() ? "/" : sb.toString();
    }

    // ------------------------------------------------------------------ 유틸

    /** {@code @org.springframework...GetMapping} 처럼 전체 이름으로 써도 GetMapping 으로 */
    private String simpleName(AnnotationExpr a) {
        return a.getName().getIdentifier();
    }

    private String lastIdentifier(String qualified) {
        int dot = qualified.lastIndexOf('.');
        return dot < 0 ? qualified : qualified.substring(dot + 1);
    }
}
