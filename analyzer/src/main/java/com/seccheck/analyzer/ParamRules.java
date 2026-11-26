package com.seccheck.analyzer;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * "컨트롤러 메서드의 어떤 파라미터가 사용자 입력인가" 규칙 모음.
 * SourceIdentifier 와 ParamExtractor 가 같은 규칙을 쓰도록 한 곳에 모아둔다.
 */
public final class ParamRules {

    /** 요청을 받는 메서드에 붙는 어노테이션 */
    public static final Set<String> MAPPING_ANNOTATIONS = Set.of(
            "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping");

    /** 사용자 입력 어노테이션 → 요청에서 값을 넣는 위치(in) */
    public static final Map<String, String> IN_BY_ANNOTATION = Map.of(
            "RequestParam", "query",     // ?name=값
            "PathVariable", "path",      // /users/{id}
            "RequestBody", "body",       // 본문
            "ModelAttribute", "query",   // ?필드=값 (DTO)
            "RequestHeader", "header",   // 헤더
            "CookieValue", "cookie",     // 쿠키
            "RequestPart", "body"        // multipart (파일 업로드 등)
    );

    /** 어노테이션이 없는 사용자 입력 파라미터의 sourceAnnotation 값 */
    public static final String IMPLICIT = "Implicit";

    /** 붙어 있으면 사용자 입력이 아닌 어노테이션 (서버 쪽 값) */
    private static final Set<String> NON_INPUT_ANNOTATIONS = Set.of(
            "AuthenticationPrincipal", "CurrentSecurityContext",
            "RequestAttribute", "SessionAttribute", "Value");

    /** 어노테이션 없이 써도 Spring 이 직접 넣어주는 타입 → 사용자 입력 아님 */
    private static final Set<String> SPRING_INJECTED = Set.of(
            "HttpServletRequest", "HttpServletResponse", "ServletRequest", "ServletResponse",
            "HttpSession", "WebRequest", "NativeWebRequest",
            "Model", "ModelMap", "ModelAndView", "Map", "RedirectAttributes", "SessionStatus",
            "BindingResult", "Errors",
            "Principal", "Authentication",
            "Locale", "TimeZone", "ZoneId",
            "UriComponentsBuilder", "HttpMethod",
            "OutputStream", "Writer"
    );

    private ParamRules() {
    }

    /** {@code @GetMapping} 등이 붙은, 요청을 받는 메서드인지 */
    public static boolean isHandlerMethod(MethodDeclaration method) {
        return method.getAnnotations().stream()
                .anyMatch(a -> MAPPING_ANNOTATIONS.contains(simpleName(a)));
    }

    /**
     * 사용자 입력이면 어노테이션 이름(또는 IMPLICIT), 아니면 null.
     * 예: @RequestParam String q → "RequestParam",  String q → "Implicit",  Model m → null
     */
    public static String sourceAnnotation(Parameter param) {
        for (AnnotationExpr anno : param.getAnnotations()) {
            String name = simpleName(anno);
            if (IN_BY_ANNOTATION.containsKey(name)) {
                return name;
            }
            if (NON_INPUT_ANNOTATIONS.contains(name)) {
                return null;
            }
        }
        // 어노테이션 없음 (@Valid 같은 검증용만 있는 경우 포함)
        if (SPRING_INJECTED.contains(simpleType(param.getTypeAsString()))) {
            return null;
        }
        return IMPLICIT;
    }

    public static Optional<AnnotationExpr> findAnnotation(Parameter param, String annotationName) {
        return param.getAnnotations().stream()
                .filter(a -> simpleName(a).equals(annotationName))
                .findFirst();
    }

    /** {@code @org.springframework...GetMapping} 처럼 전체 이름으로 써도 GetMapping 으로 */
    public static String simpleName(AnnotationExpr anno) {
        return anno.getName().getIdentifier();
    }

    /** "java.util.Map<String, Object>" → "Map" */
    public static String simpleType(String type) {
        String noGeneric = type.replaceAll("<.*>", "").trim();
        int dot = noGeneric.lastIndexOf('.');
        return dot < 0 ? noGeneric : noGeneric.substring(dot + 1);
    }
}
