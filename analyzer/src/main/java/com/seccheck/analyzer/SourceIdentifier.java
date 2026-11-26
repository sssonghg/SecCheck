package com.seccheck.analyzer;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;
import java.util.Set;

/**
 * 컨트롤러 메서드의 파라미터 중 "사용자가 보내는 값"을 Source 로 등록한다.
 *
 * 1. 사용자 입력 어노테이션이 붙은 파라미터 → 그 어노테이션 이름
 * 2. 어노테이션이 없는 파라미터 → "Implicit" (Spring 은 query 파라미터로 바인딩함)
 *    단, Spring 이 직접 넣어주는 객체(HttpServletRequest, Model 등)는 제외
 */
public class SourceIdentifier extends VoidVisitorAdapter<List<TaintedVariable>> {

    private static final Set<String> METHOD_ANNOTATIONS = Set.of(
            "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping");

    /** 사용자가 보내는 값을 받는 어노테이션 */
    private static final Set<String> PARAM_ANNOTATIONS = Set.of(
            "RequestParam",    // ?name=값
            "PathVariable",    // /users/{id}
            "RequestBody",     // 본문
            "ModelAttribute",  // ?필드=값 (DTO)
            "RequestHeader",   // 헤더
            "CookieValue",     // 쿠키
            "RequestPart"      // multipart 파일 업로드 등
    );

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

    @Override
    public void visit(MethodDeclaration method, List<TaintedVariable> collector) {
        super.visit(method, collector);

        if (!hasControllerAnnotation(method)) {
            return;
        }

        int line = method.getBegin().map(pos -> pos.line).orElse(-1);

        for (Parameter param : method.getParameters()) {
            String sourceAnno = findSourceAnnotation(param);
            if (sourceAnno == null) {
                continue;
            }
            collector.add(new TaintedVariable(
                    param.getNameAsString(),
                    param.getTypeAsString(),
                    line,
                    sourceAnno,
                    method.getNameAsString(),
                    param.getNameAsString(),   // rootSource = 자기 자신
                    null
            ));
        }
    }

    private boolean hasControllerAnnotation(MethodDeclaration method) {
        for (AnnotationExpr anno : method.getAnnotations()) {
            if (METHOD_ANNOTATIONS.contains(simpleName(anno))) {
                return true;
            }
        }
        return false;
    }

    /** Source 면 어노테이션 이름(또는 "Implicit"), 아니면 null */
    private String findSourceAnnotation(Parameter param) {
        for (AnnotationExpr anno : param.getAnnotations()) {
            String name = simpleName(anno);
            if (PARAM_ANNOTATIONS.contains(name)) {
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
        return "Implicit";
    }

    /** {@code @org.springframework...GetMapping} 처럼 전체 이름으로 써도 GetMapping 으로 */
    private String simpleName(AnnotationExpr anno) {
        return anno.getName().getIdentifier();
    }

    /** "java.util.Map<String, Object>" → "Map" */
    private String simpleType(String type) {
        String noGeneric = type.replaceAll("<.*>", "").trim();
        int dot = noGeneric.lastIndexOf('.');
        return dot < 0 ? noGeneric : noGeneric.substring(dot + 1);
    }
}