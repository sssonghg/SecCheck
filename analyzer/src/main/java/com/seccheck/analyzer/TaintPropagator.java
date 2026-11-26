package com.seccheck.analyzer;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Source 에서 시작한 오염(taint)을 다른 변수로 옮긴다.
 *
 * 원칙: "오염된 글자가 그대로 이어지는 연산"일 때만 옮긴다.
 *   - 옮김:   "..." + name, name.trim(), String.format(.., name), sb.append(name), sb.toString(),
 *             req.getUsername() / req.username() / req.username  (DTO 필드 꺼내기)
 *   - 안 옮김: name.length(), Runtime.exec(cmd) 의 결과, new BufferedReader(...) 등 목록에 없는 전부
 *
 * 처리하는 형태:
 *   1. 선언      String sql = ...;
 *   2. 대입      sql = ...;   sql += ...;
 *   3. 덧붙이기   sb.append(name);   sb.insert(0, name);   (sb 자체가 오염됨)
 *
 * 출처는 여러 개를 기억한다.
 *   "..." + req.getUsername() + req.getEmail()  →  fields = [req.username, req.email]
 */
public class TaintPropagator extends VoidVisitorAdapter<List<TaintedVariable>> {

    /** 호출한 대상(scope)의 글자를 그대로 유지하는 String 메서드 → scope 가 오염이면 결과도 오염 */
    private static final Set<String> STRING_PRESERVING = Set.of(
            "trim", "strip", "stripLeading", "stripTrailing",
            "substring", "subSequence",
            "toLowerCase", "toUpperCase",
            "replace", "replaceAll", "replaceFirst",
            "concat", "repeat", "formatted", "intern",
            "toString", "toCharArray", "getBytes"
    );

    /** 인자로 넣은 글자가 결과에 들어가는 인스턴스 메서드 → 인자가 오염이면 결과도 오염 */
    private static final Set<String> ARG_INTO_RESULT = Set.of(
            "concat", "replace", "replaceAll", "replaceFirst", "formatted"
    );

    /** StringBuilder / StringBuffer 에 글자를 넣는 메서드 → 인자가 오염이면 sb 자체가 오염 */
    private static final Set<String> BUILDER_APPEND = Set.of("append", "insert");

    /** String.xxx(...) 정적 메서드 중 인자 글자가 결과에 들어가는 것 */
    private static final Set<String> STRING_STATIC = Set.of(
            "format", "join", "valueOf", "copyValueOf"
    );

    /** new Xxx(오염값) 했을 때 글자가 그대로 담기는 타입 */
    private static final Set<String> STRING_HOLDERS = Set.of(
            "String", "StringBuilder", "StringBuffer"
    );

    /** DTO 가 아닌 타입 → getter 규칙 적용 안 함 (name.length() 같은 오탐 방지) */
    private static final Set<String> NON_DTO_TYPES = Set.of(
            "String", "CharSequence", "StringBuilder", "StringBuffer", "Object",
            "Integer", "Long", "Double", "Float", "Short", "Byte", "Boolean", "Character",
            "int", "long", "double", "float", "short", "byte", "boolean", "char"
    );

    /**
     * 숫자·참거짓 타입 → 오염을 옮기지 않음.
     * ?size=' OR 1=1 을 보내면 Spring 이 숫자 변환에 실패해서 400 에러 → 공격 문자열이 SQL 까지 못 감.
     * (char 는 ' 한 글자로도 SQL 을 깰 수 있어서 넣지 않음)
     */
    private static final Set<String> NUMERIC_TYPES = Set.of(
            "int", "long", "short", "byte", "double", "float", "boolean",
            "Integer", "Long", "Short", "Byte", "Double", "Float", "Boolean",
            "BigDecimal", "BigInteger"
    );

    /**
     * 오염 정보
     * @param vias   바로 앞 출처들 (예: [u, req.email])  → "derived from ..." 문구용
     * @param roots  처음 시작된 파라미터들 (예: [req])
     * @param fields DTO 필드 출처들, "파라미터.필드" (예: [req.username, req.email])
     */
    private record Taint(Set<String> vias, Set<String> roots, Set<String> fields) {
        static Taint of(String via, Set<String> roots, Set<String> fields) {
            return new Taint(Set.of(via), roots, fields);
        }
    }

    /** "메서드이름#변수이름" → 오염 정보 (1반 철수, 2반 철수 구분) */
    private final Map<String, Taint> tainted = new HashMap<>();
    private final DtoIndex dtoIndex;

    /**
     * @param initialSources SourceIdentifier 결과
     * @param dtoIndex       프로젝트 DTO 필드 목록 (getter 전파 판단용)
     */
    public TaintPropagator(List<TaintedVariable> initialSources, DtoIndex dtoIndex) {
        this.dtoIndex = dtoIndex;
        for (TaintedVariable v : initialSources) {
            tainted.put(key(v.getEnclosingMethod(), v.getVariableName()),
                    Taint.of(v.getVariableName(), v.getRootSources(), v.getDtoFields()));
        }
    }

    private static String key(String method, String variable) {
        return method + "#" + variable;
    }

    // ------------------------------------------------------------------ Sink 판정

    /**
     * Sink 의 위험한 인자 식이 오염됐는지 판단한다. visit(...) 으로 전파를 끝낸 뒤 호출.
     * query(sql), query(sb.toString()), query("..." + name), query(name.trim()) 모두 같은 규칙으로 판단.
     */
    public List<TaintedSink> evaluateSinks(List<SinkCall> sinks) {
        List<TaintedSink> result = new java.util.ArrayList<>();
        for (SinkCall sink : sinks) {
            Expression arg = sink.getArgumentExpr();
            if (arg == null) {
                continue;
            }
            Taint t = taintOrigin(arg, arg, sink.getEnclosingMethod());
            if (t != null) {
                result.add(new TaintedSink(sink, t.vias(), t.roots(), t.fields()));
            }
        }
        return result;
    }

    // ------------------------------------------------------------------ 1. 선언: String sql = ...;

    @Override
    public void visit(VariableDeclarator declarator, List<TaintedVariable> collector) {
        super.visit(declarator, collector);
        if (declarator.getInitializer().isEmpty()) {
            return;
        }
        String method = methodOf(declarator);
        Taint origin = taintOrigin(declarator.getInitializer().get(), declarator, method);
        if (origin != null) {
            markTainted(declarator.getNameAsString(), declarator.getTypeAsString(),
                    lineOf(declarator), origin, method, collector);
        }
    }

    // ------------------------------------------------------------------ 2. 대입: sql = ...;  sql += ...;

    @Override
    public void visit(AssignExpr assign, List<TaintedVariable> collector) {
        super.visit(assign, collector);
        if (!(assign.getTarget() instanceof NameExpr target)) {
            return; // this.field = ... 같은 필드 대입은 아직 대상 아님
        }
        AssignExpr.Operator op = assign.getOperator();
        if (op != AssignExpr.Operator.ASSIGN && op != AssignExpr.Operator.PLUS) {
            return; // -=, *= 등은 숫자 연산이라 글자가 이어지지 않음
        }
        String method = methodOf(assign);
        Taint origin = taintOrigin(assign.getValue(), assign, method);
        if (origin != null) {
            String name = target.getNameAsString();
            markTainted(name, declaredType(assign, name), lineOf(assign), origin, method, collector);
        }
    }

    // ------------------------------------------------------------------ 3. 덧붙이기: sb.append(name);

    @Override
    public void visit(MethodCallExpr call, List<TaintedVariable> collector) {
        super.visit(call, collector);
        if (!BUILDER_APPEND.contains(call.getNameAsString())) {
            return;
        }
        String method = methodOf(call);
        Taint origin = taintedArgs(call.getArguments(), call, method);
        if (origin == null) {
            return;
        }
        // sb.append("a").append(name) 처럼 이어 쓴 경우 맨 앞의 sb 를 찾는다
        Expression root = call.getScope().orElse(null);
        while (root instanceof MethodCallExpr inner && BUILDER_APPEND.contains(inner.getNameAsString())) {
            root = inner.getScope().orElse(null);
        }
        if (root instanceof NameExpr builder) {
            String name = builder.getNameAsString();
            markTainted(name, declaredType(call, name), lineOf(call), origin, method, collector);
        }
    }

    // ------------------------------------------------------------------ 핵심: 이 식이 오염된 글자를 담고 있나?

    /** 식이 오염된 글자를 그대로 담고 있으면 오염 정보를, 아니면 null 을 돌려준다. */
    private Taint taintOrigin(Expression e, Node at, String method) {
        if (e instanceof NameExpr name) {
            Taint t = tainted.get(key(method, name.getNameAsString()));
            if (t == null || NUMERIC_TYPES.contains(ParamRules.simpleType(declaredType(at, name.getNameAsString())))) {
                return null; // 오염 아님, 또는 숫자 타입 (int page 등)
            }
            return Taint.of(name.getNameAsString(), t.roots(), t.fields());
        }
        if (e instanceof EnclosedExpr enclosed) {                         // ( ... )
            return taintOrigin(enclosed.getInner(), at, method);
        }
        if (e instanceof CastExpr cast) {                                 // (String) x
            return taintOrigin(cast.getExpression(), at, method);
        }
        if (e instanceof BinaryExpr bin) {                                // a + b  → 양쪽 출처 다 합침
            if (bin.getOperator() != BinaryExpr.Operator.PLUS) {
                return null; // 비교(==), 빼기 등은 글자가 이어지지 않음
            }
            return merge(taintOrigin(bin.getLeft(), at, method), taintOrigin(bin.getRight(), at, method));
        }
        if (e instanceof ConditionalExpr cond) {                          // flag ? a : b
            return merge(taintOrigin(cond.getThenExpr(), at, method), taintOrigin(cond.getElseExpr(), at, method));
        }
        if (e instanceof ObjectCreationExpr create) {                     // new StringBuilder(name)
            return STRING_HOLDERS.contains(create.getType().getNameAsString())
                    ? taintedArgs(create.getArguments(), at, method) : null;
        }
        if (e instanceof FieldAccessExpr fa && fa.getScope() instanceof NameExpr scope) {   // req.username
            return dtoFieldTaint(scope, fa.getNameAsString(), true, at, method);
        }
        if (e instanceof MethodCallExpr call) {
            return taintOriginOfCall(call, at, method);
        }
        return null; // 목록에 없는 형태는 전파하지 않는다
    }

    private Taint taintOriginOfCall(MethodCallExpr call, Node at, String method) {
        String name = call.getNameAsString();
        Expression scope = call.getScope().orElse(null);

        // String.format(...), String.join(...), String.valueOf(...)
        if (scope instanceof NameExpr s && s.getNameAsString().equals("String")) {
            return STRING_STATIC.contains(name) ? taintedArgs(call.getArguments(), at, method) : null;
        }

        // req.getUsername() / req.isAdmin() / req.username()  (DTO 필드 꺼내기)
        if (call.getArguments().isEmpty() && scope instanceof NameExpr s) {
            Taint fromGetter = dtoFieldTaint(s, name, false, at, method);
            if (fromGetter != null) {
                return fromGetter;
            }
        }

        // sb.append(name) 의 결과(= sb) : sb 출처 + 넣는 값 출처
        if (BUILDER_APPEND.contains(name)) {
            Taint fromScope = scope == null ? null : taintOrigin(scope, at, method);
            return merge(fromScope, taintedArgs(call.getArguments(), at, method));
        }

        // name.trim(), name.substring(..), sb.toString() ...
        if (STRING_PRESERVING.contains(name)) {
            Taint fromScope = scope == null ? null : taintOrigin(scope, at, method);
            // "SELECT ... %s".formatted(name),  base.replace("X", name) : 인자의 글자도 결과로 들어감
            Taint fromArgs = ARG_INTO_RESULT.contains(name) ? taintedArgs(call.getArguments(), at, method) : null;
            return merge(fromScope, fromArgs);
        }
        return null; // name.length(), Runtime.exec(cmd), repo.findBy(name) 등 → 전파 안 함
    }

    /** 인자들 중 오염된 것의 출처를 전부 합친다 */
    private Taint taintedArgs(List<Expression> args, Node at, String method) {
        Taint result = null;
        for (Expression arg : args) {
            result = merge(result, taintOrigin(arg, at, method));
        }
        return result;
    }

    // ------------------------------------------------------------------ DTO 필드

    /**
     * 오염된 DTO 변수에서 필드를 꺼내는 경우만 오염으로 본다.
     *
     * @param member     getUsername / username (메서드 이름 또는 필드 이름)
     * @param isFieldUse true 면 req.username (필드 직접 접근), false 면 메서드 호출
     */
    private Taint dtoFieldTaint(NameExpr scope, String member, boolean isFieldUse, Node at, String method) {
        Taint scopeTaint = tainted.get(key(method, scope.getNameAsString()));
        if (scopeTaint == null) {
            return null;
        }
        String type = ParamRules.simpleType(declaredType(at, scope.getNameAsString()));
        if (NON_DTO_TYPES.contains(type)) {
            return null; // String 등에 대한 name.length() 같은 호출은 여기서 걸러짐
        }

        String field;
        if (dtoIndex.isKnown(type)) {
            // 프로젝트 안의 DTO: 진짜 필드가 있을 때만 (getUsername → username, record 는 username())
            String fromGetter = isFieldUse ? member : getterToField(member);
            if (fromGetter != null && dtoIndex.hasField(type, fromGetter)) {
                field = fromGetter;
            } else if (!isFieldUse && dtoIndex.hasField(type, member)) {
                field = member;
            } else {
                return null;
            }
            String fieldType = ParamRules.simpleType(dtoIndex.fields(type).get(field));
            if (NUMERIC_TYPES.contains(fieldType)) {
                return null; // int size 같은 숫자 필드는 공격 문자열을 못 담음
            }
        } else {
            // 프로젝트 밖 클래스(라이브러리 등): getXxx()/isXxx() 관례만 인정
            field = isFieldUse ? member : getterToField(member);
            if (field == null) {
                return null;
            }
        }

        Set<String> fields = scopeTaint.roots().stream()
                .map(root -> root + "." + field)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return Taint.of(scope.getNameAsString() + "." + field, scopeTaint.roots(), fields);
    }

    /** getUsername → username, isAdmin → admin, 그 외 → null */
    private static String getterToField(String methodName) {
        String rest;
        if (methodName.startsWith("get") && methodName.length() > 3) {
            rest = methodName.substring(3);
        } else if (methodName.startsWith("is") && methodName.length() > 2) {
            rest = methodName.substring(2);
        } else {
            return null;
        }
        if (!Character.isUpperCase(rest.charAt(0))) {
            return null; // "getaway()" 같은 건 getter 아님
        }
        return Character.toLowerCase(rest.charAt(0)) + rest.substring(1);
    }

    // ------------------------------------------------------------------ 오염 등록

    private void markTainted(String name, String type, int line, Taint origin, String method,
                             List<TaintedVariable> collector) {
        // 자기 자신에서 온 출처는 빼기 (sql = sql + name 의 sql)
        Set<String> vias = new LinkedHashSet<>(origin.vias());
        vias.remove(name);
        if (vias.isEmpty()) {
            return;
        }
        String k = key(method, name);
        Taint existing = tainted.get(k);

        if (existing == null) {                                   // 처음 오염됨
            Taint t = new Taint(vias, origin.roots(), origin.fields());
            tainted.put(k, t);
            collector.add(new TaintedVariable(name, type, line, "derived from " + String.join(", ", vias),
                    method, t.roots(), t.fields()));
            return;
        }

        // 이미 오염된 변수: 새 출처가 있으면 합친다 (sql = sql + req.getEmail())
        if (existing.roots().containsAll(origin.roots()) && existing.fields().containsAll(origin.fields())) {
            return;
        }
        Taint merged = merge(existing, new Taint(vias, origin.roots(), origin.fields()));
        tainted.put(k, merged);
        for (int i = 0; i < collector.size(); i++) {
            TaintedVariable v = collector.get(i);
            if (v.getEnclosingMethod().equals(method) && v.getVariableName().equals(name)) {
                String label = v.getSourceAnnotation().startsWith("derived from")
                        ? "derived from " + String.join(", ", merged.vias())
                        : v.getSourceAnnotation();
                collector.set(i, new TaintedVariable(name, v.getType(), v.getLineNumber(), label,
                        method, merged.roots(), merged.fields()));
                break;
            }
        }
    }

    private static Taint merge(Taint a, Taint b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        Set<String> vias = new LinkedHashSet<>(a.vias());
        vias.addAll(b.vias());
        Set<String> roots = new LinkedHashSet<>(a.roots());
        roots.addAll(b.roots());
        Set<String> fields = new LinkedHashSet<>(a.fields());
        fields.addAll(b.fields());
        return new Taint(vias, roots, fields);
    }

    // ------------------------------------------------------------------ 유틸

    @SuppressWarnings("unchecked")
    private String methodOf(Node node) {
        return node.findAncestor(MethodDeclaration.class)
                .map(MethodDeclaration::getNameAsString)
                .orElse("(unknown)");
    }

    private int lineOf(Node node) {
        return node.getBegin().map(pos -> pos.line).orElse(-1);
    }

    /** 변수의 선언 타입을 같은 메서드 안의 파라미터/선언문에서 찾는다 */
    @SuppressWarnings("unchecked")
    private String declaredType(Node node, String varName) {
        MethodDeclaration m = node.findAncestor(MethodDeclaration.class).orElse(null);
        if (m == null) {
            return "unknown";
        }
        for (Parameter p : m.getParameters()) {
            if (p.getNameAsString().equals(varName)) {
                return p.getTypeAsString();
            }
        }
        return m.findAll(VariableDeclarator.class).stream()
                .filter(v -> v.getNameAsString().equals(varName))
                .map(VariableDeclarator::getTypeAsString)
                .findFirst()
                .orElse("unknown");
    }
}