package com.seccheck.analyzer;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Source 에서 시작한 오염(taint)을 다른 변수로 옮긴다.
 *
 * 원칙: "오염된 글자가 그대로 이어지는 연산"일 때만 옮긴다.
 *   - 옮김:   "..." + name, name.trim(), String.format(.., name), sb.append(name), sb.toString()
 *   - 안 옮김: name.length(), Runtime.exec(cmd) 의 결과, new BufferedReader(...) 등 목록에 없는 전부
 *
 * 처리하는 형태:
 *   1. 선언      String sql = ...;
 *   2. 대입      sql = ...;   sql += ...;
 *   3. 덧붙이기   sb.append(name);   sb.insert(0, name);   (sb 자체가 오염됨)
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

    // "메서드이름#변수이름" 형태로 저장 → 1반 철수, 2반 철수를 구분
    private final Set<String> taintedKeys;

    public TaintPropagator(List<TaintedVariable> initialSources) {
        this.taintedKeys = initialSources.stream()
                .map(v -> key(v.getEnclosingMethod(), v.getVariableName()))
                .collect(Collectors.toCollection(HashSet::new));
    }

    private static String key(String method, String variable) {
        return method + "#" + variable;
    }

    // ------------------------------------------------------------------ 1. 선언: String sql = ...;

    @Override
    public void visit(VariableDeclarator declarator, List<TaintedVariable> collector) {
        super.visit(declarator, collector);
        if (declarator.getInitializer().isEmpty()) {
            return;
        }
        String method = methodOf(declarator);
        String origin = taintOrigin(declarator.getInitializer().get(), method);
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
        String origin = taintOrigin(assign.getValue(), method);
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
        String origin = firstTaintedArg(call.getArguments(), method);
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

    /**
     * 식이 오염된 글자를 그대로 담고 있으면, 그 오염이 어느 변수에서 왔는지 이름을 돌려준다.
     * 담고 있지 않으면 null.
     */
    private String taintOrigin(Expression e, String method) {
        if (e instanceof NameExpr name) {
            return taintedKeys.contains(key(method, name.getNameAsString())) ? name.getNameAsString() : null;
        }
        if (e instanceof EnclosedExpr enclosed) {                         // ( ... )
            return taintOrigin(enclosed.getInner(), method);
        }
        if (e instanceof CastExpr cast) {                                 // (String) x
            return taintOrigin(cast.getExpression(), method);
        }
        if (e instanceof BinaryExpr bin) {                                // a + b
            if (bin.getOperator() != BinaryExpr.Operator.PLUS) {
                return null; // 비교(==), 빼기 등은 글자가 이어지지 않음
            }
            String left = taintOrigin(bin.getLeft(), method);
            return left != null ? left : taintOrigin(bin.getRight(), method);
        }
        if (e instanceof ConditionalExpr cond) {                          // flag ? a : b
            String then = taintOrigin(cond.getThenExpr(), method);
            return then != null ? then : taintOrigin(cond.getElseExpr(), method);
        }
        if (e instanceof ObjectCreationExpr create) {                     // new StringBuilder(name)
            return STRING_HOLDERS.contains(create.getType().getNameAsString())
                    ? firstTaintedArg(create.getArguments(), method) : null;
        }
        if (e instanceof MethodCallExpr call) {
            return taintOriginOfCall(call, method);
        }
        return null; // 목록에 없는 형태는 전파하지 않는다
    }

    private String taintOriginOfCall(MethodCallExpr call, String method) {
        String name = call.getNameAsString();
        Expression scope = call.getScope().orElse(null);

        // String.format(...), String.join(...), String.valueOf(...)
        if (scope instanceof NameExpr s && s.getNameAsString().equals("String")) {
            return STRING_STATIC.contains(name) ? firstTaintedArg(call.getArguments(), method) : null;
        }

        // sb.append(name) 의 결과(= sb) : sb 가 이미 오염이거나, 넣는 값이 오염이면 오염
        if (BUILDER_APPEND.contains(name)) {
            String fromScope = scope == null ? null : taintOrigin(scope, method);
            return fromScope != null ? fromScope : firstTaintedArg(call.getArguments(), method);
        }

        // name.trim(), name.substring(..), sb.toString() ...
        if (STRING_PRESERVING.contains(name)) {
            String fromScope = scope == null ? null : taintOrigin(scope, method);
            if (fromScope != null) {
                return fromScope;
            }
            // "SELECT ... %s".formatted(name),  base.replace("X", name) : 인자의 글자가 결과로 들어감
            if (ARG_INTO_RESULT.contains(name)) {
                return firstTaintedArg(call.getArguments(), method);
            }
        }
        return null; // name.length(), Runtime.exec(cmd), repo.findBy(name) 등 → 전파 안 함
    }

    private String firstTaintedArg(List<Expression> args, String method) {
        for (Expression arg : args) {
            String origin = taintOrigin(arg, method);
            if (origin != null) {
                return origin;
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ 유틸

    private void markTainted(String name, String type, int line, String origin, String method,
                             List<TaintedVariable> collector) {
        if (name.equals(origin) || !taintedKeys.add(key(method, name))) {
            return; // 이미 오염으로 등록된 변수 (sql = sql + name 같은 경우 포함)
        }
        collector.add(new TaintedVariable(name, type, line, "derived from " + origin, method));
    }

    private String methodOf(com.github.javaparser.ast.Node node) {
        return node.findAncestor(MethodDeclaration.class)
                .map(MethodDeclaration::getNameAsString)
                .orElse("(unknown)");
    }

    private int lineOf(com.github.javaparser.ast.Node node) {
        return node.getBegin().map(pos -> pos.line).orElse(-1);
    }

    /** 대입문에서는 타입이 안 보이므로, 같은 메서드 안의 선언/파라미터에서 타입을 찾는다 */
    private String declaredType(com.github.javaparser.ast.Node node, String varName) {
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