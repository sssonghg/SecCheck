package com.seccheck.analyzer;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
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
     * 오염 정보
     * @param via   바로 앞 출처 (예: "name", "req.username")
     * @param root  처음 시작된 파라미터 (예: "name", "req")
     * @param field DTO 필드에서 왔으면 필드 이름, 아니면 null
     */
    private record Taint(String via, String root, String field) {
    }

    /** "메서드이름#변수이름" → 오염 정보 (1반 철수, 2반 철수 구분) */
    private final Map<String, Taint> tainted = new HashMap<>();
    /** DTO 클래스 이름 → 필드 이름들 */
    private final Map<String, Set<String>> dtoFields = new HashMap<>();
    /** DTO 클래스 이름 → 부모 클래스 이름 (상속받은 필드 찾기용) */
    private final Map<String, String> dtoParent = new HashMap<>();

    /**
     * @param initialSources SourceIdentifier 결과
     * @param allUnits       프로젝트 전체 CompilationUnit (DTO 클래스 필드를 찾으려고 필요)
     */
    public TaintPropagator(List<TaintedVariable> initialSources, List<CompilationUnit> allUnits) {
        for (TaintedVariable v : initialSources) {
            tainted.put(key(v.getEnclosingMethod(), v.getVariableName()),
                    new Taint(v.getVariableName(), v.getRootSource(), v.getDtoField()));
        }
        for (CompilationUnit cu : allUnits) {
            indexDtoFields(cu);
        }
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
        Taint origin = firstTaintedArg(call.getArguments(), call, method);
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
            return t == null ? null : new Taint(name.getNameAsString(), t.root(), t.field());
        }
        if (e instanceof EnclosedExpr enclosed) {                         // ( ... )
            return taintOrigin(enclosed.getInner(), at, method);
        }
        if (e instanceof CastExpr cast) {                                 // (String) x
            return taintOrigin(cast.getExpression(), at, method);
        }
        if (e instanceof BinaryExpr bin) {                                // a + b
            if (bin.getOperator() != BinaryExpr.Operator.PLUS) {
                return null; // 비교(==), 빼기 등은 글자가 이어지지 않음
            }
            Taint left = taintOrigin(bin.getLeft(), at, method);
            return left != null ? left : taintOrigin(bin.getRight(), at, method);
        }
        if (e instanceof ConditionalExpr cond) {                          // flag ? a : b
            Taint then = taintOrigin(cond.getThenExpr(), at, method);
            return then != null ? then : taintOrigin(cond.getElseExpr(), at, method);
        }
        if (e instanceof ObjectCreationExpr create) {                     // new StringBuilder(name)
            return STRING_HOLDERS.contains(create.getType().getNameAsString())
                    ? firstTaintedArg(create.getArguments(), at, method) : null;
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
            return STRING_STATIC.contains(name) ? firstTaintedArg(call.getArguments(), at, method) : null;
        }

        // req.getUsername() / req.isAdmin() / req.username()  (DTO 필드 꺼내기)
        if (call.getArguments().isEmpty() && scope instanceof NameExpr s) {
            Taint fromGetter = dtoFieldTaint(s, name, false, at, method);
            if (fromGetter != null) {
                return fromGetter;
            }
        }

        // sb.append(name) 의 결과(= sb) : sb 가 이미 오염이거나, 넣는 값이 오염이면 오염
        if (BUILDER_APPEND.contains(name)) {
            Taint fromScope = scope == null ? null : taintOrigin(scope, at, method);
            return fromScope != null ? fromScope : firstTaintedArg(call.getArguments(), at, method);
        }

        // name.trim(), name.substring(..), sb.toString() ...
        if (STRING_PRESERVING.contains(name)) {
            Taint fromScope = scope == null ? null : taintOrigin(scope, at, method);
            if (fromScope != null) {
                return fromScope;
            }
            // "SELECT ... %s".formatted(name),  base.replace("X", name) : 인자의 글자가 결과로 들어감
            if (ARG_INTO_RESULT.contains(name)) {
                return firstTaintedArg(call.getArguments(), at, method);
            }
        }
        return null; // name.length(), Runtime.exec(cmd), repo.findBy(name) 등 → 전파 안 함
    }

    private Taint firstTaintedArg(List<Expression> args, Node at, String method) {
        for (Expression arg : args) {
            Taint origin = taintOrigin(arg, at, method);
            if (origin != null) {
                return origin;
            }
        }
        return null;
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
        String type = simpleType(declaredType(at, scope.getNameAsString()));
        if (NON_DTO_TYPES.contains(type)) {
            return null; // String 등에 대한 name.length() 같은 호출은 여기서 걸러짐
        }

        String field = isFieldUse ? member : getterToField(member);
        boolean knownDto = dtoFields.containsKey(type);

        if (knownDto) {
            // 프로젝트 안의 DTO: 진짜 필드가 있을 때만 (getUsername → username, record 는 username())
            if (field != null && hasField(type, field)) {
                return new Taint(scope.getNameAsString() + "." + field, scopeTaint.root(), field);
            }
            if (!isFieldUse && hasField(type, member)) {
                return new Taint(scope.getNameAsString() + "." + member, scopeTaint.root(), member);
            }
            return null;
        }
        // 프로젝트 밖 클래스(라이브러리 등): getXxx()/isXxx() 관례만 인정
        return field == null ? null : new Taint(scope.getNameAsString() + "." + field, scopeTaint.root(), field);
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

    private void indexDtoFields(CompilationUnit cu) {
        for (ClassOrInterfaceDeclaration c : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            if (c.isInterface()) {
                continue;
            }
            Set<String> fields = new LinkedHashSet<>();
            for (FieldDeclaration f : c.getFields()) {
                if (!f.isStatic()) {
                    f.getVariables().forEach(v -> fields.add(v.getNameAsString()));
                }
            }
            dtoFields.put(c.getNameAsString(), fields);
            c.getExtendedTypes().stream().findFirst()
                    .ifPresent(parent -> dtoParent.put(c.getNameAsString(), parent.getNameAsString()));
        }
        for (RecordDeclaration r : cu.findAll(RecordDeclaration.class)) {   // record JoinRequest(String username, ...)
            Set<String> fields = new LinkedHashSet<>();
            r.getParameters().forEach(p -> fields.add(p.getNameAsString()));
            dtoFields.put(r.getNameAsString(), fields);
        }
    }

    /** 부모 클래스까지 올라가며 필드 찾기 */
    private boolean hasField(String type, String field) {
        String current = type;
        for (int depth = 0; current != null && depth < 10; depth++) {
            Set<String> fields = dtoFields.get(current);
            if (fields != null && fields.contains(field)) {
                return true;
            }
            current = dtoParent.get(current);
        }
        return false;
    }

    // ------------------------------------------------------------------ 유틸

    private void markTainted(String name, String type, int line, Taint origin, String method,
                             List<TaintedVariable> collector) {
        if (name.equals(origin.via()) || tainted.putIfAbsent(key(method, name), origin) != null) {
            return; // 이미 오염으로 등록된 변수 (sql = sql + name 같은 경우 포함)
        }
        collector.add(new TaintedVariable(name, type, line, "derived from " + origin.via(), method,
                origin.root(), origin.field()));
    }

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

    /** "com.x.JoinRequest" / "List<String>" → "JoinRequest" / "List" */
    private static String simpleType(String type) {
        String noGeneric = type.replaceAll("<.*>", "").trim();
        int dot = noGeneric.lastIndexOf('.');
        return dot < 0 ? noGeneric : noGeneric.substring(dot + 1);
    }
}