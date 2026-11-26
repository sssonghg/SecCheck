package com.seccheck.analyzer;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 위험 함수(Sink) 호출을 찾는다.
 *
 * Sink 마다
 *   - 어떤 타입의 메서드인지 (receivers) : jdbcTemplate.query(..) 의 jdbcTemplate 이 JdbcTemplate 인지
 *   - 몇 번째 인자가 위험한지 (argIndex)  : query("... ?", name) 에서 위험한 건 0번(SQL 문자열)뿐
 * 을 정해둔다.
 */
public class SinkIdentifier extends VoidVisitorAdapter<List<SinkCall>> {

    private static final String SQL = "SQL Injection";
    private static final String CMD = "Command Injection";
    private static final String SPEL = "SpEL Injection";

    /** argIndex 가 이 값이면 인자 전부가 위험 */
    private static final int ALL_ARGS = -1;

    private record SinkRule(String vulnType, Set<String> receivers, int argIndex) {
    }

    private static final Set<String> JDBC_TEMPLATE = Set.of(
            "JdbcTemplate", "JdbcOperations", "NamedParameterJdbcTemplate", "NamedParameterJdbcOperations");
    private static final Set<String> JDBC_STATEMENT = Set.of(
            "Statement", "PreparedStatement", "CallableStatement");
    private static final Set<String> JDBC_ALL = union(JDBC_TEMPLATE, JDBC_STATEMENT);

    /** 메서드 이름 → 규칙 */
    private static final Map<String, SinkRule> METHOD_SINKS = Map.ofEntries(
            // Command
            Map.entry("exec", new SinkRule(CMD, Set.of("Runtime"), 0)),
            Map.entry("command", new SinkRule(CMD, Set.of("ProcessBuilder"), ALL_ARGS)),
            // SpEL
            Map.entry("parseExpression", new SinkRule(SPEL, Set.of("ExpressionParser", "SpelExpressionParser"), 0)),
            Map.entry("parseRaw", new SinkRule(SPEL, Set.of("SpelExpressionParser"), 0)),
            // SQL - JdbcTemplate
            Map.entry("query", new SinkRule(SQL, JDBC_TEMPLATE, 0)),
            Map.entry("queryForList", new SinkRule(SQL, JDBC_TEMPLATE, 0)),
            Map.entry("queryForObject", new SinkRule(SQL, JDBC_TEMPLATE, 0)),
            Map.entry("queryForMap", new SinkRule(SQL, JDBC_TEMPLATE, 0)),
            Map.entry("queryForRowSet", new SinkRule(SQL, JDBC_TEMPLATE, 0)),
            Map.entry("queryForStream", new SinkRule(SQL, JDBC_TEMPLATE, 0)),
            Map.entry("update", new SinkRule(SQL, JDBC_TEMPLATE, 0)),
            Map.entry("batchUpdate", new SinkRule(SQL, JDBC_ALL, 0)),
            Map.entry("execute", new SinkRule(SQL, JDBC_ALL, 0)),
            // SQL - JDBC
            Map.entry("executeQuery", new SinkRule(SQL, JDBC_STATEMENT, 0)),
            Map.entry("executeUpdate", new SinkRule(SQL, JDBC_STATEMENT, 0)),
            Map.entry("executeLargeUpdate", new SinkRule(SQL, JDBC_STATEMENT, 0)),
            Map.entry("addBatch", new SinkRule(SQL, JDBC_STATEMENT, 0)),
            Map.entry("prepareStatement", new SinkRule(SQL, Set.of("Connection"), 0)),
            Map.entry("prepareCall", new SinkRule(SQL, Set.of("Connection"), 0)),
            // SQL - JPA / Hibernate
            Map.entry("createQuery", new SinkRule(SQL, Set.of("EntityManager", "Session"), 0)),
            Map.entry("createNativeQuery", new SinkRule(SQL, Set.of("EntityManager", "Session"), 0))
    );

    /** new Xxx(...) 생성자 → 규칙 */
    private static final Map<String, SinkRule> CONSTRUCTOR_SINKS = Map.of(
            "ProcessBuilder", new SinkRule(CMD, Set.of(), ALL_ARGS)   // new ProcessBuilder("sh", "-c", cmd)
    );

    // ------------------------------------------------------------------ 메서드 호출 Sink

    @Override
    public void visit(MethodCallExpr call, List<SinkCall> collector) {
        super.visit(call, collector);

        SinkRule rule = METHOD_SINKS.get(call.getNameAsString());
        if (rule == null) {
            return;
        }
        Expression scope = call.getScope().orElse(null);
        if (scope == null) {
            return; // query(...) 처럼 앞에 아무것도 없으면 자기 클래스 메서드 → Sink 아님
        }
        Optional<String> receiverType = typeOf(scope, call);
        if (receiverType.isPresent() && !rule.receivers().contains(receiverType.get())) {
            return; // 타입을 알아냈는데 Sink 타입이 아님 (예: userRepository.query(..))
        }
        // 타입을 모르면 놓치지 않게 Sink 로 인정
        addArgs(call.getNameAsString(), rule, call.getArguments(), call, collector);
    }

    // ------------------------------------------------------------------ 생성자 Sink

    @Override
    public void visit(ObjectCreationExpr create, List<SinkCall> collector) {
        super.visit(create, collector);
        String type = create.getType().getNameAsString();
        SinkRule rule = CONSTRUCTOR_SINKS.get(type);
        if (rule != null) {
            addArgs("new " + type, rule, create.getArguments(), create, collector);
        }
    }

    // ------------------------------------------------------------------ 공통

    private void addArgs(String sinkName, SinkRule rule, List<Expression> args, Node at, List<SinkCall> collector) {
        int line = at.getBegin().map(pos -> pos.line).orElse(-1);
        String enclosingMethod = methodOf(at);

        if (rule.argIndex() == ALL_ARGS) {
            for (Expression arg : args) {
                collector.add(new SinkCall(sinkName, rule.vulnType(), arg.toString(), line, enclosingMethod, arg));
            }
        } else if (rule.argIndex() < args.size()) {
            Expression arg = args.get(rule.argIndex());
            collector.add(new SinkCall(sinkName, rule.vulnType(), arg.toString(), line, enclosingMethod, arg));
        }
    }

    /**
     * 메서드를 호출한 대상의 타입을 알아낸다. 모르면 empty.
     *   jdbcTemplate        → 필드/파라미터/지역변수 선언에서 찾기
     *   this.jdbcTemplate   → 필드 선언에서 찾기
     *   Runtime.getRuntime() → Runtime
     */
    private Optional<String> typeOf(Expression scope, Node at) {
        if (scope instanceof NameExpr name) {
            return declaredType(at, name.getNameAsString());
        }
        if (scope instanceof FieldAccessExpr fa && fa.getScope() instanceof ThisExpr) {
            return fieldType(at, fa.getNameAsString());
        }
        if (scope instanceof MethodCallExpr mc && mc.getNameAsString().equals("getRuntime")) {
            return Optional.of("Runtime");
        }
        return Optional.empty();
    }

    @SuppressWarnings("unchecked")
    private Optional<String> declaredType(Node at, String varName) {
        MethodDeclaration m = at.findAncestor(MethodDeclaration.class).orElse(null);
        if (m != null) {
            for (Parameter p : m.getParameters()) {
                if (p.getNameAsString().equals(varName)) {
                    return Optional.of(ParamRules.simpleType(p.getTypeAsString()));
                }
            }
            Optional<String> local = m.findAll(VariableDeclarator.class).stream()
                    .filter(v -> v.getNameAsString().equals(varName))
                    .map(v -> ParamRules.simpleType(v.getTypeAsString()))
                    .findFirst();
            if (local.isPresent()) {
                return local;
            }
        }
        return fieldType(at, varName);
    }

    @SuppressWarnings("unchecked")
    private Optional<String> fieldType(Node at, String fieldName) {
        ClassOrInterfaceDeclaration clazz = at.findAncestor(ClassOrInterfaceDeclaration.class).orElse(null);
        if (clazz == null) {
            return Optional.empty();
        }
        for (FieldDeclaration f : clazz.getFields()) {
            for (VariableDeclarator v : f.getVariables()) {
                if (v.getNameAsString().equals(fieldName)) {
                    return Optional.of(ParamRules.simpleType(v.getTypeAsString()));
                }
            }
        }
        return Optional.empty();
    }

    @SuppressWarnings("unchecked")
    private String methodOf(Node node) {
        return node.findAncestor(MethodDeclaration.class)
                .map(MethodDeclaration::getNameAsString)
                .orElse("(unknown)");
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        java.util.Set<String> s = new java.util.HashSet<>(a);
        s.addAll(b);
        return Set.copyOf(s);
    }
}
