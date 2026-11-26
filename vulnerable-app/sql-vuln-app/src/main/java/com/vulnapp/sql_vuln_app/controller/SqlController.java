package com.vulnapp.sql_vuln_app.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.vulnapp.sql_vuln_app.dto.JoinRequest;
import com.vulnapp.sql_vuln_app.dto.SearchForm;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.List;
import java.util.Map;

@RestController
public class SqlController {

    private final JdbcTemplate jdbcTemplate;

    public SqlController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/vuln/sql")
    public List<Map<String, Object>> search(@RequestParam String name) {
        // 취약점: 사용자 입력을 검증 없이 그대로 SQL 문자열에 조합
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForList(sql);
    }
    // [4번-1] record DTO + 필드 2개가 한 SQL에
    @PostMapping("/vuln/sql/join")
    public List<Map<String, Object>> searchByJoin(@RequestBody JoinRequest req) {
        String sql = "SELECT * FROM users WHERE name = '" + req.username()
                + "' OR name = '" + req.nickname() + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // [4번-2] 어노테이션 없는 class DTO
    @GetMapping("/vuln/sql/find")
    public List<Map<String, Object>> find(SearchForm form) {
        String sql = "SELECT * FROM users WHERE name = '" + form.getKeyword() + "' LIMIT " + form.getSize();
        return jdbcTemplate.queryForList(sql);
    }

    // [4번-3] 헤더 → SQL
    @GetMapping("/vuln/sql/agent")
    public List<Map<String, Object>> byAgent(@RequestHeader("User-Agent") String userAgent) {
        String sql = "SELECT * FROM users WHERE name = '" + userAgent + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // [4번-4] StringBuilder → Sink 인자가 sb.toString() (식)
    @GetMapping("/vuln/sql/builder")
    public List<Map<String, Object>> builder(@RequestParam String name) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE name = '");
        sb.append(name).append("'");
        return jdbcTemplate.queryForList(sb.toString());
    }

    // [4번-5] Sink 인자에 바로 문자열 더하기 (식)
    @GetMapping("/vuln/sql/inline")
    public List<Map<String, Object>> inline(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }
}