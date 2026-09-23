package com.vulnapp.sql_vuln_app.controller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
}