package com.vulnapp.sql_vuln_app.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class SqlControllerTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void 존재하는_이름으로_검색하면_정상_조회된다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/sql?name={name}", String.class, "철수");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("chulsoo@example.com");
    }

    @Test
    void 존재하지_않는_이름으로_검색하면_빈_결과가_온다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/sql?name={name}", String.class, "없는사람");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("[]");
    }
}