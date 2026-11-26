package com.vulnapp.sql_vuln_app.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import com.vulnapp.sql_vuln_app.dto.JoinRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

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

    @Test
    void join으로_이름을_보내면_정상_조회된다() {
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/vuln/sql/join", new JoinRequest("철수", "없는사람"), String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("chulsoo@example.com");
    }

    @Test
    void find로_키워드를_보내면_정상_조회된다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/sql/find?keyword={keyword}", String.class, "철수");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("chulsoo@example.com");
    }

    @Test
    void find에_없는_키워드를_보내면_빈_결과가_온다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/sql/find?keyword={keyword}&size={size}", String.class, "없는사람", 5);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("[]");
    }

    @Test
    void agent에_일반_브라우저_정보를_보내면_빈_결과가_온다() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "Mozilla/5.0");

        ResponseEntity<String> response = restTemplate.exchange(
                "/vuln/sql/agent", HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("[]");
    }

    @Test
    void builder로_검색하면_정상_조회된다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/sql/builder?name={name}", String.class, "철수");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("chulsoo@example.com");
    }

    @Test
    void inline으로_검색하면_정상_조회된다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/sql/inline?name={name}", String.class, "철수");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).contains("chulsoo@example.com");
    }
}