package com.vulnapp.spel_vuln_app.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
class SpelControllerTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void 정상적인_수식을_계산하면_올바른_결과가_나온다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/spel?expr={expr}", String.class, "1+1");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("2");
    }

    @Test
    void 다른_수식_예시도_정상_계산된다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/spel?expr={expr}", String.class, "10*5");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("50");
    }

    @Test
    void 본문으로_수식을_보내도_계산된다() {
        ResponseEntity<String> response = restTemplate.postForEntity(
                "/vuln/spel/body", "1+1", String.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("2");
    }

    @Test
    void q_이름으로_수식을_보내면_계산된다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/spel/named?q={q}", String.class, "1+1");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("2");
    }

    @Test
    void repeat을_주면_결과가_반복된다() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "/vuln/spel/named?q={q}&repeat={repeat}", String.class, "1+1", 2);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEqualTo("22");
    }
}