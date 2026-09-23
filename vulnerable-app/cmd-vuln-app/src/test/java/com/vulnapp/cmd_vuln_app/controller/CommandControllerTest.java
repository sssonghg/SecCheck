package com.vulnapp.cmd_vuln_app.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@AutoConfigureTestRestTemplate
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CommandControllerTest {

	@Autowired
	private TestRestTemplate restTemplate;

	private String pingCommand() {
		boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
		return isWindows ? "ping -n 1 localhost" : "ping -c 1 localhost";
	}

	@Test
	void 정상_호스트로_ping하면_200_응답이_온다() {
		ResponseEntity<String> response = restTemplate.getForEntity(
				"/vuln/command?cmd=" + pingCommand(), String.class);

		assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
	}

	@Test
	void 응답에_ping_결과_문자열이_포함된다() {
		ResponseEntity<String> response = restTemplate.getForEntity(
				"/vuln/command?cmd=" + pingCommand(), String.class);

		assertThat(response.getBody()).containsIgnoringCase("ping");
	}
}