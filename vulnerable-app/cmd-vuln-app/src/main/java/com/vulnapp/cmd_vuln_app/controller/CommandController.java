package com.vulnapp.cmd_vuln_app.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@RestController
public class CommandController {

	@GetMapping("/vuln/command")
	public String runCommand(@RequestParam String cmd) throws Exception {
		// 취약점: 사용자 입력을 검증 없이 그대로 셸 명령어로 실행
		Process process = Runtime.getRuntime().exec(cmd);

		BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		StringBuilder output = new StringBuilder();
		String line;
		while ((line = reader.readLine()) != null) {
			output.append(line).append("\n");
		}
		process.waitFor();

		return output.toString();
	}
}