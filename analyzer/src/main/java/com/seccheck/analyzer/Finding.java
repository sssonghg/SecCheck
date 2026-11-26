package com.seccheck.analyzer;

import java.util.List;

/**
 * 최종 JSON 의 findings[] 한 건 (팀원 LLM 이 받는 형식, schemaVersion 1.1).
 */
public record Finding(
        String findingId,          // "F-001"
        String vulnType,           // SQL_INJECTION / COMMAND_INJECTION / SPEL_INJECTION
        Endpoint endpoint,         // 어디로, 어떻게 보내는지 (2번 + 3번)
        Location location,         // 취약한 메서드 위치
        Sink sink,                 // 위험 함수 호출
        List<PathStep> taintPath,  // 입력값이 Sink 까지 가는 경로
        String methodSource        // 메서드 코드 원문
) {

    public record Endpoint(List<String> httpMethods, List<String> paths, List<String> consumes,
                           List<ParamInfo> params) {
    }

    public record Location(String file, String className, String method, int startLine, int endLine) {
    }

    public record Sink(String call, int line, String code) {
    }

    /** kind: SOURCE / PROPAGATION / SINK_ARG */
    public record PathStep(String var, int line, String kind) {
    }

    /** 결과 파일 전체 */
    public record AnalysisResult(String schemaVersion, String project, List<Finding> findings) {
    }
}