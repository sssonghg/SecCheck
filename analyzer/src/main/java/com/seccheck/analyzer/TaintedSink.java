package com.seccheck.analyzer;

import java.util.Set;

/**
 * 취약점 판정 결과 1건: 오염된 값이 들어간 Sink.
 * 5번에서 findings[] 한 건이 된다.
 *
 * @param sink        위험 함수 호출
 * @param vias        Sink 인자에 바로 들어간 오염 변수들 (예: [sql], [sb], [name])
 * @param rootSources 처음 시작된 파라미터들 (예: [name], [req])
 * @param dtoFields   DTO 필드 출처들 (예: [req.username, req.nickname])
 */
public record TaintedSink(
        SinkCall sink,
        Set<String> vias,
        Set<String> rootSources,
        Set<String> dtoFields
) {
}