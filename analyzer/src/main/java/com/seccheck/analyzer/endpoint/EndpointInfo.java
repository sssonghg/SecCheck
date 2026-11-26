package com.seccheck.analyzer.endpoint;

import java.util.List;

/**
 * 컨트롤러 메서드 1개의 "어디로, 어떻게 보내는지" 정보.
 *
 * @param className     컨트롤러 클래스명
 * @param methodName    메서드명 (Source-Sink 결과의 enclosingMethod 와 연결하는 키)
 * @param methodLine    메서드 선언 줄 번호
 * @param httpMethods   허용 HTTP 메서드 (지정 없으면 전부)
 * @param paths         context-path 까지 붙은 전체 경로
 * @param consumes      body 형식 제한 (없으면 빈 리스트)
 * @param unresolved    값을 못 알아낸 경로/consumes 표현식 (비어 있으면 전부 해석 성공)
 */
public record EndpointInfo(
        String className,
        String methodName,
        int methodLine,
        List<String> httpMethods,
        List<String> paths,
        List<String> consumes,
        List<String> unresolved
) {
}
