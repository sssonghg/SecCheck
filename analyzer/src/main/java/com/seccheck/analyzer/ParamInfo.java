package com.seccheck.analyzer;

import java.util.List;

/**
 * JSON 의 params[] 한 줄.
 *
 * @param name         요청에 쓰는 이름표 (@RequestParam("q") → "q", 없으면 변수명)
 * @param in           값 넣는 위치: query / path / body / header / cookie
 * @param javaType     파라미터 타입
 * @param required     빠뜨리면 400 에러가 나는지
 * @param defaultValue 안 보냈을 때 들어가는 값 (없으면 null)
 * @param tainted      Sink 까지 흘러가는 파라미터인지 = 공격값 넣을 곳
 * @param fields       DTO 면 필드 목록, 아니면 null
 */
public record ParamInfo(
        String name,
        String in,
        String javaType,
        boolean required,
        String defaultValue,
        boolean tainted,
        List<FieldInfo> fields
) {
    /** DTO 필드 하나 */
    public record FieldInfo(String name, String javaType, boolean tainted) {
    }
}
