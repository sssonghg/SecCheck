package com.seccheck.analyzer.endpoint;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

/**
 * 분석 대상 앱의 설정 파일에서 모든 URL 앞에 붙는 공통 경로를 읽는다.
 *
 *  - server.servlet.context-path : 앱 전체 경로 (예: /shop)
 *  - spring.mvc.servlet.path     : DispatcherServlet 경로 (예: /app)
 *  → 둘 다 있으면 /shop/app
 *
 * 읽는 파일: src/main/resources/application.properties, application.yml, application.yaml
 * (프로필별 파일 application-dev.yml 등은 기본 실행에 안 쓰이므로 무시)
 */
public final class ContextPathResolver {

    private static final String CONTEXT_PATH = "server.servlet.context-path";
    private static final String SERVLET_PATH = "spring.mvc.servlet.path";

    private ContextPathResolver() {
    }

    public static String resolve(Path projectRoot) {
        Path resources = projectRoot.resolve("src/main/resources");
        String contextPath = "";
        String servletPath = "";

        Path props = resources.resolve("application.properties");
        if (Files.exists(props)) {
            Properties p = new Properties();
            try (InputStream in = Files.newInputStream(props)) {
                p.load(in);
                contextPath = p.getProperty(CONTEXT_PATH, contextPath);
                servletPath = p.getProperty(SERVLET_PATH, servletPath);
            } catch (IOException ignored) {
                // 설정 파일을 못 읽으면 공통 경로 없음으로 처리
            }
        }

        for (String name : new String[]{"application.yml", "application.yaml"}) {
            Path yml = resources.resolve(name);
            if (!Files.exists(yml)) {
                continue;
            }
            try (Reader reader = Files.newBufferedReader(yml)) {
                for (Object doc : new Yaml().loadAll(reader)) {
                    if (!(doc instanceof Map<?, ?> map) || isProfileDocument(map)) {
                        continue; // --- 로 나뉜 프로필 전용 문서는 건너뜀
                    }
                    String c = lookup(map, CONTEXT_PATH);
                    String s = lookup(map, SERVLET_PATH);
                    if (c != null) contextPath = c;
                    if (s != null) servletPath = s;
                }
            } catch (IOException | RuntimeException ignored) {
                // YAML 문법 오류 등
            }
        }

        String joined = EndpointExtractor.joinPath(contextPath, servletPath);
        return joined.equals("/") ? "" : joined;
    }

    /** spring.config.activate.on-profile 이나 spring.profiles 가 있는 문서 = 특정 프로필 전용 */
    private static boolean isProfileDocument(Map<?, ?> map) {
        return lookup(map, "spring.config.activate.on-profile") != null
                || lookup(map, "spring.profiles") != null;
    }

    /**
     * YAML 은 server: servlet: context-path: 처럼 중첩으로도,
     * server.servlet.context-path: 처럼 점으로 이어서도 쓸 수 있어서 둘 다 찾는다.
     */
    private static String lookup(Map<?, ?> map, String dottedKey) {
        Object direct = map.get(dottedKey);
        if (direct != null && !(direct instanceof Map)) {
            return direct.toString();
        }
        String[] parts = dottedKey.split("\\.");
        for (int i = 1; i < parts.length; i++) {
            String head = String.join(".", java.util.Arrays.copyOfRange(parts, 0, i));
            String rest = String.join(".", java.util.Arrays.copyOfRange(parts, i, parts.length));
            if (map.get(head) instanceof Map<?, ?> child) {
                String found = lookup(child, rest);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
