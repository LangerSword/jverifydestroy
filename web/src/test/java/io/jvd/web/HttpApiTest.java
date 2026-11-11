package io.jvd.web;

import io.jvd.evidence.Json;
import io.jvd.log.Checkpoint;
import io.jvd.log.LogStore;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the real HTTP server over a real socket.
 *
 * <p>The server binds port {@code 0} so the operating system picks a free one, and the tests
 * talk to it with the JDK's own {@link HttpClient}. Nothing is stubbed: these are the bytes a
 * visitor's browser would receive.</p>
 */
class HttpApiTest {

    private HttpApi api;
    private HttpClient client;
    private String base;

    @BeforeEach void startServer() throws Exception {
        api = new HttpApi(0);
        api.start();
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        base = "http://127.0.0.1:" + api.port();
    }

    @AfterEach void stopServer() {
        if (api != null) api.stop();
    }

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test void healthReturnsTheExpectedJson() throws Exception {
        HttpResponse<String> r = get("/health");

        assertEquals(200, r.statusCode());
        Map<String, Object> body = Json.parseObject(r.body());
        assertEquals("ok", body.get("status"));
        assertEquals("jverifydestroy", body.get("tool"));
        assertEquals("1.0.0", body.get("version"));
        assertTrue(r.headers().firstValue("Content-Type").orElse("").contains("application/json"));
    }

    @Test void schemaReturnsTheEvidenceRecordSchema() throws Exception {
        HttpResponse<String> r = get("/schema");

        assertEquals(200, r.statusCode());
        Map<String, Object> schema = Json.parseObject(r.body());
        assertEquals("https://json-schema.org/draft/2020-12/schema", schema.get("$schema"));
        assertEquals("object", schema.get("type"));
    }

    @Test void theIndexPageIsServedAsSelfContainedHtml() throws Exception {
        HttpResponse<String> r = get("/");

        assertEquals(200, r.statusCode());
        assertTrue(r.headers().firstValue("Content-Type").orElse("").contains("text/html"));
        assertTrue(r.body().contains("<!doctype html>"));
        // The dark theme of the desktop application.
        assertTrue(r.body().contains("#0B0D10"));
        assertTrue(r.body().contains("#ECE9E2"));
        assertTrue(r.body().contains("#C8F56A"));
        // Self-contained: nothing is fetched from anywhere else.
        assertFalse(r.body().contains("<script"), "the page must not load a script");
        assertFalse(r.body().contains("<link"), "the page must not load a stylesheet");
        assertFalse(r.body().contains("src="), "the page must not reference an external asset");
        assertFalse(r.body().contains("href="), "the page must not reference an external asset");
        assertFalse(r.body().contains("@import"), "the page must not import a stylesheet");
        // The only URL allowed is the localhost example in the curl snippet.
        var urls = java.util.regex.Pattern.compile("https?://[^\\s\"'<>]+")
                .matcher(r.body()).results().map(java.util.regex.MatchResult::group).distinct().toList();
        for (String url : urls) {
            assertTrue(url.startsWith("http://localhost"),
                    "the page must not reference an external URL: " + url);
        }
    }

    @Test void verifyAcceptsAGenuineLogAndReportsItValid(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 3);
        Checkpoint cp = f.checkpoint(store);
        String body = Json.write(Map.of(
                "log", Files.readString(store.logFile()),
                "checkpoint", cp.toJson(),
                "logPublicKey", Fixtures.pub(f.logKey),
                "witnessPublicKey", Fixtures.pub(f.witnessKey)));

        HttpResponse<String> r = post("/verify", body);

        assertEquals(200, r.statusCode());
        Map<String, Object> report = Json.parseObject(r.body());
        assertEquals(Boolean.TRUE, report.get("valid"));
        assertEquals("AUTHENTIC", report.get("outcome"));
        assertEquals(3L, ((Number) report.get("records")).longValue());
        assertEquals(Boolean.TRUE, report.get("witnessChecked"));
        assertTrue(report.get("summary") instanceof String);
        assertTrue(report.get("checkedAt") instanceof String);
    }

    @Test void verifyReportsATamperedLogAsValidFalseWithA200(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 3);
        Checkpoint cp = f.checkpoint(store);
        String tampered = Fixtures.tamperRecord(Files.readString(store.logFile()), 1,
                Map.of("timestamp", "2000-01-01T00:00:00Z"));
        String body = Json.write(Map.of(
                "log", tampered,
                "checkpoint", cp.toJson(),
                "logPublicKey", Fixtures.pub(f.logKey),
                "witnessPublicKey", Fixtures.pub(f.witnessKey)));

        HttpResponse<String> r = post("/verify", body);

        // A tamper detection is a successful check. It must not be reported as an HTTP error.
        assertEquals(200, r.statusCode());
        Map<String, Object> report = Json.parseObject(r.body());
        assertEquals(Boolean.FALSE, report.get("valid"));
        assertEquals("TAMPERED", report.get("outcome"));
        @SuppressWarnings("unchecked")
        java.util.List<Object> errors = (java.util.List<Object>) report.get("errors");
        assertFalse(errors.isEmpty(), "the report must name what is wrong");
        assertTrue(String.valueOf(errors.get(0)).contains("leaf mismatch"), errors.toString());
    }

    @Test void verifyRejectsABadJsonBodyWithA400() throws Exception {
        HttpResponse<String> r = post("/verify", "{ this is not json");

        assertEquals(400, r.statusCode());
        Map<String, Object> body = Json.parseObject(r.body());
        @SuppressWarnings("unchecked")
        Map<String, Object> error = (Map<String, Object>) body.get("error");
        assertNotNull(error);
        assertEquals("invalid_json", error.get("code"));
        assertNotNull(error.get("correlationId"));
        assertTrue(error.get("message") instanceof String);
    }

    @Test void verifyRejectsABadPublicKeyWithA400(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 1);
        Checkpoint cp = f.checkpoint(store);
        String body = Json.write(Map.of(
                "log", Files.readString(store.logFile()),
                "checkpoint", cp.toJson(),
                "logPublicKey", "this is not a key"));

        HttpResponse<String> r = post("/verify", body);

        assertEquals(400, r.statusCode());
        Map<String, Object> report = Json.parseObject(r.body());
        assertEquals(Boolean.FALSE, report.get("valid"));
        assertEquals("MALFORMED", report.get("outcome"));
        @SuppressWarnings("unchecked")
        java.util.List<Object> errors = (java.util.List<Object>) report.get("errors");
        assertTrue(errors.stream().anyMatch(e -> e.toString().contains("logPublicKey")),
                errors.toString());
    }

    @Test void anOversizedBodyIsRejectedWithA413() throws Exception {
        // One byte over the limit, so the boundary is tested and not just the far end.
        StringBuilder oversized = new StringBuilder();
        oversized.append("{\"log\":\"");
        while (oversized.length() <= HttpApi.MAX_BODY_BYTES) {
            oversized.append('x');
        }
        oversized.append("\"}");

        HttpResponse<String> r = post("/verify", oversized.toString());

        assertEquals(413, r.statusCode());
        Map<String, Object> body = Json.parseObject(r.body());
        @SuppressWarnings("unchecked")
        Map<String, Object> error = (Map<String, Object>) body.get("error");
        assertEquals("payload_too_large", error.get("code"));
    }

    @Test void anUnknownPathIsA404WithAJsonBody() throws Exception {
        HttpResponse<String> r = get("/nope");

        assertEquals(404, r.statusCode());
        Map<String, Object> body = Json.parseObject(r.body());
        @SuppressWarnings("unchecked")
        Map<String, Object> error = (Map<String, Object>) body.get("error");
        assertEquals("not_found", error.get("code"));
        assertNotNull(error.get("correlationId"));
    }

    @Test void theWrongMethodIsRejectedWithA405() throws Exception {
        HttpResponse<String> r = post("/health", "{}");

        assertEquals(405, r.statusCode());
        Map<String, Object> body = Json.parseObject(r.body());
        @SuppressWarnings("unchecked")
        Map<String, Object> error = (Map<String, Object>) body.get("error");
        assertEquals("method_not_allowed", error.get("code"));
    }

    @Test void getOnVerifyIsRejectedWithA405() throws Exception {
        HttpResponse<String> r = get("/verify");

        assertEquals(405, r.statusCode());
    }

    @Test void noErrorResponseLeaksAStackTraceOrAPath(@TempDir Path dir) throws Exception {
        // Every response below must be free of internal detail.
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);
        String tampered = Fixtures.tamperRecord(Files.readString(store.logFile()), 1,
                Map.of("subjectLabel", "/home/someone/secret.txt"));

        HttpResponse<String>[] responses = new HttpResponse[]{
                post("/verify", "{ not json"),
                post("/verify", Json.write(Map.of(
                        "log", tampered,
                        "checkpoint", cp.toJson(),
                        "logPublicKey", "not a key"))),
                get("/does-not-exist"),
                post("/health", "{}"),
        };

        for (HttpResponse<String> r : responses) {
            String body = r.body();
            assertFalse(body.contains("at io.jvd"), "a stack trace leaked: " + body);
            assertFalse(body.contains("Exception"), "an exception name leaked: " + body);
            assertFalse(body.contains(dir.toString()), "a filesystem path leaked: " + body);
            assertFalse(body.matches("(?s).*(?<![\\w])/[\\w./-]+/.*"),
                    "a filesystem path leaked: " + body);
        }
    }

    @Test void theServerHandlesManyConcurrentRequests(@TempDir Path dir) throws Exception {
        Fixtures f = new Fixtures();
        LogStore store = f.buildLog(dir, 2);
        Checkpoint cp = f.checkpoint(store);
        String body = Json.write(Map.of(
                "log", Files.readString(store.logFile()),
                "checkpoint", cp.toJson(),
                "logPublicKey", Fixtures.pub(f.logKey)));

        var executor = java.util.concurrent.Executors.newFixedThreadPool(8);
        var futures = new java.util.ArrayList<java.util.concurrent.Future<HttpResponse<String>>>();
        for (int i = 0; i < 24; i++) {
            futures.add(executor.submit(() -> post("/verify", body)));
        }
        for (var future : futures) {
            HttpResponse<String> r = future.get();
            assertEquals(200, r.statusCode());
            assertEquals(Boolean.TRUE, Json.parseObject(r.body()).get("valid"));
        }
        executor.shutdownNow();
    }
}
