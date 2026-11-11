package io.jvd.web;

import io.jvd.evidence.Json;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The HTTP face of the verification service.
 *
 * <p>Built on the JDK's own {@code com.sun.net.httpserver}, so the service adds no third-party
 * dependency to a project whose whole point is that it needs none. This class does the
 * transport work only: reading a bounded body, dispatching to {@link VerificationService},
 * and turning the answer into an HTTP response. Every decision about what is authentic lives
 * in the service, where it can be tested without a socket.</p>
 *
 * <h2>What this class will not do</h2>
 * <ul>
 *   <li><b>It will not accept a path.</b> No request field names a file. The caller uploads
 *       log content, so there is nothing to traverse into.</li>
 *   <li><b>It will not leak internals.</b> An unexpected failure produces a generic message
 *       and a correlation id; the exception itself goes to the server log, where the operator
 *       can find it and the visitor cannot.</li>
 *   <li><b>It will not work without a bound.</b> The body size is capped, the worker pool and
 *       its queue are fixed, and a client that trickles its body is cut off.</li>
 * </ul>
 */
public final class HttpApi {

    private static final Logger LOG = System.getLogger(HttpApi.class.getName());

    /** The largest request body the service will read, in bytes. */
    public static final int MAX_BODY_BYTES = 4 * 1024 * 1024;

    /** How long a client may take to send its body before the connection is given up on. */
    public static final int READ_TIMEOUT_SECONDS = 15;

    /** The number of worker threads that may handle requests at once. */
    public static final int WORKER_THREADS = 8;

    /** How many requests may wait for a worker before further ones are refused. */
    public static final int QUEUE_DEPTH = 32;

    /** The tool this service speaks for, as reported by {@code GET /health}. */
    public static final String TOOL = "jverifydestroy";

    /** The version this service speaks for, as reported by {@code GET /health}. */
    public static final String VERSION = "1.0.0";

    private final VerificationService service;
    private final HttpServer server;
    private final ThreadPoolExecutor executor;
    private final ScheduledExecutorService watchdog;

    /**
     * Binds the API to a port and prepares every route.
     *
     * <p>Pass port {@code 0} to let the operating system choose a free one, which is what the
     * tests and the development runs do. {@link #port()} then reports the port that was
     * actually assigned.</p>
     *
     * @param port the port to bind, or {@code 0} for any free port
     * @throws IOException if the port cannot be bound
     */
    public HttpApi(int port) throws IOException {
        this(new VerificationService(), port);
    }

    /**
     * Binds the API to a port, using a given service.
     *
     * <p>The overload exists so a test can supply a service of its own without the API
     * having to know how to build one.</p>
     */
    public HttpApi(VerificationService service, int port) throws IOException {
        this.service = service;
        this.executor = new ThreadPoolExecutor(
                WORKER_THREADS, WORKER_THREADS, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(QUEUE_DEPTH),
                daemonThreads("jvd-web-worker"),
                new ThreadPoolExecutor.AbortPolicy());
        this.watchdog = Executors.newSingleThreadScheduledExecutor(daemonThreads("jvd-web-watchdog"));
        this.server = HttpServer.create(new InetSocketAddress(port), 64);
        this.server.setExecutor(this.executor);
        this.server.createContext("/", this::handle);
    }

    /**
     * Starts accepting requests.
     *
     * <p>Separate from construction so that a caller can bind an ephemeral port, learn what it
     * is, and only then let traffic in.</p>
     */
    public void start() {
        server.start();
    }

    /** The port the server is listening on. Meaningful after {@link #start()}. */
    public int port() {
        return server.getAddress().getPort();
    }

    /** Stops the server and releases the worker threads. */
    public void stop() {
        server.stop(0);
        executor.shutdownNow();
        watchdog.shutdownNow();
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Routes a request.
     *
     * <p>One context serves every path, and the path decides what happens. That keeps the
     * routing table in one readable place, and it means an unknown path gets the same
     * treatment as every other unknown path: a 404 with a JSON body, never a stack trace.</p>
     */
    private void handle(HttpExchange exchange) {
        String correlationId = UUID.randomUUID().toString();
        try {
            route(exchange, correlationId);
        } catch (IOException e) {
            // The client hung up mid-response. Nothing to say to a client that is gone.
            LOG.log(Level.DEBUG, "client disconnected during " + exchange.getRequestURI(), e);
        } catch (RuntimeException e) {
            // Anything unexpected is our fault, not the caller's. Say so generically and keep
            // the detail in the log, where the operator can correlate it by id.
            LOG.log(Level.ERROR, "unhandled failure for correlation id " + correlationId, e);
            try {
                sendError(exchange, 500, "internal_error",
                        "The check could not be completed. Quote this id if you report it: "
                                + correlationId, correlationId);
            } catch (IOException ignored) {
                LOG.log(Level.DEBUG, "could not send the error response", ignored);
            }
        } finally {
            exchange.close();
        }
    }

    /** Dispatches on the path and the method. */
    private void route(HttpExchange exchange, String correlationId) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();

        switch (path) {
            case "/" -> {
                if (!"GET".equals(method)) {
                    sendError(exchange, 405, "method_not_allowed",
                            "Only GET is allowed on this path.", correlationId);
                    return;
                }
                sendHtml(exchange, 200, IndexPage.HTML);
            }
            case "/health" -> {
                if (!"GET".equals(method)) {
                    sendError(exchange, 405, "method_not_allowed",
                            "Only GET is allowed on this path.", correlationId);
                    return;
                }
                sendJson(exchange, 200, "{\"status\":\"ok\",\"tool\":\"" + TOOL
                        + "\",\"version\":\"" + VERSION + "\"}");
            }
            case "/schema" -> {
                if (!"GET".equals(method)) {
                    sendError(exchange, 405, "method_not_allowed",
                            "Only GET is allowed on this path.", correlationId);
                    return;
                }
                sendJson(exchange, 200, EvidenceSchema.SCHEMA);
            }
            case "/verify" -> {
                if (!"POST".equals(method)) {
                    sendError(exchange, 405, "method_not_allowed",
                            "Only POST is allowed on this path.", correlationId);
                    return;
                }
                verify(exchange, correlationId);
            }
            default -> sendError(exchange, 404, "not_found",
                    "There is no endpoint at this path.", correlationId);
        }
    }

    /**
     * Reads the request body, runs the check, and writes the report.
     *
     * <p>Three outcomes are possible and they mean different things to the caller:</p>
     * <ul>
     *   <li>The material is malformed — the request could not be read at all. That is a
     *       <b>400</b>: the caller sent something this service cannot work with.</li>
     *   <li>The material is readable but does not verify. That is a <b>200</b> with
     *       {@code valid:false}. A tampered log is a successful check with a negative answer,
     *       and reporting it as an HTTP error would tell the visitor that the service broke
     *       rather than that their evidence was changed.</li>
     *   <li>The material verifies. That is a <b>200</b> with {@code valid:true}.</li>
     * </ul>
     */
    private void verify(HttpExchange exchange, String correlationId) throws IOException {
        String body = readBody(exchange);
        if (body == null) {
            sendError(exchange, 413, "payload_too_large",
                    "The request body is larger than " + (MAX_BODY_BYTES / (1024 * 1024)) + " MiB.",
                    correlationId);
            return;
        }

        VerificationRequest request;
        try {
            Map<String, Object> parsed = Json.parseObject(body);
            request = new VerificationRequest(
                    string(parsed, "log"),
                    string(parsed, "checkpoint"),
                    string(parsed, "logPublicKey"),
                    string(parsed, "witnessPublicKey"),
                    string(parsed, "evidencePublicKey"));
        } catch (RuntimeException e) {
            // The body is not a JSON object. Say what is wrong about the body, not about the
            // parser: the parser's position is not useful to the caller.
            sendError(exchange, 400, "invalid_json",
                    "The request body must be a JSON object with 'log', 'checkpoint' and "
                            + "'logPublicKey'.", correlationId);
            return;
        }

        VerificationReport report = service.verify(request);
        if (report.outcome() == Outcome.MALFORMED) {
            // The material could not be read well enough to form an opinion. That is the
            // caller's problem, so it is a 400 with the specific reasons why.
            sendJson(exchange, 400, report.toJson());
            return;
        }
        // Authentic or tampered: either way the check succeeded and the answer is the report.
        sendJson(exchange, 200, report.toJson());
    }

    /**
     * Reads the request body, refusing anything over the limit.
     *
     * <p>The body is read with a hard cap rather than trusting a {@code Content-Length}
     * header, because a header is a claim and a claim from the internet is not evidence. The
     * reader stops one byte past the limit so that a body which is exactly at the limit is
     * accepted and one which is larger is not.</p>
     *
     * <p>A watchdog closes the connection if the client takes longer than
     * {@link #READ_TIMEOUT_SECONDS} to deliver the body. Without it, a client that opens a
     * connection and then stops sending would hold a worker thread for as long as the network
     * keeps the socket open, which is how a handful of slow clients take a small service
     * down.</p>
     *
     * @return the body, or {@code null} when it is over the limit
     */
    private String readBody(HttpExchange exchange) throws IOException {
        var timeout = new java.util.concurrent.atomic.AtomicBoolean(false);
        var pending = watchdog.schedule(() -> {
            timeout.set(true);
            // Closing the exchange is what unblocks the worker thread stuck in the read.
            exchange.close();
        }, READ_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        try (InputStream in = exchange.getRequestBody()) {
            byte[] bytes = in.readNBytes(MAX_BODY_BYTES + 1);
            if (bytes.length > MAX_BODY_BYTES) return null;
            if (timeout.get()) throw new IOException("the request body took too long to arrive");
            return new String(bytes, StandardCharsets.UTF_8);
        } finally {
            pending.cancel(false);
        }
    }

    /** Reads a string field from a parsed request object. */
    private static String string(Map<String, Object> map, String key) {
        Object v = map.get(key);
        return v == null ? null : v.toString();
    }

    /** Sends a JSON response. */
    private void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    /** Sends an HTML response. */
    private void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    /**
     * Sends a structured error.
     *
     * <p>The body carries a machine-readable code, a message that is safe to show to
     * anyone, and the correlation id. No stack trace and no internal message ever reaches
     * this method: the caller of the service is a stranger on the internet.</p>
     */
    private void sendError(HttpExchange exchange, int status, String code, String message,
                           String correlationId) throws IOException {
        String json = "{\"error\":{\"code\":\"" + escape(code) + "\",\"message\":\"" + escape(message)
                + "\",\"correlationId\":\"" + escape(correlationId) + "\"}}";
        sendJson(exchange, status, json);
    }

    /** Escapes a string for a JSON body. */
    private static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    /**
     * Names the worker threads and marks them as daemons.
     *
     * <p>Daemon threads let the JVM exit even if a caller forgets to stop the server, which
     * keeps a test run from hanging on a stuck worker.</p>
     */
    private static ThreadFactory daemonThreads(String prefix) {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread t = new Thread(runnable, prefix + "-" + counter.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }
}
