package com.openvireo.core.java;

import com.openvireo.core.HttpHeader;
import com.openvireo.core.HttpRequest;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A {@link JHttpTransport} written in plain Java over {@code java.net.http}: proves the interface is
 * implementable without Kotlin or coroutines. No redirects, no cookies, any status is a response;
 * streams read the body through an {@code InputStream} on a small thread pool.
 */
final class JavaHttpClientTransport implements JHttpTransport {
    /** Headers java.net.http sets itself and refuses from callers. */
    private static final Set<String> RESERVED = Set.of("connection", "content-length", "expect", "host", "upgrade");

    private final HttpClient client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(10))
        .build();

    private final ExecutorService readers = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "java-transport-reader");
        t.setDaemon(true);
        return t;
    });

    private java.net.http.HttpRequest build(HttpRequest req) {
        java.net.http.HttpRequest.Builder b = java.net.http.HttpRequest.newBuilder(URI.create(req.getUrl()))
            .timeout(Duration.ofSeconds(30));
        for (HttpHeader h : req.getHeaders()) {
            if (!RESERVED.contains(h.getName().toLowerCase(Locale.ROOT))) {
                b.header(h.getName(), h.getValue());
            }
        }
        byte[] body = req.getBody();
        b.method(req.getMethod().name(), body == null
            ? java.net.http.HttpRequest.BodyPublishers.noBody()
            : java.net.http.HttpRequest.BodyPublishers.ofByteArray(body));
        return b.build();
    }

    private static List<HttpHeader> headers(HttpResponse<?> r) {
        List<HttpHeader> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : r.headers().map().entrySet()) {
            if (e.getKey().startsWith(":")) continue;
            for (String v : e.getValue()) out.add(new HttpHeader(e.getKey(), v));
        }
        return out;
    }

    @Override
    public CompletableFuture<JHttpResponse> send(HttpRequest req) {
        return client.sendAsync(build(req), HttpResponse.BodyHandlers.ofByteArray())
            .thenApply(r -> new JHttpResponse(r.statusCode(), headers(r), r.body() == null ? new byte[0] : r.body()));
    }

    @Override
    public CompletableFuture<JByteStream> openStream(HttpRequest req) {
        return client.sendAsync(build(req), HttpResponse.BodyHandlers.ofInputStream())
            .thenApply(r -> new InputStreamByteStream(r.statusCode(), r.body()));
    }

    private final class InputStreamByteStream implements JByteStream {
        private final int status;
        private final InputStream in;
        private volatile boolean closed;

        InputStreamByteStream(int status, InputStream in) {
            this.status = status;
            this.in = in;
        }

        @Override
        public int status() {
            return status;
        }

        @Override
        public CompletableFuture<byte[]> nextChunk() {
            if (closed) return CompletableFuture.completedFuture(null);
            return CompletableFuture.supplyAsync(() -> {
                byte[] buf = new byte[16 * 1024];
                try {
                    int n = in.read(buf);
                    return n < 0 || closed ? null : Arrays.copyOf(buf, n);
                } catch (IOException e) {
                    if (closed) return null;
                    throw new UncheckedIOException(e);
                }
            }, readers);
        }

        @Override
        public void closeStream() {
            closed = true;
            try {
                in.close();
            } catch (IOException ignored) {
                // closing anyway
            }
        }
    }
}
