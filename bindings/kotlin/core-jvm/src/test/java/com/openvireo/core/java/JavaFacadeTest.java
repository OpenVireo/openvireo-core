package com.openvireo.core.java;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.openvireo.core.ClientConfig;
import com.openvireo.core.DeviceInfo;
import com.openvireo.core.Host;
import com.openvireo.core.HttpRequest;
import com.openvireo.core.KdfOverrides;
import com.openvireo.core.OvErrorCode;
import com.openvireo.core.OvException;
import com.openvireo.core.OvExceptions;
import com.openvireo.core.Platform;
import com.openvireo.core.SecureStore;
import com.openvireo.core.TransportException;
import com.openvireo.core.hosts.MemoryStore;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** The facade from plain Java, offline: free functions, records, errors, futures and cancellation. */
class JavaFacadeTest {
    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    /** A transport that fails every request as offline. */
    private static final class OfflineTransport implements JHttpTransport {
        @Override
        public CompletableFuture<JHttpResponse> send(HttpRequest req) {
            return CompletableFuture.failedFuture(new TransportException.Offline());
        }

        @Override
        public CompletableFuture<JByteStream> openStream(HttpRequest req) {
            return CompletableFuture.failedFuture(new java.net.ConnectException("refused"));
        }
    }

    private static JOvClient client(JHttpTransport http) {
        // Clock and LogSink are plain interfaces: lambdas work.
        Host host = JHosts.builder().http(http).clock(System::currentTimeMillis).log((level, target, msg) -> { }).build();
        return new JOvClient(new ClientConfig(new DeviceInfo(null, "java-facade", Platform.CLI), false, null), host);
    }

    @Test
    void freeFunctions() throws OvException {
        assertEquals(3, JOv.version().split("\\.").length);
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            hex(JOv.sha256("abc".getBytes(StandardCharsets.UTF_8))));
        assertEquals("plan_limit", JOv.errorCodeWire(OvErrorCode.PLAN_LIMIT));
    }

    @Test
    void syncErrorsCarryTheirCode() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[24];
        byte[] ct;
        try {
            ct = JOv.aeadEncrypt(key, nonce, "hi".getBytes(StandardCharsets.UTF_8), new byte[0]);
        } catch (OvException e) {
            throw new AssertionError(e);
        }
        byte[] wrong = new byte[32];
        wrong[0] = 1;
        OvException e = assertThrows(OvException.class, () -> JOv.aeadDecrypt(wrong, nonce, ct, new byte[0]));
        assertEquals(OvErrorCode.DECRYPTION_FAILED, JErrors.code(e));
        assertEquals("decryption_failed", JErrors.wireCode(e));
        // B2's extension properties work from Java too.
        assertEquals(OvErrorCode.DECRYPTION_FAILED, OvExceptions.getCode(e));
    }

    @Test
    void errorsUnwrapFutureExceptions() {
        OvException e = JErrors.ovException(OvErrorCode.PLAN_LIMIT, "too many");
        assertEquals(OvErrorCode.PLAN_LIMIT, JErrors.code(new CompletionException(e)));
        assertEquals(OvErrorCode.PLAN_LIMIT, JErrors.code(new ExecutionException(new CompletionException(e))));
        assertEquals("too many", JErrors.errorMessage(e));
        assertNull(JErrors.code(new RuntimeException(e)));
        assertNull(JErrors.code(null));
    }

    @Test
    void recordsWithUnsignedFields() {
        KdfOverrides kdf = JRecords.newKdfOverrides(19456L, 2L, 1L);
        assertEquals(19456L, JRecords.getM(kdf));
        assertEquals(1L, JRecords.getP(kdf));
        assertThrows(IllegalArgumentException.class, () -> JRecords.newKdfOverrides(-1L, null, null));
        assertThrows(IllegalArgumentException.class, () -> JRecords.newKdfOverrides(1L << 32, null, null));
        assertNull(JRecords.getT(JRecords.newKdfOverrides(null, null, null)));
    }

    @Test
    void networkFailuresCompleteTheFutureExceptionally() throws Exception {
        try (JOvClient c = client(new OfflineTransport())) {
            ExecutionException e = assertThrows(ExecutionException.class,
                () -> c.discover("https://auth.test").get(30, TimeUnit.SECONDS));
            assertEquals(OvErrorCode.NETWORK_ERROR, JErrors.code(e), String.valueOf(e.getCause()));
        }
    }

    @Test
    void cancellingTheFutureCancelsTheCall() throws Exception {
        AtomicReference<CompletableFuture<JHttpResponse>> pending = new AtomicReference<>();
        JHttpTransport hanging = new JHttpTransport() {
            @Override
            public CompletableFuture<JHttpResponse> send(HttpRequest req) {
                CompletableFuture<JHttpResponse> f = new CompletableFuture<>();
                pending.set(f);
                return f;
            }

            @Override
            public CompletableFuture<JByteStream> openStream(HttpRequest req) {
                return new CompletableFuture<>();
            }
        };
        ExecutorService exec = Executors.newSingleThreadExecutor();
        try (JOvClient c = new JOvClient(client(hanging).unwrap(), exec)) {
            CompletableFuture<?> call = c.discover("https://auth.test");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (pending.get() == null && System.nanoTime() < deadline) Thread.sleep(10);
            assertTrue(pending.get() != null, "the request reached the Java transport");
            assertTrue(call.cancel(true));
            // The coroutine is cancelled, the Rust future dropped, and the transport's future cancelled.
            deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (!pending.get().isCancelled() && System.nanoTime() < deadline) Thread.sleep(10);
            assertTrue(pending.get().isCancelled(), "the transport's future was cancelled");
        } finally {
            exec.shutdownNow();
        }
    }

    @Test
    void adaptersRoundTrip() {
        SecureStore store = new MemoryStore();
        assertSame(store, JHosts.toKotlin(JHosts.fromKotlin(store)));
        JHttpTransport http = new OfflineTransport();
        assertSame(http, JHosts.fromKotlin(JHosts.toKotlin(http)));
    }

    @Test
    void responsesCheckTheStatus() {
        assertThrows(IllegalArgumentException.class, () -> new JHttpResponse(42, java.util.List.of(), new byte[0]));
        assertArrayEquals(new byte[] {1}, new JHttpResponse(200, java.util.List.of(), new byte[] {1}).toKotlin().getBody());
    }
}
