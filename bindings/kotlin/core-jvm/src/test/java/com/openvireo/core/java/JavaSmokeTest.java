package com.openvireo.core.java;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.openvireo.core.AccountEvent;
import com.openvireo.core.CachedVault;
import com.openvireo.core.ClientConfig;
import com.openvireo.core.CreatedShare;
import com.openvireo.core.DeviceInfo;
import com.openvireo.core.EntryExpiry;
import com.openvireo.core.EntryInput;
import com.openvireo.core.EntryRecord;
import com.openvireo.core.FieldInput;
import com.openvireo.core.FieldRecord;
import com.openvireo.core.Host;
import com.openvireo.core.HttpHeader;
import com.openvireo.core.HttpRequest;
import com.openvireo.core.KdfOverrides;
import com.openvireo.core.LoginInput;
import com.openvireo.core.LoginStep;
import com.openvireo.core.NewAccount;
import com.openvireo.core.OpenedShare;
import com.openvireo.core.OvErrorCode;
import com.openvireo.core.OvException;
import com.openvireo.core.Platform;
import com.openvireo.core.RegisterInput;
import com.openvireo.core.ShareInfo;
import com.openvireo.core.SyncOptions;
import com.openvireo.core.SyncOutcome;
import com.openvireo.core.SyncReport;
import com.openvireo.core.hosts.JavaNetHttpTransport;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The Kotlin {@code SmokeTest} in plain Java, through the facade only: register, log in on a second
 * device, vault, entry, sync, a server event over the streaming transport, share link and error
 * codes, against the testkit relay ({@code cargo xtask kotlin --smoke} passes it). Device B's
 * store and cache are Java implementations of {@link JSecureStore} and {@link JBlobCache}; the
 * transport is either the plain-Java {@link JavaHttpClientTransport} or the shipped Kotlin
 * {@code JavaNetHttpTransport} seen through {@link JHosts#fromKotlin}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JavaSmokeTest {
    private static final String ISSUER = "https://auth.test";

    private Process server;
    private String relay = "";

    @BeforeAll
    void startServer() throws Exception {
        String exe = System.getProperty("ov.testkitRelay");
        if ("true".equals(System.getProperty("ov.requireSmoke"))) {
            assertTrue(exe != null && !exe.isEmpty(), "ov.requireSmoke is set but ov.testkitRelay isn't");
        }
        assumeTrue(exe != null && !exe.isEmpty(), "set -Pov.testkitRelay=<path to the http_relay example> (cargo xtask kotlin --smoke)");
        server = new ProcessBuilder(exe).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        String line = new BufferedReader(new InputStreamReader(server.getInputStream(), StandardCharsets.UTF_8)).readLine();
        assertTrue(line != null, "the relay printed nothing");
        Matcher m = Pattern.compile("\"relay\"\\s*:\\s*\"(http://127\\.0\\.0\\.1:\\d+)\"").matcher(line);
        assertTrue(m.find(), "unexpected first line from the relay: " + line);
        relay = m.group(1);
    }

    @AfterAll
    void stopServer() throws Exception {
        if (server != null) {
            server.getOutputStream().close(); // it exits when stdin closes
            if (!server.waitFor(5, TimeUnit.SECONDS)) server.destroyForcibly();
        }
    }

    /** Sends each request to the relay, the real URL in {@code x-ov-relay-url}; counts stream traffic. */
    private final class ToTestkit implements JHttpTransport {
        private final JHttpTransport inner;
        final AtomicInteger requests = new AtomicInteger();
        final AtomicInteger streamsOpened = new AtomicInteger();
        final AtomicInteger streamChunks = new AtomicInteger();

        ToTestkit(JHttpTransport inner) {
            this.inner = inner;
        }

        private HttpRequest rewrite(HttpRequest req) {
            requests.incrementAndGet();
            URI real = URI.create(req.getUrl());
            String path = real.getRawPath() + (real.getRawQuery() != null ? "?" + real.getRawQuery() : "");
            List<HttpHeader> headers = new ArrayList<>(req.getHeaders());
            headers.add(new HttpHeader("x-ov-relay-url", req.getUrl()));
            return new HttpRequest(req.getMethod(), relay + path, headers, req.getBody(), req.getKeepalive());
        }

        @Override
        public CompletableFuture<JHttpResponse> send(HttpRequest req) {
            return inner.send(rewrite(req));
        }

        @Override
        public CompletableFuture<JByteStream> openStream(HttpRequest req) {
            return inner.openStream(rewrite(req)).thenApply(s -> {
                streamsOpened.incrementAndGet();
                return new JByteStream() {
                    @Override
                    public int status() {
                        return s.status();
                    }

                    @Override
                    public CompletableFuture<byte[]> nextChunk() {
                        return s.nextChunk().thenApply(c -> {
                            if (c != null) streamChunks.incrementAndGet();
                            return c;
                        });
                    }

                    @Override
                    public void closeStream() {
                        s.closeStream();
                    }
                };
            });
        }
    }

    /** A {@link JSecureStore} over a map. */
    private static final class MapStore implements JSecureStore {
        final Map<String, byte[]> map = new ConcurrentHashMap<>();

        @Override
        public CompletableFuture<byte[]> get(String key) {
            byte[] v = map.get(key);
            return CompletableFuture.completedFuture(v == null ? null : v.clone());
        }

        @Override
        public CompletableFuture<Void> set(String key, byte[] value) {
            map.put(key, value.clone());
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> delete(String key) {
            map.remove(key);
            return CompletableFuture.completedFuture(null);
        }
    }

    /** A {@link JBlobCache} over maps, completing on another thread to exercise real asynchrony. */
    private static final class MapCache implements JBlobCache {
        final Map<String, CachedVault> vaults = new ConcurrentHashMap<>();
        final Map<String, byte[]> meta = new ConcurrentHashMap<>();
        final AtomicInteger calls = new AtomicInteger();

        private static String k(String a, String b) {
            return a + "\u0000" + b;
        }

        @Override
        public CompletableFuture<CachedVault> load(String userId, String vaultId) {
            calls.incrementAndGet();
            return CompletableFuture.supplyAsync(() -> vaults.get(k(userId, vaultId)));
        }

        @Override
        public CompletableFuture<Void> save(String userId, String vaultId, CachedVault v) {
            calls.incrementAndGet();
            return CompletableFuture.runAsync(() -> {
                vaults.put(k(userId, vaultId), v);
            });
        }

        @Override
        public CompletableFuture<Void> remove(String userId, String vaultId) {
            calls.incrementAndGet();
            vaults.remove(k(userId, vaultId));
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<List<String>> list(String userId) {
            calls.incrementAndGet();
            List<String> ids = new ArrayList<>();
            String prefix = userId + "\u0000";
            for (String key : vaults.keySet()) if (key.startsWith(prefix)) ids.add(key.substring(prefix.length()));
            return CompletableFuture.completedFuture(ids);
        }

        @Override
        public CompletableFuture<byte[]> loadMeta(String userId, String name) {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(meta.get(k(userId, name)));
        }

        @Override
        public CompletableFuture<Void> saveMeta(String userId, String name, byte[] value) {
            calls.incrementAndGet();
            meta.put(k(userId, name), value.clone());
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> clearUser(String userId) {
            calls.incrementAndGet();
            String prefix = userId + "\u0000";
            vaults.keySet().removeIf(key -> key.startsWith(prefix));
            meta.keySet().removeIf(key -> key.startsWith(prefix));
            return CompletableFuture.completedFuture(null);
        }
    }

    private JHttpTransport transport(String kind) {
        switch (kind) {
            case "java-impl":
                return new JavaHttpClientTransport();
            case "kotlin-default":
                return JHosts.fromKotlin(new JavaNetHttpTransport());
            default:
                throw new IllegalArgumentException(kind);
        }
    }

    private static ClientConfig config() {
        return config(false);
    }

    /** {@code offline}: keep offline data (the vault cache), as device B does. */
    private static ClientConfig config(boolean offline) {
        return new ClientConfig(new DeviceInfo(null, "java-smoke", Platform.CLI), offline, null);
    }

    private static <T> T await(CompletableFuture<T> f) throws Exception {
        return f.get(30, TimeUnit.SECONDS);
    }

    private static EntryInput entry(String title, String password) {
        List<FieldInput> fields = List.of(
            new FieldInput("Title", title.getBytes(StandardCharsets.UTF_8), null),
            new FieldInput("Password", password.getBytes(StandardCharsets.UTF_8), null));
        return JRecords.newEntryInput(fields, List.of(), null, null, EntryExpiry.Keep.INSTANCE);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"java-impl", "kotlin-default"})
    void registerLoginVaultEntrySyncEventsShareErrors(String kind) throws Exception {
        String email = "java-" + kind + "@example.com";
        String password = "correct horse";
        KdfOverrides kdf = JRecords.newKdfOverrides(19456L, 2L, 1L); // the SDK tests' cheap KDF

        // Device A: the JVM defaults with the relay transport.
        ToTestkit httpA = new ToTestkit(transport(kind));
        JOvClient clientA = new JOvClient(config(), JDefaultHosts.builder().http(httpA).build());
        JAccount a = await(clientA.connect(ISSUER));
        NewAccount kit = await(a.register(new RegisterInput(email, utf8(password), kdf, true)));
        assertTrue(kit.getSecretKey().length > 0);
        assertTrue(httpA.requests.get() > 0, "requests went through the Java transport");

        // Device B: Java store and cache (it keeps offline data), Java clock and log sink.
        ToTestkit httpB = new ToTestkit(transport(kind));
        MapStore storeB = new MapStore();
        MapCache cacheB = new MapCache();
        AtomicInteger logLines = new AtomicInteger();
        Host hostB = JHosts.create(httpB, storeB, cacheB, System::currentTimeMillis, (level, target, msg) -> logLines.incrementAndGet());
        JAccount b = await(new JOvClient(config(true), hostB).connect(ISSUER));
        LoginStep step = await(b.login(new LoginInput(email, utf8(password), kit.getSecretKey(), null, true)));
        LoginStep.Unlocked unlocked = assertInstanceOf(LoginStep.Unlocked.class, step);
        assertFalse(unlocked.getUnlocked().getOffline());
        assertFalse(storeB.map.isEmpty(), "the session went into the Java store");

        // A creates a vault, adds an entry and syncs it up.
        JVault vault = await(a.createVault("Infra", null));
        String entryId = vault.addEntry(vault.rootGroupId(), entry("VPN", "s3cret"));
        SyncReport report = await(vault.sync(new SyncOptions(true, false)));
        assertTrue(report.getOutcome() == SyncOutcome.UPLOADED || report.getOutcome() == SyncOutcome.CREATED, String.valueOf(report.getOutcome()));

        // B sees it.
        JVault theirs = await(b.openVault(vault.id()));
        EntryRecord rec = theirs.entry(entryId);
        FieldRecord pw = rec.getFields().stream().filter(f -> f.getName().equals("Password")).findFirst().orElseThrow();
        assertArrayEquals(utf8("s3cret"), pw.getValue());
        assertTrue(cacheB.calls.get() > 0, "B used the Java cache");

        // Streaming: A subscribes, B uploads, A gets the event.
        JEventStream events = await(a.subscribe());
        CompletableFuture<AccountEvent> next = events.next();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (httpA.streamChunks.get() == 0 && System.nanoTime() < deadline) Thread.sleep(20); // ": connected"
        assertTrue(httpA.streamChunks.get() > 0, "the event stream connected");
        theirs.addEntry(theirs.rootGroupId(), entry("New", "x"));
        await(theirs.sync(new SyncOptions(true, false)));
        AccountEvent ev = next.get(10, TimeUnit.SECONDS);
        AccountEvent.VaultChanged changed = assertInstanceOf(AccountEvent.VaultChanged.class, ev);
        assertEquals(vault.id(), changed.getVaultId());
        assertFalse(changed.getDeleted());
        assertEquals(1, httpA.streamsOpened.get());
        events.closeStream();
        assertNull(await(events.next()));

        // A pulls B's entry.
        assertEquals(SyncOutcome.PULLED, await(vault.sync(new SyncOptions(false, false))).getOutcome());
        assertTrue(vault.entries(false).stream().anyMatch(e -> e.getTitle().equals("New")));

        // Share link, opened by a device with no account.
        String api = a.serverConfig().getApi();
        CreatedShare created = await(a.createShare(JOv.textSharePayload(utf8("the secret"), "Note", null),
            JRecords.newShareOptions(3600L, 2L, null, null, null)));
        JOvClient anon = new JOvClient(config(), JDefaultHosts.builder().http(new ToTestkit(transport(kind))).build());
        ShareInfo info = await(anon.shareInfo(api, created.getId()));
        assertEquals(2L, JRecords.getOpensLeft(info));
        OpenedShare opened = await(anon.openShare(api, created.getUrl(), null, info));
        assertArrayEquals(utf8("the secret"), opened.getPayload().getFields().get(0).getValue());
        assertEquals(1L, JRecords.getOpensLeft(opened));

        // Error codes: a passcode-protected link without the passcode, and a wrong password.
        CreatedShare locked = await(a.createShare(JOv.textSharePayload(utf8("x"), null, null),
            JRecords.newShareOptions(3600L, null, utf8("1234"), null, null)));
        ExecutionException e1 = assertThrows(ExecutionException.class, () -> await(anon.openShare(api, locked.getUrl(), null, null)));
        assertInstanceOf(OvException.class, e1.getCause());
        assertEquals(OvErrorCode.PASSCODE_REQUIRED, JErrors.code(e1));
        assertEquals("passcode_required", JErrors.wireCode(e1));
        JAccount c = await(new JOvClient(config(), JDefaultHosts.builder().http(new ToTestkit(transport(kind))).build()).connect(ISSUER));
        ExecutionException e2 = assertThrows(ExecutionException.class,
            () -> await(c.login(new LoginInput(email, utf8("wrong"), kit.getSecretKey(), null, true))));
        assertEquals(OvErrorCode.UNAUTHORIZED, JErrors.code(e2));
        assertEquals(401, JErrors.status(e2));

        for (AutoCloseable o : List.<AutoCloseable>of(c, anon, theirs, vault, events, b, a, clientA)) o.close();
    }
}
