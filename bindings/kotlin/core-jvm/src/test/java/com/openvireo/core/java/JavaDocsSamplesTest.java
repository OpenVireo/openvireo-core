package com.openvireo.core.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.openvireo.core.ClientConfig;
import com.openvireo.core.CreatedShare;
import com.openvireo.core.DeviceInfo;
import com.openvireo.core.EntryExpiry;
import com.openvireo.core.EntrySummary;
import com.openvireo.core.FieldInput;
import com.openvireo.core.HttpHeader;
import com.openvireo.core.HttpRequest;
import com.openvireo.core.LoginInput;
import com.openvireo.core.LoginStep;
import com.openvireo.core.OpenedShare;
import com.openvireo.core.OvErrorCode;
import com.openvireo.core.Platform;
import com.openvireo.core.RegisterInput;
import com.openvireo.core.ShareInfo;
import com.openvireo.core.SharePayload;
import com.openvireo.core.SyncOptions;
import com.openvireo.core.TotpParams;
import com.openvireo.core.VaultInfo;
import com.openvireo.core.hosts.JavaNetHttpTransport;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

/**
 * The Java sample of docs/bindings/kotlin-java.md against the testkit relay, with the same calls.
 * Only the issuer ({@code https://auth.test}), the prompts (a queue of answers) and the transport
 * (the shipped one, sent to the relay) differ. Skipped like {@code JavaSmokeTest} without
 * {@code -Pov.testkitRelay}. Keep it in step with the page.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JavaDocsSamplesTest {
    private static final String ISSUER = "https://auth.test";

    private Process server;
    private String relay = "";
    private final ArrayDeque<String> answers = new ArrayDeque<>();

    @BeforeAll
    void startServer() throws Exception {
        String exe = System.getProperty("ov.testkitRelay");
        assumeTrue(exe != null && !exe.isEmpty(), "set -Pov.testkitRelay=<path to the http_relay example> (cargo xtask kotlin --smoke)");
        server = new ProcessBuilder(exe).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        String line = new BufferedReader(new InputStreamReader(server.getInputStream(), StandardCharsets.UTF_8)).readLine();
        Matcher m = Pattern.compile("\"relay\"\\s*:\\s*\"(http://127\\.0\\.0\\.1:\\d+)\"").matcher(line);
        assertTrue(m.find(), line);
        relay = m.group(1);
    }

    @AfterAll
    void stopServer() throws Exception {
        if (server != null) {
            server.getOutputStream().close();
            if (!server.waitFor(5, TimeUnit.SECONDS)) server.destroyForcibly();
        }
    }

    /** The shipped transport, each request sent to the relay with the real URL in a header. */
    private JHttpTransport toRelay() {
        JHttpTransport inner = JHosts.fromKotlin(new JavaNetHttpTransport());
        return new JHttpTransport() {
            private HttpRequest rewrite(HttpRequest req) {
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
                return inner.openStream(rewrite(req));
            }
        };
    }

    private JOvClient client(Path cacheDir) {
        return new JOvClient(
            new ClientConfig(new DeviceInfo(null, "backup tool", Platform.CLI), false, null),
            JDefaultHosts.builder().http(toRelay()).cache(new com.openvireo.core.hosts.FileCache(cacheDir)).build());
    }

    private byte[] askSecretKey() {
        return answers.removeFirst().getBytes(StandardCharsets.UTF_8);
    }

    private String askCode() {
        return answers.removeFirst();
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void theJavaSample(@TempDir Path dir) throws Exception {
        String email = "docs-java@example.com";
        byte[] password = utf8("correct horse");

        // Set-up: an account with two-step sign-in and one vault.
        JAccount owner = client(dir.resolve("owner")).connect(ISSUER).join();
        byte[] secretKey = owner.register(new RegisterInput(email, password.clone(), JRecords.newKdfOverrides(19456L, 2L, 1L), true))
            .join().getSecretKey();
        String vaultId = owner.createVault("Personal", null).join().id();
        TotpParams totp = JOv.parseTotpUri(owner.startTwoStep().join().getUri());
        owner.confirmTwoStep(new String(JOv.totpCode(totp, System.currentTimeMillis()).getCode(), StandardCharsets.UTF_8)).join();
        answers.add(new String(secretKey, StandardCharsets.UTF_8));
        answers.add(new String(JOv.totpCode(totp, System.currentTimeMillis()).getCode(), StandardCharsets.UTF_8));

        // The sample, from here on.
        JOvClient client = client(dir.resolve("ov-cache"));
        JAccount account = client.connect(ISSUER).join();

        LoginInput input = new LoginInput(email, password, null, null, true);
        LoginStep step;
        try {
            step = account.login(input).join();
        } catch (CompletionException e) {
            if (JErrors.code(e) != OvErrorCode.INVALID_SECRET_KEY) throw e;
            input.setSecretKey(askSecretKey());
            step = account.login(input).join();
        }
        while (step instanceof LoginStep.NeedsTotp) {
            JTotpChallenge challenge = new JTotpChallenge(((LoginStep.NeedsTotp) step).getChallenge());
            step = account.submitTotp(challenge, askCode()).join();
        }
        assertTrue(step instanceof LoginStep.Unlocked, String.valueOf(step));

        List<String> lines = new ArrayList<>();
        for (VaultInfo info : account.vaults().join()) {
            JVault vault = account.openVault(info.getId()).join();
            for (EntrySummary entry : vault.entries(false)) {
                lines.add(info.getName() + " / " + entry.getTitle() + " " + entry.getUsername());
            }
        }
        assertEquals(List.of(), lines);

        JVault vault = account.openVault(vaultId).join();
        List<FieldInput> fields = List.of(
            new FieldInput("Title", "Router".getBytes(StandardCharsets.UTF_8), null),
            new FieldInput("Password", "correct horse".getBytes(StandardCharsets.UTF_8), null));
        String entryId = vault.addEntry(vault.rootGroupId(),
            JRecords.newEntryInput(fields, List.of(), null, null, EntryExpiry.Keep.INSTANCE));
        vault.sync(new SyncOptions(true, false)).join();

        SharePayload payload = JOv.itemSharePayload(vault.entry(entryId), JOv.defaultShareFields(), null);
        CreatedShare share = account.createShare(payload,
            JRecords.newShareOptions(3600L, 1L, null, vault.id(), entryId)).join();

        // Checks on what the sample did.
        String api = account.serverConfig().getApi();
        String link = new String(share.getUrl(), StandardCharsets.UTF_8);
        ShareInfo info = client.shareInfo(api, JOv.parseShareLink(link).getId()).join();
        assertEquals(1L, JRecords.getOpensLeft(info));
        OpenedShare opened = client.openShare(api, share.getUrl(), null, info).join();
        assertEquals("correct horse", new String(opened.getPayload().getFields().get(0).getValue(), StandardCharsets.UTF_8));
        JVault theirs = owner.openVault(vaultId).join();
        assertEquals("Router", new String(theirs.entry(entryId).getFields().stream()
            .filter(f -> f.getName().equals("Title")).findFirst().orElseThrow().getValue(), StandardCharsets.UTF_8));

        // "Errors in Java"
        JAccount other = client(dir.resolve("other")).connect(ISSUER).join();
        String said;
        try {
            other.login(new LoginInput(email, utf8("wrong"), secretKey, null, true)).join();
            said = "ok";
        } catch (CompletionException e) {
            OvErrorCode code = JErrors.code(e);
            if (code == OvErrorCode.UNAUTHORIZED) {
                said = "wrong email, password or Secret Key";
            } else if (code == null) {
                throw e;
            } else {
                said = JErrors.wireCode(e) + " " + JErrors.status(e) + ": " + JErrors.errorMessage(e);
            }
        }
        assertEquals("wrong email, password or Secret Key", said);

        for (AutoCloseable o : List.<AutoCloseable>of(other, theirs, vault, account, client, owner)) o.close();
    }
}
