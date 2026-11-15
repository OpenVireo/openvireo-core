/*
 * Deterministic libopaque runs for vectors/opaque-transcripts.json (driven by gen-opaque-transcripts.mjs).
 *
 * libopaque takes all its randomness from libsodium's randombytes. This tool installs a seeded
 * randombytes implementation before sodium_init(), so every run with the same seed gives the same bytes:
 * call n (n = 0, 1, ...) fills its buffer with randombytes_buf_deterministic(buf, len, BLAKE2b-256(seed ‖ u64le n)).
 * The library code itself is the unmodified static build (libopaque, liboprf, libsodium).
 *
 * Every argument is lowercase hex (strings are passed as their UTF-8 bytes). Output: one `name=hex` per line.
 *
 *   register        SEED PW IDU IDS              C client + C server registration (per-user server keypair)
 *   server-register SEED REQUEST                 server: CreateRegistrationResponse (per-user keypair)
 *   server-store    SEC REG_RECORD               server: StoreUserRecord
 *   login           SEED USER_RECORD PW IDU IDS CTX    C client + C server login
 *   server-login    SEED USER_RECORD KE1 IDU IDS CTX   server: CreateCredentialResponse
 *
 * Build: see build-libopaque-tool.sh.
 */
#include <opaque.h>
#include <stdio.h>
#include <string.h>

static uint8_t g_seed[32];
static uint64_t g_counter;

static void det_buf(void *const buf, const size_t size) {
  uint8_t in[40], sub[32];
  memcpy(in, g_seed, 32);
  for (int i = 0; i < 8; i++) in[32 + i] = (uint8_t)(g_counter >> (8 * i));
  g_counter++;
  crypto_generichash(sub, sizeof sub, in, sizeof in, NULL, 0);
  randombytes_buf_deterministic(buf, size, sub);
}

static uint32_t det_random(void) {
  uint8_t b[4];
  det_buf(b, 4);
  return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

static const char *det_name(void) { return "ov-vectors-deterministic"; }

static randombytes_implementation det_impl = {det_name, det_random, NULL, NULL, det_buf, NULL};

static void die(const char *msg) {
  fprintf(stderr, "libopaque-transcript: %s\n", msg);
  exit(1);
}

/* Decodes hex into a malloc'd buffer; *len gets the byte count. */
static uint8_t *unhex(const char *hex, size_t *len) {
  size_t n = strlen(hex);
  if (n % 2) die("odd-length hex");
  uint8_t *out = malloc(n / 2 + 1);
  if (!out) die("out of memory");
  size_t got = 0;
  if (sodium_hex2bin(out, n / 2 + 1, hex, n, NULL, &got, NULL) != 0 || got != n / 2) die("bad hex");
  *len = got;
  return out;
}

static uint8_t *unhex_exact(const char *hex, size_t want, const char *what) {
  size_t n;
  uint8_t *b = unhex(hex, &n);
  if (n != want) {
    fprintf(stderr, "libopaque-transcript: %s must be %zu bytes, got %zu\n", what, want, n);
    exit(1);
  }
  return b;
}

static void put(const char *name, const uint8_t *b, size_t n) {
  printf("%s=", name);
  for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

static void seed_from(const char *hex) {
  uint8_t *s = unhex_exact(hex, 32, "SEED");
  memcpy(g_seed, s, 32);
  free(s);
  g_counter = 0;
}

static Opaque_Ids ids_from(const char *u, const char *s) {
  size_t ul, sl;
  Opaque_Ids ids;
  ids.idU = unhex(u, &ul);
  ids.idS = unhex(s, &sl);
  if (ul > 0xffff || sl > 0xffff) die("id too long");
  ids.idU_len = (uint16_t)ul;
  ids.idS_len = (uint16_t)sl;
  return ids;
}

static uint8_t *pw_from(const char *hex, uint16_t *len) {
  size_t n;
  uint8_t *pw = unhex(hex, &n);
  if (n == 0 || n > 0xffff) die("password must be 1..65535 bytes");
  *len = (uint16_t)n;
  return pw;
}

static int cmd_register(char **a) {
  seed_from(a[0]);
  uint16_t pwl;
  uint8_t *pw = pw_from(a[1], &pwl);
  Opaque_Ids ids = ids_from(a[2], a[3]);

  uint8_t csec[OPAQUE_REGISTER_USER_SEC_LEN + pwl], request[crypto_core_ristretto255_BYTES];
  if (opaque_CreateRegistrationRequest(pw, pwl, csec, request)) die("CreateRegistrationRequest failed");
  uint8_t ssec[OPAQUE_REGISTER_SECRET_LEN], response[OPAQUE_REGISTER_PUBLIC_LEN];
  if (opaque_CreateRegistrationResponse(request, NULL, ssec, response)) die("CreateRegistrationResponse failed");
  uint8_t reg_record[OPAQUE_REGISTRATION_RECORD_LEN], export_key[crypto_hash_sha512_BYTES];
  if (opaque_FinalizeRequest(csec, response, &ids, reg_record, export_key)) die("FinalizeRequest failed");
  uint8_t user_record[OPAQUE_USER_RECORD_LEN];
  opaque_StoreUserRecord(ssec, reg_record, user_record);

  put("request", request, sizeof request);
  put("server_sec", ssec, sizeof ssec);
  put("response", response, sizeof response);
  put("record", reg_record, sizeof reg_record);
  put("export_key", export_key, sizeof export_key);
  put("user_record", user_record, sizeof user_record);
  return 0;
}

static int cmd_server_register(char **a) {
  seed_from(a[0]);
  uint8_t *request = unhex_exact(a[1], crypto_core_ristretto255_BYTES, "REQUEST");
  uint8_t ssec[OPAQUE_REGISTER_SECRET_LEN], response[OPAQUE_REGISTER_PUBLIC_LEN];
  if (opaque_CreateRegistrationResponse(request, NULL, ssec, response)) die("CreateRegistrationResponse failed");
  put("server_sec", ssec, sizeof ssec);
  put("response", response, sizeof response);
  return 0;
}

static int cmd_server_store(char **a) {
  uint8_t *ssec = unhex_exact(a[0], OPAQUE_REGISTER_SECRET_LEN, "SEC");
  uint8_t *reg_record = unhex_exact(a[1], OPAQUE_REGISTRATION_RECORD_LEN, "REG_RECORD");
  uint8_t user_record[OPAQUE_USER_RECORD_LEN];
  opaque_StoreUserRecord(ssec, reg_record, user_record);
  put("user_record", user_record, sizeof user_record);
  return 0;
}

static int cmd_login(char **a) {
  seed_from(a[0]);
  uint8_t *rec = unhex_exact(a[1], OPAQUE_USER_RECORD_LEN, "USER_RECORD");
  uint16_t pwl;
  uint8_t *pw = pw_from(a[2], &pwl);
  Opaque_Ids ids = ids_from(a[3], a[4]);
  size_t ctxl;
  uint8_t *ctx = unhex(a[5], &ctxl);

  uint8_t csec[OPAQUE_USER_SESSION_SECRET_LEN + pwl], ke1[OPAQUE_USER_SESSION_PUBLIC_LEN];
  if (opaque_CreateCredentialRequest(pw, pwl, csec, ke1)) die("CreateCredentialRequest failed");
  uint8_t ke2[OPAQUE_SERVER_SESSION_LEN], ssk[OPAQUE_SHARED_SECRETBYTES], auth0[crypto_auth_hmacsha512_BYTES];
  if (opaque_CreateCredentialResponse(ke1, rec, &ids, ctx, (uint16_t)ctxl, ke2, ssk, auth0))
    die("CreateCredentialResponse failed");
  uint8_t csk[OPAQUE_SHARED_SECRETBYTES], auth_u[crypto_auth_hmacsha512_BYTES], export_key[crypto_hash_sha512_BYTES];
  if (opaque_RecoverCredentials(ke2, csec, ctx, (uint16_t)ctxl, &ids, csk, auth_u, export_key))
    die("RecoverCredentials failed");
  if (opaque_UserAuth(auth0, auth_u)) die("UserAuth failed");
  if (sodium_memcmp(csk, ssk, sizeof csk)) die("session keys differ");

  put("ke1", ke1, sizeof ke1);
  put("ke2", ke2, sizeof ke2);
  put("auth_u", auth_u, sizeof auth_u);
  put("session_key", ssk, sizeof ssk);
  put("export_key", export_key, sizeof export_key);
  return 0;
}

static int cmd_server_login(char **a) {
  seed_from(a[0]);
  uint8_t *rec = unhex_exact(a[1], OPAQUE_USER_RECORD_LEN, "USER_RECORD");
  uint8_t *ke1 = unhex_exact(a[2], OPAQUE_USER_SESSION_PUBLIC_LEN, "KE1");
  Opaque_Ids ids = ids_from(a[3], a[4]);
  size_t ctxl;
  uint8_t *ctx = unhex(a[5], &ctxl);

  uint8_t ke2[OPAQUE_SERVER_SESSION_LEN], ssk[OPAQUE_SHARED_SECRETBYTES], auth0[crypto_auth_hmacsha512_BYTES];
  if (opaque_CreateCredentialResponse(ke1, rec, &ids, ctx, (uint16_t)ctxl, ke2, ssk, auth0))
    die("CreateCredentialResponse failed");
  put("ke2", ke2, sizeof ke2);
  put("session_key", ssk, sizeof ssk);
  put("expected_auth_u", auth0, sizeof auth0);
  return 0;
}

int main(int argc, char **argv) {
  if (randombytes_set_implementation(&det_impl) != 0 || sodium_init() < 0) die("libsodium init failed");
  if (argc < 2) die("usage: see the comment at the top of libopaque-transcript.c");
  const char *cmd = argv[1];
  char **a = argv + 2;
  int n = argc - 2;
  if (!strcmp(cmd, "register") && n == 4) return cmd_register(a);
  if (!strcmp(cmd, "server-register") && n == 2) return cmd_server_register(a);
  if (!strcmp(cmd, "server-store") && n == 2) return cmd_server_store(a);
  if (!strcmp(cmd, "login") && n == 6) return cmd_login(a);
  if (!strcmp(cmd, "server-login") && n == 6) return cmd_server_login(a);
  die("unknown command or wrong number of arguments");
  return 1;
}
