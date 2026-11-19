import Foundation
import OpenVireoRustCore
import XCTest

/// The ov-crypto exports against `vectors/test-vectors.json`, case for case with the iOS app's
/// `CryptoVectorTests` (which these exports replace).
final class CryptoTests: XCTestCase {
    let v = V.root

    private func code(_ error: Error) -> OvErrorCode { (error as! OvError).code }

    func testSecretKey() throws {
        for c in v["secret_key"].array {
            XCTAssertEqual(try formatSecretKey(raw: c["raw_hex"].hex), c["display"].string)
            XCTAssertEqual(try parseSecretKey(display: c["display"].string), c["raw_hex"].hex)
        }
        let display = v["secret_key"][0]["display"].string
        let sloppy = display.lowercased().replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "0", with: "o")
        XCTAssertEqual(try parseSecretKey(display: sloppy), v["secret_key"][0]["raw_hex"].hex)
        for bad in ["K2-WWW24C-Y37MK-G0PB7-GZ4KG-K532M", "K1-WWW24C-Y37MK-G0PB7-GZ4KG-K532", "K1-ZZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ"] {
            XCTAssertThrowsError(try parseSecretKey(display: bad)) { XCTAssertEqual(self.code($0), .invalidSecretKey) }
        }
        XCTAssertThrowsError(try formatSecretKey(raw: Data(count: 15))) { XCTAssertEqual(self.code($0), .invalidSecretKey) }
        XCTAssertEqual(try generateSecretKey().count, 16)
    }

    func testAuk() throws {
        for c in v["auk"].array {
            let kdf = KdfParams(alg: c["kdf"]["alg"].string, salt: c["kdf"]["salt"].string, m: UInt32(c["kdf"]["m"].int),
                                t: UInt32(c["kdf"]["t"].int), p: UInt32(c["kdf"]["p"].int))
            XCTAssertEqual(try passwordBytes(password: c["password"].string).hex, c["password_nfkc_hex"].string)
            let stretched = try stretchPassword(password: c["password"].string, kdf: kdf, allowWeak: true, kdfMin: nil)
            XCTAssertEqual(stretched.hex, c["argon2id_hex"].string)
            let auk = try deriveAuk(password: c["password"].string, kdf: kdf, secretKey: c["secret_key_hex"].hex, allowWeak: true, kdfMin: nil)
            XCTAssertEqual(auk.hex, c["auk_hex"].string)
            XCTAssertEqual(try aukFromStretched(stretched: stretched, secretKey: c["secret_key_hex"].hex), auk)
            // the same Argon2id through the general export
            let salt = try b64uDecode(text: kdf.salt)
            XCTAssertEqual(try argon2(variant: .argon2id, password: passwordBytes(password: c["password"].string), salt: salt,
                                      mKib: kdf.m, t: kdf.t, pLanes: kdf.p, outLen: 32).hex, c["argon2id_hex"].string)
        }
        let weak = v["auk"][0]["kdf"]
        let kdf = KdfParams(alg: "argon2id", salt: weak["salt"].string, m: UInt32(weak["m"].int), t: UInt32(weak["t"].int), p: 1)
        XCTAssertThrowsError(try deriveAuk(password: "x", kdf: kdf, secretKey: Data(count: 16), allowWeak: false, kdfMin: nil)) {
            XCTAssertEqual(self.code($0), .weakKdf)
            XCTAssertEqual(($0 as! OvError).message, "KDF parameters below the minimum (m >= 19456, t >= 2)")
        }
        XCTAssertThrowsError(try checkKdfParams(kdf: kdf, kdfMin: nil))
        XCTAssertEqual(kdfMinimum(), KdfMin(m: 19456, t: 2))
        let fresh = try newKdfParams()
        XCTAssertEqual([fresh.m, fresh.t, fresh.p], [65536, 3, 1])
        XCTAssertNoThrow(try checkKdfParams(kdf: fresh, kdfMin: nil))
        XCTAssertThrowsError(try checkKdfParams(kdf: fresh, kdfMin: KdfMin(m: 131072, t: 3)))
        XCTAssertEqual(try newKdfParamsWith(m: 19456, t: 2, pLanes: 1).m, 19456)
    }

    /// Argon2d / Argon2i with lanes > 1 and other output lengths (local `.kdbx` files), against the
    /// PHC reference implementation (`echo -n password | argon2 somesaltsomesalt -d -t 3 -k 1024 -p 2 -l 32 -r`).
    func testArgon2Variants() throws {
        let pw = Data("password".utf8), salt = Data("somesaltsomesalt".utf8)
        XCTAssertEqual(try argon2(variant: .argon2d, password: pw, salt: salt, mKib: 1024, t: 3, pLanes: 2, outLen: 32).hex,
                       "70bbe1f806bdedfeb0986154bbd155569c2bdef982d2c08d5263cc0e924b0188")
        XCTAssertEqual(try argon2(variant: .argon2i, password: pw, salt: salt, mKib: 1024, t: 3, pLanes: 4, outLen: 24).hex,
                       "e36bc4e3a34b5033518b64d561211c95cb670604b2cbe525")
        XCTAssertEqual(try argon2(variant: .argon2id, password: pw, salt: salt, mKib: 2048, t: 2, pLanes: 2, outLen: 64).hex,
                       "cc1a57b9c166e08c2c1b65e606ce3c4cd80625f2e49ffb8ffa73869503561add594d0ce14abfb44f05289d693e9674dc1129ce2a6af9e83ec44340c25da4de79")
        XCTAssertThrowsError(try argon2(variant: .argon2d, password: pw, salt: salt, mKib: 1024, t: 0, pLanes: 1, outLen: 32)) {
            XCTAssertEqual(self.code($0), .weakKdf)
        }
    }

    func testKeysetAndPublicKeys() throws {
        let k = v["keyset"]
        let ks = try keysetFromSecrets(encSk: k["enc_sk_hex"].hex, signSeed: k["sign_seed_hex"].hex)
        let pub = PublicKeysJson(encPk: k["public"]["enc_pk"].string, signPk: k["public"]["sign_pk"].string, sig: k["public"]["sig"].string)
        XCTAssertEqual(try publicKeysToJson(keys: ks.publicKeys), pub)
        XCTAssertEqual(ks.publicKeys.fingerprint, k["public"]["fingerprint"].string)
        XCTAssertEqual(try publicKeyFingerprint(encPk: ks.publicKeys.encPk, signPk: ks.publicKeys.signPk), k["public"]["fingerprint"].string)
        let wrapped = try wrapKeyset(key: k["auk_hex"].hex, keyset: ks, nonce: k["nonce_hex"].hex)
        XCTAssertEqual(wrapped.wrapped, k["wrapped"].string)
        XCTAssertEqual(try unwrapKeyset(key: k["auk_hex"].hex, wrapped: wrapped), ks)
        XCTAssertThrowsError(try unwrapKeyset(key: Data(count: 32), wrapped: wrapped)) { XCTAssertEqual(self.code($0), .decryptionFailed) }
        let bob = v["public_keys"][0]
        var swapped = wrapped
        swapped.encPk = bob["enc_pk"].string
        swapped.signPk = bob["sign_pk"].string
        swapped.sig = bob["sig"].string
        XCTAssertThrowsError(try unwrapKeyset(key: k["auk_hex"].hex, wrapped: swapped)) { XCTAssertEqual(self.code($0), .invalidPublicKeys) }
        // a random nonce differs each time and still unwraps
        let a = try wrapKeyset(key: k["auk_hex"].hex, keyset: ks, nonce: nil)
        XCTAssertNotEqual(a.wrapped, wrapped.wrapped)
        XCTAssertEqual(try unwrapKeyset(key: k["auk_hex"].hex, wrapped: a).encSk, ks.encSk)
        let fresh = try generateKeyset()
        XCTAssertTrue(try verifyPublicKeys(keys: fresh.publicKeys))

        for c in v["public_keys"].array {
            let json = PublicKeysJson(encPk: c["enc_pk"].string, signPk: c["sign_pk"].string, sig: c["sig"].string)
            XCTAssertEqual(try keysetFromSecrets(encSk: c["enc_sk_hex"].hex, signSeed: c["sign_seed_hex"].hex).publicKeys,
                           try trustedPublicKeys(json: json))
            XCTAssertEqual(try trustedPublicKeys(json: json).fingerprint, c["fingerprint"].string)
            var tampered = json
            tampered.encPk = k["public"]["enc_pk"].string
            XCTAssertThrowsError(try trustedPublicKeys(json: tampered)) { XCTAssertEqual(self.code($0), .invalidPublicKeys) }
            XCTAssertFalse(try verifyPublicKeys(keys: publicKeysFromJson(json: tampered)))
        }
    }

    func testSealAndWrap() throws {
        for c in v["seal"].array {
            let sealed = try envelopeSeal(recipientEncPk: c["recipient_enc_pk"].b64, plaintext: c["plaintext_hex"].hex, aad: c["aad"].string,
                                          ephemeralSecretKey: c["ephemeral_sk_hex"].hex, nonce: c["nonce_hex"].hex)
            XCTAssertEqual(try b64uEncode(bytes: sealed), c["sealed"].string)
            XCTAssertEqual(Data(sealed[1 ..< 33]).hex, c["ephemeral_pk_hex"].string)
            XCTAssertEqual(try envelopeSealDerivedKey(recipientEncSk: c["recipient_enc_sk_hex"].hex, sealed: sealed).hex, c["derived_key_hex"].string)
            XCTAssertEqual(try envelopeUnseal(recipientEncSk: c["recipient_enc_sk_hex"].hex, sealed: c["sealed"].b64, aad: c["aad"].string),
                           c["plaintext_hex"].hex)
        }
        for c in v["seal_negative"].array {
            let expected: OvErrorCode = c["expect"].string == "unsupported version" ? .unsupportedVersion : .decryptionFailed
            XCTAssertThrowsError(try envelopeUnseal(recipientEncSk: c["recipient_enc_sk_hex"].hex, sealed: c["sealed"].b64, aad: c["aad"].string),
                                 c["case"].string) { XCTAssertEqual(self.code($0), expected, c["case"].string) }
        }
        XCTAssertThrowsError(try envelopeSeal(recipientEncPk: Data(count: 32), plaintext: Data(count: 32), aad: "x", ephemeralSecretKey: nil, nonce: nil)) {
            XCTAssertEqual(self.code($0), .lowOrderPoint)
        }
        let key = try randomBytes(n: 32)
        let a = try envelopeWrap(key: key, plaintext: Data("hello".utf8), aad: "aad", nonce: nil)
        let b = try envelopeWrap(key: key, plaintext: Data("hello".utf8), aad: "aad", nonce: nil)
        XCTAssertNotEqual(a, b)
        XCTAssertEqual(try envelopeUnwrap(key: key, blob: a, aad: "aad"), Data("hello".utf8))
        XCTAssertThrowsError(try envelopeUnwrap(key: key, blob: a, aad: "other")) { XCTAssertEqual(self.code($0), .decryptionFailed) }
        let fixed = try envelopeWrap(key: key, plaintext: Data("hello".utf8), aad: "aad", nonce: Data(repeating: 1, count: 24))
        XCTAssertEqual(Data(fixed[1 ..< 25]), Data(repeating: 1, count: 24))
        XCTAssertThrowsError(try envelopeWrap(key: Data(count: 31), plaintext: Data(), aad: "", nonce: nil)) { XCTAssertEqual(self.code($0), .invalidRequest) }

        XCTAssertEqual(envelopeAad(kind: .keyset, id: ""), "ov-keyset-v1")
        XCTAssertEqual(envelopeAad(kind: .vaultKey, id: "v"), "ov-vault-key|v")
        XCTAssertEqual(envelopeAad(kind: .vaultName, id: "v"), "ov-vault-name|v")
        XCTAssertEqual(envelopeAad(kind: .saMaster, id: "s"), "ov-sa-master-v1|s")
        XCTAssertEqual(envelopeAad(kind: .share, id: "x"), "ov-share-v1|x")
        XCTAssertEqual(envelopeAad(kind: .shareRef, id: "x"), "ov-share-ref|x")
    }

    func testVaultKeySealing() throws {
        let k = v["keyset"]
        let vaultKey = try randomBytes(n: 32)
        let sealed = try sealVaultKey(recipientEncPk: k["public"]["enc_pk"].b64, vaultId: "v1", vaultKey: vaultKey, ephemeralSecretKey: nil, nonce: nil)
        XCTAssertEqual(try unsealVaultKey(encSk: k["enc_sk_hex"].hex, vaultId: "v1", sealed: sealed), vaultKey)
        XCTAssertThrowsError(try unsealVaultKey(encSk: k["enc_sk_hex"].hex, vaultId: "v2", sealed: sealed)) { XCTAssertEqual(self.code($0), .decryptionFailed) }
    }

    func testVaultName() throws {
        let c = v["vault_name"]
        XCTAssertEqual(try vaultNameKey(vaultKey: c["vault_key_hex"].hex).hex, c["name_key_hex"].string)
        let enc = try encryptVaultName(vaultKey: c["vault_key_hex"].hex, vaultId: c["vault_id"].string, name: c["name"].string, nonce: c["nonce_hex"].hex)
        XCTAssertEqual(enc, c["encrypted_name"].string)
        XCTAssertEqual(try decryptVaultName(vaultKey: c["vault_key_hex"].hex, vaultId: c["vault_id"].string, encryptedName: enc), c["name"].string)
        XCTAssertThrowsError(try decryptVaultName(vaultKey: c["vault_key_hex"].hex, vaultId: "00000000-0000-0000-0000-000000000000", encryptedName: enc))
        let random = try encryptVaultName(vaultKey: c["vault_key_hex"].hex, vaultId: c["vault_id"].string, name: "x", nonce: nil)
        XCTAssertEqual(try decryptVaultName(vaultKey: c["vault_key_hex"].hex, vaultId: c["vault_id"].string, encryptedName: random), "x")
    }

    func testServiceAccountTokens() throws {
        let c = v["service_account"]
        let payload = try JSONSerialization.jsonObject(with: Data(c["payload_json"].string.utf8)) as! [String: Any]
        let secret = try b64uDecode(text: payload["secret"] as! String)
        let kek = try b64uDecode(text: payload["kek"] as! String)
        let token = try buildSaToken(url: payload["url"] as! String, saId: c["sa_id"].string, secret: secret, kek: kek)
        XCTAssertEqual(token, c["token"].string)
        let parsed = try parseSaToken(token: token)
        XCTAssertEqual(parsed.saId, c["sa_id"].string)
        XCTAssertEqual(parsed.kek, c["kek_hex"].hex)
        XCTAssertEqual(parsed.secret, secret)
        XCTAssertEqual(try saSecretHash(secret: secret), c["secret_hash_hex"].string)
        XCTAssertEqual(try saSecretPrefix(secret: secret), c["secret_prefix"].string)

        let wrappedMaster = try wrapSaMaster(kek: kek, saId: c["sa_id"].string, master: c["master_key_hex"].hex, nonce: c["wrapped_master_nonce_hex"].hex)
        XCTAssertEqual(wrappedMaster, c["wrapped_master"].string)
        let master = try unwrapSaMaster(kek: kek, saId: c["sa_id"].string, wrapped: wrappedMaster)
        XCTAssertEqual(master, c["master_key_hex"].hex)

        let ks = try keysetFromSecrets(encSk: c["keyset_enc_sk_hex"].hex, signSeed: c["keyset_sign_seed_hex"].hex)
        XCTAssertEqual(ks.publicKeys.fingerprint, c["public"]["fingerprint"].string)
        XCTAssertEqual(try wrapKeyset(key: master, keyset: ks, nonce: c["wrapped_keyset_nonce_hex"].hex).wrapped, c["wrapped_keyset"].string)

        let admin = v["keyset"]
        let s = c["master_sealed_to_admin"]
        let sealed = try sealSaMaster(recipientEncPk: admin["public"]["enc_pk"].b64, saId: c["sa_id"].string, master: master,
                                      ephemeralSecretKey: s["ephemeral_sk_hex"].hex, nonce: s["nonce_hex"].hex)
        XCTAssertEqual(try b64uEncode(bytes: sealed), s["sealed"].string)
        XCTAssertEqual(try unsealSaMaster(encSk: admin["enc_sk_hex"].hex, saId: c["sa_id"].string, sealed: sealed), master)

        XCTAssertThrowsError(try parseSaToken(token: "ov_rt_abc")) { XCTAssertEqual(self.code($0), .invalidToken) }
        XCTAssertThrowsError(try parseSaToken(token: "ov_sa_bm90IGpzb24")) { XCTAssertEqual(self.code($0), .invalidToken) }

        let fresh = try newSaSecret(url: "https://a.example", saId: "sa1", master: master, secretId: "s1", name: "ci", expiresAt: nil)
        let back = try parseSaToken(token: fresh.token)
        XCTAssertEqual(try saSecretHash(secret: back.secret), fresh.secretHash)
        XCTAssertEqual(try unwrapSaMaster(kek: back.kek, saId: "sa1", wrapped: fresh.wrappedMaster), master)
    }

    func testRefreshTokens() throws {
        XCTAssertEqual(refreshTokenHash(token: v["refresh_token"]["token"].string), v["refresh_token"]["stored_hash_hex"].string)
        XCTAssertTrue(try newRefreshToken().hasPrefix("ov_rt_"))
    }

    final class Refetch: JwksRefetcher, @unchecked Sendable {
        let jwks: Jwks
        var calls = 0
        init(_ jwks: Jwks) { self.jwks = jwks }
        func refetch() throws -> Jwks? {
            calls += 1
            return jwks
        }
    }

    func testJwt() throws {
        let j = v["jwt"]
        let jwks = Jwks(keys: j["jwks"]["keys"].array.map {
            Jwk(kty: $0["kty"].string, crv: $0["crv"].string, x: $0["x"].string, kid: $0["kid"].string, keyUse: $0["use"].string, alg: $0["alg"].string)
        })
        let issuer = j["valid"][0]["claims"]["iss"].string
        let now = Int64(j["now"].int)
        let opts = JwtVerifyOptions(issuer: issuer, audience: "ov-sync", now: now, skew: nil)
        for c in j["valid"].array {
            let claims = try verifyJwt(token: c["token"].string, jwks: jwks, options: opts, refetch: nil)
            XCTAssertEqual(claims.sub, c["claims"]["sub"].string)
            XCTAssertEqual(claims.vlt?.first?.id, c["claims"]["vlt"][0]["id"].string)
            XCTAssertTrue(isJwt(token: c["token"].string))
            XCTAssertEqual(try decodeJwt(token: c["token"].string).claims, claims)
        }
        XCTAssertEqual(try decodeJwt(token: j["valid"][0]["token"].string).kid, "test-2026-10")
        for c in j["invalid"].array {
            let refetch = Refetch(jwks)
            XCTAssertThrowsError(try verifyJwt(token: c["token"].string, jwks: jwks, options: opts, refetch: refetch), c["case"].string) {
                let e = $0 as! OvError
                XCTAssertEqual(e.code, .unauthorized, c["case"].string)
                XCTAssertEqual(e.status.map(Int.init), c["expect"].int, c["case"].string)
            }
            if c["case"].string.hasPrefix("unknown kid") { XCTAssertEqual(refetch.calls, 1) }
        }
        let expired = j["invalid"].array.first { $0["case"].string.hasPrefix("expired") }!
        XCTAssertNoThrow(try verifyJwt(token: expired["token"].string, jwks: jwks,
                                       options: JwtVerifyOptions(issuer: issuer, audience: "ov-sync", now: now - 2, skew: nil), refetch: nil))
        XCTAssertFalse(isJwt(token: "ov_rt_x"))
        XCTAssertThrowsError(try decodeJwt(token: "a.b.c")) { XCTAssertEqual(self.code($0), .invalidToken) }
    }

    func testRestoreProof() throws {
        let r = v["restore_proof"]
        let old = v["keyset"]
        let current = try trustedPublicKeys(json: PublicKeysJson(encPk: r["new_public"]["enc_pk"].string, signPk: r["new_public"]["sign_pk"].string,
                                                                 sig: r["new_public"]["sig"].string))
        let user = r["user_id"].string
        XCTAssertEqual(try restoreProofMessage(userId: user, currentEncPk: current.encPk, currentSignPk: current.signPk).hex, r["message_hex"].string)
        let proof = try restoreProof(oldSignSeed: old["sign_seed_hex"].hex, userId: user, currentEncPk: current.encPk, currentSignPk: current.signPk)
        XCTAssertEqual(try b64uEncode(bytes: proof), r["proof"].string)
        XCTAssertTrue(try verifyRestoreProof(proof: proof, userId: user, currentEncPk: current.encPk, currentSignPk: current.signPk, oldSignPk: r["old_sign_pk"].b64))
        for c in r["invalid"].array {
            XCTAssertFalse(try verifyRestoreProof(proof: c["proof"].b64, userId: user, currentEncPk: current.encPk, currentSignPk: current.signPk,
                                                  oldSignPk: r["old_sign_pk"].b64), c["case"].string)
        }
        let s = r["reseal"]
        let resealed = try resealVaultKey(oldEncSk: old["enc_sk_hex"].hex, currentEncPk: current.encPk,
                                          vaultId: String(s["aad"].string.split(separator: "|")[1]), sealed: s["archived_sealed_key"].b64,
                                          ephemeralSecretKey: s["ephemeral_sk_hex"].hex, nonce: s["nonce_hex"].hex)
        XCTAssertEqual(try b64uEncode(bytes: resealed), s["sealed"].string)
    }

    func testCurves() throws {
        let k = v["keyset"]
        let encSk = k["enc_sk_hex"].hex, seed = k["sign_seed_hex"].hex
        XCTAssertEqual(try x25519PublicKey(secretKey: encSk), k["public"]["enc_pk"].b64)
        XCTAssertEqual(try ed25519PublicKey(seed: seed), k["public"]["sign_pk"].b64)
        let other = try x25519RandomSecret()
        XCTAssertEqual(try x25519Shared(secretKey: encSk, publicKey: x25519PublicKey(secretKey: other)),
                       try x25519Shared(secretKey: other, publicKey: x25519PublicKey(secretKey: encSk)))
        XCTAssertThrowsError(try x25519Shared(secretKey: encSk, publicKey: Data(count: 32))) { XCTAssertEqual(self.code($0), .lowOrderPoint) }
        // the signed public keys are Ed25519 over "ov-pubkeys-v1" ‖ enc_pk ‖ sign_pk
        let message = Data("ov-pubkeys-v1".utf8) + k["public"]["enc_pk"].b64 + k["public"]["sign_pk"].b64
        let sig = try ed25519Sign(message: message, seed: seed)
        XCTAssertEqual(try b64uEncode(bytes: sig), k["public"]["sig"].string)
        XCTAssertTrue(try ed25519Verify(signature: sig, message: message, publicKey: ed25519PublicKey(seed: seed)))
        XCTAssertFalse(try ed25519Verify(signature: sig, message: message + Data([0]), publicKey: ed25519PublicKey(seed: seed)))
    }

    func testEncoding() throws {
        XCTAssertEqual(try b64uDecode(text: "AQI"), Data([1, 2]))
        XCTAssertEqual(try b64uDecode(text: "AQI="), Data([1, 2]))
        // unlike the iOS `Data(base64URL:)`, the core also accepts the standard alphabet's + and /
        XCTAssertEqual(try b64uDecode(text: "-_8"), try b64uDecode(text: "+/8="))
        XCTAssertThrowsError(try b64uDecode(text: "A*I")) { XCTAssertEqual(self.code($0), .invalidRequest) }
        XCTAssertEqual(try b64uEncode(bytes: Data([0xFB, 0xFF])), "-_8")
        XCTAssertTrue(try constantTimeEq(a: Data([1, 2]), b: Data([1, 2])))
        XCTAssertFalse(try constantTimeEq(a: Data([1, 2]), b: Data([1, 3])))
    }
}
