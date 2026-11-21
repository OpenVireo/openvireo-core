import Foundation
import OpenVireoRustCore
import XCTest

/// Share-link crypto against `vectors/test-vectors.json` `share`, case for case with the iOS
/// `CryptoVectorTests.shareLinksMatchVectors`.
final class ShareCryptoTests: XCTestCase {
    let v = V.root

    func testShareLinksMatchVectors() throws {
        let cases = v["share"]["cases"].array
        XCTAssertEqual(cases.count, 2)
        for c in cases {
            let id = c["id"].string
            let key = c["key"].b64
            var passcodeKey: Data?
            if c["passcode"].isPresent {
                let k = c["kdf"]
                let kdf = KdfParams(alg: k["alg"].string, salt: k["salt"].string, m: UInt32(k["m"].int), t: UInt32(k["t"].int), p: UInt32(k["p"].int))
                let p = try sharePasscodeKey(passcode: c["passcode"].string, kdf: kdf, allowWeak: true)
                XCTAssertEqual(p.hex, c["passcode_key_hex"].string)
                XCTAssertThrowsError(try sharePasscodeKey(passcode: c["passcode"].string, kdf: kdf, allowWeak: false)) {
                    XCTAssertEqual(($0 as! OvError).code, .weakKdf)
                }
                let auth = try shareAuth(passcodeKey: p)
                XCTAssertEqual(try b64uEncode(bytes: auth), c["auth"].string)
                XCTAssertEqual(try shareAuthHash(auth: auth).hex, c["auth_sha256_hex"].string)
                passcodeKey = p
            }
            XCTAssertEqual(try shareContentKey(linkKey: key, passcodeKey: passcodeKey).hex, c["content_key_hex"].string)
            let payload = Data(c["payload"].string.utf8)
            XCTAssertEqual(try sharePad(data: payload).hex, c["padded_hex"].string)
            XCTAssertEqual(envelopeAad(kind: .share, id: id), c["aad"].string)
            let ct = try shareEncrypt(payloadJson: payload, linkKey: key, shareId: id, passcodeKey: passcodeKey, nonce: c["nonce_hex"].hex)
            XCTAssertEqual(try b64uEncode(bytes: ct), c["ct"].string)
            XCTAssertEqual(try shareDecrypt(ct: c["ct"].b64, linkKey: key, shareId: id, passcodeKey: passcodeKey), payload)
            XCTAssertThrowsError(try shareDecrypt(ct: ct, linkKey: key, shareId: "AAAAAAAAAAAAAAAAAAAAAA", passcodeKey: passcodeKey)) {
                XCTAssertEqual(($0 as! OvError).code, .decryptionFailed)
            }
            if passcodeKey != nil {
                XCTAssertThrowsError(try shareDecrypt(ct: ct, linkKey: key, shareId: id, passcodeKey: nil))
            }
            let random = try shareEncrypt(payloadJson: payload, linkKey: key, shareId: id, passcodeKey: passcodeKey, nonce: nil)
            XCTAssertNotEqual(random, ct)
            XCTAssertEqual(try shareDecrypt(ct: random, linkKey: key, shareId: id, passcodeKey: passcodeKey), payload)

            let link = c["link"].string
            let base = String(link[..<link.range(of: "/\(id)")!.lowerBound])
            XCTAssertEqual(try shareLink(base: base + "/", shareId: id, linkKey: key), link)
            let parts = try parseShareLink(link: "  \(link) ")
            XCTAssertEqual(parts, ShareLinkParts(base: base, id: id, key: key))
            XCTAssertEqual(try shareKeyFromHash(hash: String(link[link.range(of: "#")!.lowerBound...])), key)
        }
        XCTAssertThrowsError(try parseShareLink(link: "https://share.example/abc#def")) { XCTAssertEqual(($0 as! OvError).code, .invalidLink) }
        XCTAssertThrowsError(try shareKeyFromHash(hash: "#short")) { XCTAssertEqual(($0 as! OvError).code, .invalidLink) }

        let r = v["share"]["ref"]
        let encSk = r["owner_enc_sk_hex"].hex
        XCTAssertEqual(try shareRefKey(encSk: encSk).hex, r["ref_key_hex"].string)
        let ref = try shareEncryptRef(referenceJson: Data(r["plaintext"].string.utf8), encSk: encSk, shareId: r["share_id"].string, nonce: r["nonce_hex"].hex)
        XCTAssertEqual(ref, r["ref"].string)
        XCTAssertEqual(try shareDecryptRef(reference: ref, encSk: encSk, shareId: r["share_id"].string), Data(r["plaintext"].string.utf8))
        XCTAssertThrowsError(try shareDecryptRef(reference: ref, encSk: encSk, shareId: "other"))

        let pad = Int(sharePadBlock())
        XCTAssertEqual(pad, 512)
        for n in [0, 1, 511, 512, 1000] {
            let data = Data(repeating: 7, count: n)
            XCTAssertEqual(try sharePad(data: data).count % pad, 0)
            XCTAssertEqual(try shareUnpad(padded: sharePad(data: data)), data)
        }
        XCTAssertThrowsError(try shareUnpad(padded: Data(count: 512)))
        XCTAssertEqual(try newShareKey().count, 32)
        XCTAssertThrowsError(try shareEncrypt(payloadJson: Data(count: Int(shareMaxCiphertext())), linkKey: Data(count: 32), shareId: "x",
                                              passcodeKey: nil, nonce: nil)) { XCTAssertEqual(($0 as! OvError).code, .tooLarge) }
    }
}
