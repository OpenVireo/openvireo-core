import Foundation
import OpenVireoRustCore
import XCTest

final class SmokeTests: XCTestCase {
    func testVersion() {
        // Qualified: XCTestCase (an NSObject) has its own `version`.
        let v = OpenVireoRustCore.version()
        XCTAssertEqual(v.split(separator: ".").count, 3)
    }

    func testSha256() throws {
        let digest = try sha256(data: Data("abc".utf8))
        XCTAssertEqual(
            digest.map { String(format: "%02x", $0) }.joined(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testAeadRoundTripAndErrorCodes() throws {
        let key = Data(repeating: 7, count: 32)
        let nonce = Data(repeating: 9, count: 24)
        let ct = try aeadEncrypt(key: key, nonce: nonce, plaintext: Data("hi".utf8), aad: Data())
        XCTAssertEqual(try aeadDecrypt(key: key, nonce: nonce, ciphertext: ct, aad: Data()), Data("hi".utf8))
        XCTAssertThrowsError(try aeadDecrypt(key: Data(repeating: 8, count: 32), nonce: nonce, ciphertext: ct, aad: Data())) {
            let e = $0 as! OvError
            XCTAssertEqual(e.code, .decryptionFailed)
            XCTAssertEqual(e.wireCode, "decryption_failed")
        }
    }

    /// The facade is still `todo!()` stubs: a call must come back as `OvError(internal)`, not a crash.
    func testPanicBecomesInternalError() {
        XCTAssertThrowsError(try defaultShareFields()) {
            XCTAssertEqual(($0 as! OvError).code, .internal)
        }
    }

    func testWireCodes() {
        XCTAssertEqual(errorCodeWire(code: .planLimit), "plan_limit")
        XCTAssertEqual(errorCodeFromWire(wire: "plan_limit"), .planLimit)
        XCTAssertEqual(OvError(code: .aborted, message: "x").wireCode, "aborted")
    }
}
