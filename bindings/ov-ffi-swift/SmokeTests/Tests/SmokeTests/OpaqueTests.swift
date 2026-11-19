import Foundation
import OpenVireoRustCore
import XCTest

/// OPAQUE client steps, `opaqueIds` and the test-server steps: a byte-for-byte replay of
/// `vectors/opaque-transcripts.json` (seeded steps), then random runs as the iOS `OpaqueTests` do.
/// Needs the xcframework built with `--test-server` (`--smoke` does that).
final class OpaqueTests: XCTestCase {
    let t = V.opaque["opaque_ke"]
    let ids = opaqueIds(email: "  Alice@Example.com ", issuerOrHost: "https://accounts.openvireo.example")

    func testIdsAreNormalized() {
        XCTAssertEqual(ids, OpaqueIds(idU: t["id_u"].string, idS: t["id_s"].string))
        XCTAssertEqual(opaqueIds(email: "a@b", issuerOrHost: "http://localhost:5000").idS, "localhost:5000")
        XCTAssertEqual(opaqueIds(email: "a@b", issuerOrHost: "https://h.example:443/x").idS, "h.example")
        XCTAssertEqual(opaqueIds(email: "a@b", issuerOrHost: "accounts.openvireo.com").idS, "accounts.openvireo.com")
        XCTAssertEqual(opaqueContext(), t["context"].string)
        XCTAssertTrue(try opaqueHasTestServer())
    }

    func testTranscriptReplays() throws {
        let pw = t["password"].string
        XCTAssertEqual(try passwordBytes(password: pw).hex, t["password_nfkc_hex"].string)
        let r = t["registration"]
        let start = try opaqueStartRegistration(password: pw, seed: r["client_start_seed_hex"].hex)
        XCTAssertEqual(start.request.hex, r["request_hex"].string)
        let srv = try opaqueServerRegistrationResponse(request: start.request, seed: r["server_seed_hex"].hex)
        XCTAssertEqual(srv.setup.hex, r["server_setup_hex"].string)
        XCTAssertEqual(srv.response.hex, r["response_hex"].string)
        let fin = try opaqueFinishRegistration(state: start.state, response: srv.response, ids: ids, seed: r["client_finish_seed_hex"].hex)
        XCTAssertEqual(fin.record.hex, r["record_hex"].string)
        XCTAssertEqual(fin.exportKey.hex, r["export_key_hex"].string)
        let stored = try opaqueServerStoreRecord(setup: srv.setup, record: fin.record)
        XCTAssertEqual(stored.hex, r["stored_record_hex"].string)
        // a state is used once
        XCTAssertThrowsError(try opaqueFinishRegistration(state: start.state, response: srv.response, ids: ids, seed: nil)) {
            XCTAssertEqual(($0 as! OvError).code, .invalidRequest)
        }

        let l = t["login"]
        let ls = try opaqueStartLogin(password: pw, seed: l["client_start_seed_hex"].hex)
        XCTAssertEqual(ls.ke1.hex, l["ke1_hex"].string)
        let cr = try opaqueServerCredentialResponse(ke1: ls.ke1, storedRecord: stored, ids: ids, context: nil, seed: l["server_seed_hex"].hex)
        XCTAssertEqual(cr.ke2.hex, l["ke2_hex"].string)
        let lf = try opaqueFinishLogin(state: ls.state, ke2: cr.ke2, ids: ids, context: t["context"].string, seed: l["client_finish_seed_hex"].hex)
        XCTAssertEqual(lf.authU.hex, l["auth_u_hex"].string)
        XCTAssertEqual(lf.sessionKey.hex, l["session_key_hex"].string)
        XCTAssertEqual(lf.exportKey.hex, l["export_key_hex"].string)
        XCTAssertEqual(try opaqueServerUserAuth(state: cr.state, authU: lf.authU), lf.sessionKey)

        let w = t["login_wrong_password"]
        let ws = try opaqueStartLogin(password: w["password"].string, seed: w["client_start_seed_hex"].hex)
        XCTAssertEqual(ws.ke1.hex, w["ke1_hex"].string)
        let wc = try opaqueServerCredentialResponse(ke1: ws.ke1, storedRecord: stored, ids: ids, context: nil, seed: w["server_seed_hex"].hex)
        XCTAssertEqual(wc.ke2.hex, w["ke2_hex"].string)
        XCTAssertThrowsError(try opaqueFinishLogin(state: ws.state, ke2: wc.ke2, ids: ids, context: nil, seed: w["client_finish_seed_hex"].hex)) {
            XCTAssertEqual(($0 as! OvError).code, .opaqueFailed)
            XCTAssertEqual(($0 as! OvError).message, "wrong password")
        }
    }

    private func register(_ password: String) throws -> Data {
        let start = try opaqueStartRegistration(password: password, seed: nil)
        let srv = try opaqueServerRegistrationResponse(request: start.request, seed: nil)
        let fin = try opaqueFinishRegistration(state: start.state, response: srv.response, ids: ids, seed: nil)
        return try opaqueServerStoreRecord(setup: srv.setup, record: fin.record)
    }

    func testRandomRegisterAndLogIn() throws {
        let password = "Ünïcödé pässwörd ﬁ"
        let stored = try register(password)
        let ls = try opaqueStartLogin(password: password, seed: nil)
        let cr = try opaqueServerCredentialResponse(ke1: ls.ke1, storedRecord: stored, ids: ids, context: nil, seed: nil)
        let lf = try opaqueFinishLogin(state: ls.state, ke2: cr.ke2, ids: ids, context: nil, seed: nil)
        XCTAssertEqual(try opaqueServerUserAuth(state: cr.state, authU: lf.authU), lf.sessionKey)
    }

    func testOtherIdentityAndDisposedStateFail() throws {
        let stored = try register("pw")
        let other = OpaqueIds(idU: "bob@example.com", idS: ids.idS)
        let ls = try opaqueStartLogin(password: "pw", seed: nil)
        let cr = try opaqueServerCredentialResponse(ke1: ls.ke1, storedRecord: stored, ids: other, context: nil, seed: nil)
        XCTAssertThrowsError(try opaqueFinishLogin(state: ls.state, ke2: cr.ke2, ids: ids, context: nil, seed: nil))
        let disposed = try opaqueStartLogin(password: "pw", seed: nil)
        disposed.state.dispose()
        XCTAssertThrowsError(try opaqueFinishLogin(state: disposed.state, ke2: cr.ke2, ids: ids, context: nil, seed: nil)) {
            XCTAssertEqual(($0 as! OvError).code, .invalidRequest)
        }
        XCTAssertThrowsError(try opaqueServerUserAuth(state: cr.state, authU: Data(count: 64))) { XCTAssertEqual(($0 as! OvError).code, .opaqueFailed) }
    }

    func testEmptyPasswordIsRefused() {
        XCTAssertThrowsError(try opaqueStartLogin(password: "", seed: nil)) { XCTAssertEqual(($0 as! OvError).code, .opaqueFailed) }
        XCTAssertThrowsError(try opaqueStartRegistration(password: "", seed: Data(count: 32)))
        XCTAssertThrowsError(try opaqueStartLogin(password: "x", seed: Data(count: 31))) { XCTAssertEqual(($0 as! OvError).code, .invalidRequest) }
    }
}
