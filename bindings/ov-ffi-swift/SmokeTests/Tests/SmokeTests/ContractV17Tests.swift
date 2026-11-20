import Foundation
import OpenVireoRustCore
import XCTest

/// contract-v1.7 on the Swift binding (docs/adr/0001-contract.md): local files opened with the
/// password hash, `SelfHosted.syncDatabaseWith`, and `vaultKeyMismatch` for a wrong local-file key.
final class ContractV17Tests: XCTestCase {
    private func client() -> OvClient {
        let host = Host(http: FakeHttp(), store: FakeStore(), cache: FakeCache(), clock: FakeClock(), log: FakeLog())
        return OvClient(config: ClientConfig(device: DeviceInfo(id: nil, name: "smoke", platform: .ios), offline: false, server: nil),
                        host: host)
    }

    func testOpensWithThePasswordHash() async throws {
        let pw = KdbxCredentials(password: Data("pw ✓".utf8), keyFile: nil)
        let v = try await client().createLocal(name: "Home", credentials: pw, cancel: CancelToken())
        let bytes = try await v.saveLocal(cancel: CancelToken())
        let hash = try sha256(data: Data("pw ✓".utf8))
        let byHash = KdbxCredentials(password: nil, keyFile: nil, passwordHash: hash)
        let opened = try await Vault.openLocal(kdbx: bytes, credentials: byHash, cancel: CancelToken())
        let saved = try await opened.saveLocal(cancel: CancelToken())
        _ = try await Vault.openLocal(kdbx: saved, credentials: pw, cancel: CancelToken())
        let wrong = KdbxCredentials(password: nil, keyFile: nil, passwordHash: try sha256(data: Data("no".utf8)))
        await XCTAssertThrowsErrorAsync(try await Vault.openLocal(kdbx: bytes, credentials: wrong, cancel: CancelToken())) {
            XCTAssertEqual(($0 as! OvError).code, .vaultKeyMismatch)
        }
        let both = KdbxCredentials(password: Data("pw ✓".utf8), keyFile: nil, passwordHash: hash)
        await XCTAssertThrowsErrorAsync(try await Vault.openLocal(kdbx: bytes, credentials: both, cancel: CancelToken())) {
            XCTAssertEqual(($0 as! OvError).code, .invalidRequest)
        }
    }

    func testSyncDatabaseWithReachesTheServer() async throws {
        let c = client()
        let pw = KdbxCredentials(password: Data("pw".utf8), keyFile: nil)
        let bytes = try await c.createLocal(name: "Home", credentials: pw, cancel: CancelToken()).saveLocal(cancel: CancelToken())
        let sh = try SelfHosted.connect(client: c, serverUrl: "https://sync.test", deviceToken: Data("dev".utf8))
        // No stored state, so even `localChanged: false` downloads; the fake transport is offline
        await XCTAssertThrowsErrorAsync(try await sh.syncDatabaseWith(databaseId: "home", kdbx: bytes, credentials: pw,
                                                                      options: SyncOptions(localChanged: false, acceptServerState: false),
                                                                      cancel: CancelToken())) {
            XCTAssertEqual(($0 as! OvError).code, .networkError)
        }
    }
}
