import Foundation
import OpenVireoRustCore
import XCTest

/// Swift implementations of the foreign Host traits, enough to build an `OvClient`.
final class FakeHttp: HttpTransport, @unchecked Sendable {
    func send(req: HttpRequest) async throws -> HttpResponse {
        throw TransportError.Offline
    }

    func openStream(req: HttpRequest) async throws -> OpenedStream {
        throw TransportError.Offline
    }
}

final class FakeStore: SecureStore, @unchecked Sendable {
    func get(key: String) async throws -> Data? { nil }
    func set(key: String, value: Data) async throws {}
    func delete(key: String) async throws {}
}

final class FakeCache: BlobCache, @unchecked Sendable {
    func load(userId: String, vaultId: String) async throws -> CachedVault? { nil }
    func save(userId: String, vaultId: String, v: CachedVault) async throws {}
    func remove(userId: String, vaultId: String) async throws {}
    func list(userId: String) async throws -> [String] { [] }
    func loadMeta(userId: String, name: String) async throws -> Data? { nil }
    func saveMeta(userId: String, name: String, value: Data) async throws {}
    func clearUser(userId: String) async throws {}
}

final class FakeClock: Clock, @unchecked Sendable {
    func nowUnixMs() -> Int64 { 1_700_000_000_000 }
}

final class FakeLog: LogSink, @unchecked Sendable {
    func log(level: Level, target: String, msg: String) {}
}

final class HostTests: XCTestCase {
    func makeClient() -> OvClient {
        let host = Host(http: FakeHttp(), store: FakeStore(), cache: FakeCache(), clock: FakeClock(), log: FakeLog())
        let config = ClientConfig(
            device: DeviceInfo(id: nil, name: "smoke", platform: .ios),
            offline: false,
            server: nil
        )
        return OvClient(config: config, host: host)
    }

    func testClientKeepsItsConfig() throws {
        let config = try makeClient().config()
        XCTAssertEqual(config.device.name, "smoke")
        XCTAssertEqual(config.device.platform, .ios)
    }

    /// An async facade call runs through the Swift Host: the fake transport is offline, so discovery
    /// fails with `network_error` (at W1-BS the facade was stubs and this was `internal`).
    func testAsyncCallUsesTheHost() async {
        do {
            _ = try await makeClient().discover(issuer: "https://example.test", cancel: CancelToken())
            XCTFail("expected an error")
        } catch let e as OvError {
            XCTAssertEqual(e.code, .networkError)
        } catch {
            XCTFail("unexpected \(error)")
        }
    }
}
