import Foundation
import OpenVireoRustCore
import XCTest

/// A transport that answers a self-hosted server's history routes from canned responses.
final class HistoryHttp: HttpTransport, @unchecked Sendable {
    let versions: Data
    let revision1: Data

    init(versions: Data, revision1: Data) {
        self.versions = versions
        self.revision1 = revision1
    }

    func send(req: HttpRequest) async throws -> HttpResponse {
        if req.url.hasSuffix("/databases/home/history") {
            return HttpResponse(status: 200, headers: [HttpHeader(name: "content-type", value: "application/json")], body: versions)
        }
        if req.url.hasSuffix("/databases/home/history/1") {
            return HttpResponse(status: 200, headers: [HttpHeader(name: "etag", value: "\"r1\"")], body: revision1)
        }
        return HttpResponse(status: 404, headers: [], body: Data("{\"error\":\"not_found\"}".utf8))
    }

    func openStream(req: HttpRequest) async throws -> OpenedStream {
        throw TransportError.Offline
    }
}

/// contract-v1.6 on the Swift binding (docs/adr/0001-contract.md): entry last use, colours, custom
/// icons and field order, caller-chosen ids, attachment protection, every record in one call, local
/// imports with a preview, file metadata and KDFs, self-hosted history, local vaults on the Host clock.
final class ContractV16Tests: XCTestCase {
    let pw = KdbxCredentials(password: Data("pw".utf8), keyFile: nil)

    private func client(_ http: HttpTransport = FakeHttp()) -> OvClient {
        let host = Host(http: http, store: FakeStore(), cache: FakeCache(), clock: FakeClock(), log: FakeLog())
        return OvClient(config: ClientConfig(device: DeviceInfo(id: nil, name: "smoke", platform: .ios), offline: false, server: nil),
                        host: host)
    }

    private func field(_ name: String, _ value: String) -> FieldInput {
        FieldInput(name: name, value: Data(value.utf8), protected: nil)
    }

    func testEntriesAttachmentsAndChosenIds() async throws {
        let v = try await client().createLocal(name: "Home", credentials: pw, cancel: CancelToken())
        let icon = try v.addCustomIcon(png: Data([0x89, 0x50, 0x4E, 0x47]))
        let id = try v.addEntryWithId(entryId: "0123456789ABCDEF0123456789ABCDEF", groupId: v.rootGroupId(),
                                      input: EntryInput(fields: [field("Title", "Mail"), field("B", "b"), field("A", "a")],
                                                        removeFields: [], tags: nil, iconId: nil, expiry: .keep,
                                                        foregroundColor: "#112233", backgroundColor: nil, customIcon: icon,
                                                        fieldOrder: ["A", "B"]))
        XCTAssertEqual(id, "0123456789abcdef0123456789abcdef")
        XCTAssertThrowsError(try v.addEntryWithId(entryId: id, groupId: v.rootGroupId(), input: EntryInput(fields: [], removeFields: [], tags: nil, iconId: nil, expiry: .keep))) {
            XCTAssertEqual(($0 as! OvError).code, .conflict)
        }
        var e = try v.entry(entryId: id)
        XCTAssertEqual(e.modifiedAt, 1_700_000_000) // the Host clock, not the system's
        XCTAssertEqual([e.foregroundColor, e.customIcon], ["#112233", icon])
        XCTAssertEqual(e.fields.suffix(2).map(\.name), ["A", "B"])
        XCTAssertNil(e.lastAccessAt)
        XCTAssertEqual(e.usageCount, 0)

        try v.editEntry(entryId: id, input: EntryInput(fields: [], removeFields: [], tags: nil, iconId: nil, expiry: .keep,
                                                       customIcon: .some(nil)))
        XCTAssertNil(try v.entry(entryId: id).customIcon)

        try v.setAttachmentWith(entryId: id, name: "plain.txt", data: Data("hi".utf8), protected: false)
        try v.setAttachment(entryId: id, name: "secret.bin", data: Data("s".utf8))
        e = try v.entry(entryId: id)
        XCTAssertEqual(e.attachments.map(\.protected), [false, true])

        let records = try v.entryRecords(includeRecycleBin: false)
        XCTAssertEqual(records.map(\.id), try v.entries(includeRecycleBin: false).map(\.id))
        XCTAssertEqual(try v.entries(includeRecycleBin: false).first?.usageCount, 0)
    }

    func testImportMetadataAndKdf() async throws {
        let c = client()
        let source = try await c.createLocal(name: "Work", credentials: pw, cancel: CancelToken())
        _ = try source.addEntry(groupId: source.ensureGroup(path: "Servers"), input: EntryInput(fields: [field("Title", "db")], removeFields: [], tags: nil, iconId: nil, expiry: .keep))
        XCTAssertEqual(try source.importPreview(), ImportPreview(entries: 1, groups: 1))

        let target = try await c.createLocal(name: "Home", credentials: pw, cancel: CancelToken())
        let into = try target.ensureGroup(path: "Imported")
        XCTAssertEqual(try target.importTargets().map(\.path), ["Home", "Home / Imported"])
        let copies = try target.importFrom(source: source, mode: .copies(parentGroupId: into))
        XCTAssertEqual([copies.added, copies.groupsAdded], [1, 2])
        let merged = try target.importFrom(source: source, mode: .merge)
        XCTAssertEqual(merged.added, 1)

        try target.setName(name: "Family")
        XCTAssertEqual(try target.name(), "Family")
        try target.setMetaCustomData(key: "KPXC_REMOTE_SYNC_SETTINGS", value: #"[{"type":"syncServer","url":"https://s"}]"#)
        let copy = try target.copyWithoutRemotes(credentials: KdbxCredentials(password: Data("copy".utf8), keyFile: nil))
        XCTAssertNil(try copy.metaCustomData(key: "KPXC_REMOTE_SYNC_SETTINGS"))
        XCTAssertNotNil(try target.metaCustomData(key: "KPXC_REMOTE_SYNC_SETTINGS"))
        try copy.setKdf(kdf: .argon2id(memory: 1 << 20, iterations: 3, parallelism: 1))
        let saved = try await copy.saveLocal(cancel: CancelToken())
        XCTAssertEqual(try kdbxPeekHeader(kdbx: saved).kdf, .argon2id)
        XCTAssertThrowsError(try copy.setKdf(kdf: .aesKdf(rounds: 0))) { XCTAssertEqual(($0 as! OvError).code, .invalidRequest) }

        let exported = try await target.exportKdbxWith(credentials: pw, groupIds: nil, kdf: .aesKdf(rounds: 100), cancel: CancelToken())
        XCTAssertEqual(try kdbxPeekHeader(kdbx: exported).kdf, .aesKdf)
        let reopened = try await c.openLocal(kdbx: exported, credentials: pw, cancel: CancelToken())
        XCTAssertEqual(try reopened.entries(includeRecycleBin: false).count, 2)
    }

    func testSelfHostedHistoryAndVersions() async throws {
        let old = try await client().createLocal(name: "Home", credentials: pw, cancel: CancelToken())
        _ = try old.addEntry(groupId: old.rootGroupId(), input: EntryInput(fields: [field("Title", "Wifi")], removeFields: [], tags: nil, iconId: nil, expiry: .keep))
        let bytes = try await old.saveLocal(cancel: CancelToken())
        let versions = Data(#"{"versions":[{"id":"home","etag":"\"r2\"","revision":2,"size":10,"updatedAt":"2026-11-19T10:00:00Z"},{"id":"home","etag":"\"r1\"","revision":1,"size":9,"updatedAt":"2026-11-18T10:00:00Z"}]}"#.utf8)
        let c = client(HistoryHttp(versions: versions, revision1: bytes))
        let sh = try SelfHosted.connect(client: c, serverUrl: "https://sync.test", deviceToken: Data("dev".utf8))
        let history = try await sh.history(databaseId: "home", cancel: CancelToken())
        XCTAssertEqual(history.map(\.revision), [2, 1])
        XCTAssertEqual(history.map(\.isCurrent), [true, false])
        let v1 = try await sh.openVersion(databaseId: "home", revision: 1, credentials: pw, cancel: CancelToken())
        XCTAssertTrue(try v1.isReadOnly())
        XCTAssertEqual(try v1.entries(includeRecycleBin: false).map(\.title), ["Wifi"])
        XCTAssertEqual(try v1.etag(), "\"r1\"")
    }
}
