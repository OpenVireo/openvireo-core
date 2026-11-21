import Foundation
import OpenVireoRustCore
import XCTest

/// contract-v1.8 on the Swift binding (docs/adr/0001-contract.md): Recycle Bin restore to the previous
/// group through a saved file, `restoreEntry` on a binned entry, the web app's plain export, and the new
/// calls (`shareVaultWithKeys`, `SelfHosted.download`, the service account's vault files, `Profile.kdf`).
final class ContractV18Tests: XCTestCase {
    private func client() -> OvClient {
        let host = Host(http: FakeHttp(), store: FakeStore(), cache: FakeCache(), clock: FakeClock(), log: FakeLog())
        return OvClient(config: ClientConfig(device: DeviceInfo(id: nil, name: "smoke", platform: .ios), offline: false, server: nil),
                        host: host)
    }

    private let pw = KdbxCredentials(password: Data("pw".utf8), keyFile: nil)

    private func input(_ fields: [(String, String)]) -> EntryInput {
        EntryInput(fields: fields.map { FieldInput(name: $0.0, value: Data($0.1.utf8), protected: nil) },
                   removeFields: [], tags: nil, iconId: nil, expiry: .keep)
    }

    func testTheRecycleBinRestoresToThePreviousGroupAfterASave() async throws {
        let v = try await client().createLocal(name: "Home", credentials: pw, cancel: CancelToken())
        let work = try v.addGroup(parentId: nil, name: "Work")
        let id = try v.addEntry(groupId: work, input: input([("Title", "VPN")]))
        try v.deleteEntry(entryId: id)
        let bytes = try await v.saveLocal(cancel: CancelToken())
        let back = try await Vault.openLocal(kdbx: bytes, credentials: pw, cancel: CancelToken())
        try back.restoreFromRecycleBin(id: id)
        XCTAssertEqual(try back.entry(entryId: id).groupPath, ["Work"])
    }

    func testRestoringABinnedEntryKeepsItsHistory() async throws {
        let v = try await client().createLocal(name: "Home", credentials: pw, cancel: CancelToken())
        let work = try v.addGroup(parentId: nil, name: "Work")
        let id = try v.addEntry(groupId: work, input: input([("Title", "VPN"), ("Password", "v1")]))
        let version = try v.copyWithoutRemotes(credentials: nil)
        try v.editEntry(entryId: id, input: input([("Password", "v2")]))
        try v.deleteEntry(entryId: id)
        try v.restoreEntry(version: version, entryId: id, groupPath: "Elsewhere")
        let rec = try v.entry(entryId: id)
        XCTAssertFalse(try v.isInRecycleBin(id: id))
        XCTAssertEqual(rec.groupPath, ["Work"])
        XCTAssertEqual(rec.historyCount, 2)
        XCTAssertEqual(rec.fields.first { $0.name == "Password" }?.value, Data("v1".utf8))
    }

    func testPlainExportIsTheWebAppsFormat() async throws {
        let v = try await client().createLocal(name: "Home", credentials: pw, cancel: CancelToken())
        let work = try v.addGroup(parentId: nil, name: "Work")
        _ = try v.addEntry(groupId: work, input: input([("Title", "VPN"), ("UserName", "ops"), ("Password", "p\"w")]))
        let csv = String(decoding: try v.exportPlain(format: .csv, groupIds: nil), as: UTF8.self)
        XCTAssertEqual(csv, "Folder,Title,Username,Password,URL,Notes\n\"Work\",\"VPN\",\"ops\",\"p\"\"w\",\"\",\"\"")
        let json = String(decoding: try v.exportPlain(format: .json, groupIds: nil), as: UTF8.self)
        XCTAssertEqual(json, """
        [
          {
            "folder": "Work",
            "title": "VPN",
            "username": "ops",
            "passwordValue": "p\\"w",
            "url": "",
            "notes": ""
          }
        ]
        """)
    }

    func testTheNewCallsAreThere() async throws {
        let sh = try SelfHosted.connect(client: client(), serverUrl: "https://sync.test", deviceToken: Data("dev".utf8))
        await XCTAssertThrowsErrorAsync(try await sh.download(databaseId: "home", cancel: CancelToken())) {
            XCTAssertEqual(($0 as! OvError).code, .networkError)
        }
        await XCTAssertThrowsErrorAsync(try await sh.health(cancel: CancelToken())) {
            XCTAssertEqual(($0 as! OvError).code, .networkError)
        }
        // Signatures only (they need a server): shareVaultWithKeys, the SA's vault files, the profile's keys
        let share: (Account) -> (String, Grantee, VaultRole, PublicKeys, CancelToken) async throws -> GrantResult = Account.shareVaultWithKeys
        let creds: (ServiceAccount) -> (String, CancelToken) async throws -> KdbxCredentials = ServiceAccount.vaultKdbxCredentials
        let sync: (ServiceAccount) -> (String, Data, Data?, SyncOptions, CancelToken) async throws -> VaultKdbxSyncResult = ServiceAccount.syncVaultKdbx
        _ = (share, creds, sync, \Profile.kdf, \Profile.publicKeys)
    }
}
