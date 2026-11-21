import Foundation
import OpenVireoRustCore
import XCTest

/// What OpenVireoKit does with a database, on the core's `Vault` (README "Kit on the core `Vault`"):
/// open a local `.kdbx` (Argon2d, 2 lanes, written by the desktop app), list entries and groups,
/// add/edit/move/delete entries, history, attachments, custom icons, the Recycle Bin, save and reopen.
final class VaultModelTests: XCTestCase {
    let password = KdbxCredentials(password: Data("desktop pw ✓".utf8), keyFile: nil)

    private func open(_ bytes: Data) async throws -> Vault {
        try await Vault.openLocal(kdbx: bytes, credentials: password, cancel: CancelToken())
    }

    private func text(_ e: EntryRecord, _ name: String) -> String? {
        e.fields.first { $0.name == name }.map { String(decoding: $0.value, as: UTF8.self) }
    }

    /// AutoFill checks a file's KDF memory before unlocking it (the iOS `KDBXFile.peekKDF`).
    func testPeekHeader() throws {
        let h = try kdbxPeekHeader(kdbx: vectorFile("kdbx/desktop-kdbx4-argon2d.kdbx"))
        XCTAssertEqual(h.versionMajor, 4)
        XCTAssertEqual(h.kdf, .argon2d)
        XCTAssertGreaterThan(h.memoryBytes, 0)
        XCTAssertEqual(try kdbxPeekHeader(kdbx: vectorFile("kdbx/desktop-kdbx31.kdbx")).kdf, .aesKdf)
        let vault = try kdbxPeekHeader(kdbx: vectorFile("vault-fixture.kdbx"))
        XCTAssertEqual([vault.kdf == .argon2id, vault.memoryBytes == 1024 * 1024], [true, true])
        XCTAssertThrowsError(try kdbxPeekHeader(kdbx: Data("nope".utf8))) { XCTAssertEqual(($0 as! OvError).code, .kdbxError) }
    }

    func testVaultFixtureOpensWithTheVaultKey() async throws {
        let v = V.root["vault_kdbx"]
        let vault = try await Vault.openLocal(kdbx: vectorFile(v["file"].string),
                                              credentials: KdbxCredentials(password: nil, keyFile: v["vault_key_hex"].hex), cancel: CancelToken())
        XCTAssertEqual(try vault.groups().first?.name, v["expect"]["root_group"].string)
        let e = try XCTUnwrap(vault.entries(includeRecycleBin: false).first { $0.title == v["expect"]["entry"]["Title"].string })
        let full = try vault.entry(entryId: e.id)
        for k in ["UserName", "Password", "URL"] {
            XCTAssertEqual(text(full, k), v["expect"]["entry"][k].string)
        }
    }

    func testKitEditingFlow() async throws {
        let bytes = vectorFile("kdbx/desktop-kdbx4-argon2d.kdbx")
        await XCTAssertThrowsErrorAsync(try await Vault.openLocal(kdbx: bytes, credentials: KdbxCredentials(password: Data("nope".utf8), keyFile: nil),
                                                                  cancel: CancelToken())) { XCTAssertEqual(($0 as! OvError).code, .vaultKeyMismatch) }
        let vault = try await open(bytes)
        XCTAssertFalse(try vault.entries(includeRecycleBin: false).isEmpty)
        XCTAssertTrue(try vault.entries(includeRecycleBin: false).contains { $0.title == "From desktop" })
        let root = try vault.rootGroupId()

        // groups by path (Kit keys groups by "A/B" paths)
        let work = try vault.ensureGroup(path: "Email/Work")
        XCTAssertEqual(try vault.groupIdAt(path: "Email/Work"), work)
        XCTAssertTrue(try vault.groups().contains { $0.path == ["Email", "Work"] })

        // add, then edit: the old version goes to history
        let id = try vault.addEntry(groupId: work, input: EntryInput(fields: [
            FieldInput(name: "title", value: Data("Mail".utf8), protected: nil),
            FieldInput(name: "password", value: Data("one".utf8), protected: nil),
            FieldInput(name: "Recovery", value: Data("code".utf8), protected: true),
        ], removeFields: [], tags: ["Favorite"], iconId: 19, expiry: .keep))
        try vault.editEntry(entryId: id, input: EntryInput(fields: [FieldInput(name: "Password", value: Data("two".utf8), protected: nil)],
                                                           removeFields: ["Recovery"], tags: nil, iconId: nil, expiry: .at(4_102_444_800)))
        var e = try vault.entry(entryId: id)
        XCTAssertEqual(text(e, "Password"), "two")
        XCTAssertNil(text(e, "Recovery"))
        XCTAssertEqual(e.tags, ["Favorite"])
        XCTAssertEqual(e.iconId, 19)
        XCTAssertEqual(e.expiresAt, 4_102_444_800)
        XCTAssertEqual(e.groupPath, ["Email", "Work"])
        XCTAssertEqual(e.historyCount, 1)
        XCTAssertEqual(try vault.history(entryId: id).first.flatMap { text($0, "Password") }, "one")

        // attachments and custom icons
        try vault.setAttachment(entryId: id, name: "note.txt", data: Data("hello".utf8))
        XCTAssertEqual(try vault.attachment(entryId: id, name: "note.txt"), Data("hello".utf8))
        let png = Data([0x89, 0x50, 0x4E, 0x47, 1, 2, 3])
        let icon = try vault.addCustomIcon(png: png)
        XCTAssertEqual(try vault.customIcon(iconId: icon), png)

        // move, delete to the Recycle Bin, restore
        try vault.moveEntry(entryId: id, groupId: root)
        XCTAssertEqual(try vault.entry(entryId: id).groupPath, [])
        try vault.deleteEntry(entryId: id)
        XCTAssertTrue(try vault.isInRecycleBin(id: id))
        XCTAssertFalse(try vault.entries(includeRecycleBin: false).contains { $0.id == id })
        XCTAssertTrue(try vault.entries(includeRecycleBin: true).contains { $0.id == id && $0.inRecycleBin })
        try vault.restoreFromRecycleBin(id: id)
        XCTAssertFalse(try vault.isInRecycleBin(id: id))

        // save and reopen: everything is still there
        let saved = try await vault.saveLocal(cancel: CancelToken())
        let reopened = try await open(saved)
        e = try reopened.entry(entryId: id)
        XCTAssertEqual(text(e, "Password"), "two")
        XCTAssertEqual(e.attachments.map(\.name), ["note.txt"])
        XCTAssertEqual(e.historyCount, try vault.entry(entryId: id).historyCount)
        XCTAssertEqual(try reopened.customIcon(iconId: icon), png)

        // a group delete goes to the Recycle Bin, emptying it removes it for good
        try reopened.deleteGroup(groupId: work)
        try reopened.emptyRecycleBin()
        XCTAssertNil(try reopened.groupIdAt(path: "Email/Work"))
        let csv = String(decoding: try reopened.exportPlain(format: .csv, groupIds: nil), as: UTF8.self)
        // contract-v1.8: the web app's header, unquoted
        XCTAssertTrue(csv.hasPrefix("Folder,Title,Username,Password,URL,Notes"))
    }
}

func XCTAssertThrowsErrorAsync<T>(_ expression: @autoclosure () async throws -> T, _ check: (Error) -> Void = { _ in },
                                  file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await expression()
        XCTFail("no error thrown", file: file, line: line)
    } catch {
        check(error)
    }
}
