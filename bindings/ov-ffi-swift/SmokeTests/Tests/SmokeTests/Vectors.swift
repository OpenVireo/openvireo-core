import Foundation
import OpenVireoRustCore

/// The repo's `vectors/` folder, found from this file's path (SmokeTests/Tests/SmokeTests/ → repo root).
let vectorsDir: URL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("vectors")

func vectorFile(_ relative: String) -> Data {
    try! Data(contentsOf: vectorsDir.appendingPathComponent(relative))
}

/// Untyped access to a vectors JSON file, as the iOS suites read `test-vectors.json`.
struct V {
    let value: Any?

    static let root = V(value: try! JSONSerialization.jsonObject(with: vectorFile("test-vectors.json")))
    static let opaque = V(value: try! JSONSerialization.jsonObject(with: vectorFile("opaque-transcripts.json")))

    subscript(_ key: String) -> V { V(value: (value as? [String: Any])?[key]) }
    subscript(_ i: Int) -> V { V(value: (value as? [Any])?[i]) }

    var array: [V] { (value as? [Any] ?? []).map { V(value: $0) } }
    var isPresent: Bool { value != nil && !(value is NSNull) }
    var string: String { value as! String }
    var int: Int { (value as! NSNumber).intValue }
    var hex: Data { Data(hex: string) }
    var b64: Data { try! b64uDecode(text: string) }
}

extension Data {
    init(hex: String) {
        var out = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            out.append(UInt8(hex[i ..< j], radix: 16)!)
            i = j
        }
        self = out
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
