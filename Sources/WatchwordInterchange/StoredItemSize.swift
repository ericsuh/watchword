import Foundation
import WatchwordModel

/// An upper bound on the bytes the vault stores for a draft, so that an entry reported as imported is one the vault
/// can save (PRD SEC7, SEC9; docs/02-architecture.md §5, §14).
///
/// The vault stores an item as JSON and refuses a payload over 1 MiB (`ItemCodec`), and what it stores is not what a
/// file holds: JSON escaping writes a control character as six bytes and a quote, backslash or slash as two; every
/// field also carries a sync stamp; and the notes are stored a second time as one record per line, each with two
/// identifiers. A row of 512 KiB of control characters is three megabytes there, and 256 KiB of line breaks is fifty.
///
/// This module may not depend on the session or on sync, so the bound is computed here from the shape of
/// `WatchwordModel`'s types as the vault writes them on a first save from one device. It errs high. The adversarial
/// suite checks it against the real encoder (`ItemMerge.stamped`, then `ItemCodec.encode`) for the shapes that
/// inflate most, so a change to the stored form that outgrows the bound fails a test, not an import.
public enum StoredItemSize {
    /// `{"id":"<36>","kind":"<16>","label":,"meta":{},"value":}` and the comma after it, without the three texts.
    static let fieldOverhead = 112
    /// A field's entry in `Item.revisions`: `"field.<36>":{"revision":{"device":"<36>","version":<20>},"seen":
    /// {"<36>":<20>}}` and its comma.
    static let stampOverhead = 216
    /// One `NoteLine` without its text: two identifiers of a device, a version and an index each, and a flag.
    static let noteLineOverhead = 272
    /// `{"excludedHosts":[],"host":,"includeSubdomains":false}` and its comma.
    static let scopeOverhead = 64
    /// `{"fields":[],"replacedAt":<25>,"version":<20>}` and its comma.
    static let historyEntryOverhead = 80
    /// The item's own keys, identifiers, dates, flags and clock, and the stamps of its eight attributes.
    static let itemOverhead = 1_024 + 8 * stampOverhead

    /// The bytes of `text` as a JSON string, quotes included, as Foundation's encoder writes it on any platform:
    /// six for a control character (and DEL, which some versions escape), two for a quote, a backslash or a slash.
    static func escapedBytes(_ text: String) -> Int {
        var count = 2
        for byte in text.utf8 {
            switch byte {
            case 0..<0x20, 0x7F: count += 6
            case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): count += 2
            default: count += 1
            }
        }
        return count
    }

    private static func bytes(of field: Field) -> Int {
        var count = fieldOverhead + escapedBytes(field.label) + escapedBytes(field.value)
        for (key, value) in field.meta {
            count += escapedBytes(key) + escapedBytes(value) + 2
        }
        return count
    }

    /// An upper bound on the stored size of `item` after its first save. Linear in the item.
    public static func estimate(_ item: Item) -> Int {
        var count = itemOverhead + escapedBytes(item.title)
        // The notes are stored as text and again line by line. A line ends at a line feed; a line feed that is part
        // of a longer character does not end one, so this counts at least as many lines as the vault will make.
        let lines = item.notes.isEmpty ? 0 : item.notes.utf8.reduce(1) { $1 == 0x0A ? $0 + 1 : $0 }
        count += 2 * escapedBytes(item.notes) + lines * noteLineOverhead
        for scope in item.scopes {
            count += scopeOverhead + escapedBytes(scope.host)
            for host in scope.excludedHosts {
                count += escapedBytes(host) + 1
            }
        }
        for field in item.fields {
            count += bytes(of: field) + stampOverhead
        }
        for tag in item.tags {
            count += escapedBytes(tag) + 1
        }
        for entry in item.history {
            count += historyEntryOverhead
            for field in entry.fields {
                count += bytes(of: field)
            }
        }
        return count
    }
}
