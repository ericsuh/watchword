/// Which keys are next to which, for finding keyboard walks (`qwerty`, `1qaz2wsx`, `7410`).
///
/// Built at first use from the rows below, not embedded as a table: the rows are a US QWERTY keyboard and a numeric
/// keypad as printed on the keys, which is their only source. Other layouts (QWERTZ, AZERTY, Dvorak) are not
/// modelled; a walk on one of those is estimated as the characters it happens to be.
struct KeyboardGraph: Sendable {
    struct Key: Sendable, Equatable {
        let plain: Unicode.Scalar
        let shifted: Unicode.Scalar?
    }

    /// For each character on the layout (shifted or not), the keys around it, in a fixed order of directions; `nil`
    /// where there is no key. The position in the array is the direction, which is what "a turn" is counted from.
    let neighbours: [Unicode.Scalar: [Key?]]
    /// Whether the layout has shifted characters at all (the keypad does not).
    let hasShift: Bool
    /// How many places a walk can start, and how many ways on average it can continue: the two numbers the guess
    /// estimate needs.
    let startingPositions: Double
    let averageDegree: Double

    /// - Parameters:
    ///   - rows: top row first; each row's first key sits at column `offset`.
    ///   - slanted: whether rows are staggered, as on a typewriter keyboard (six neighbours), or aligned, as on a
    ///     keypad (eight).
    init(rows: [(offset: Int, keys: [String])], slanted: Bool) {
        struct Position: Hashable {
            var x: Int
            var y: Int
        }
        var keys: [Position: Key] = [:]
        var anyShift = false
        for (y, row) in rows.enumerated() {
            for (index, text) in row.keys.enumerated() {
                let scalars = Array(text.unicodeScalars)
                guard let plain = scalars.first else { continue }
                let shifted = scalars.count > 1 ? scalars[1] : nil
                anyShift = anyShift || shifted != nil
                keys[Position(x: row.offset + index, y: y)] = Key(plain: plain, shifted: shifted)
            }
        }
        let steps: [(Int, Int)] =
            slanted
            ? [(-1, 0), (0, -1), (1, -1), (1, 0), (0, 1), (-1, 1)]
            : [(-1, 0), (-1, -1), (0, -1), (1, -1), (1, 0), (1, 1), (0, 1), (-1, 1)]
        var neighbours: [Unicode.Scalar: [Key?]] = [:]
        var degreeTotal = 0
        for (position, key) in keys {
            let around = steps.map { keys[Position(x: position.x + $0.0, y: position.y + $0.1)] }
            let degree = around.filter { $0 != nil }.count
            neighbours[key.plain] = around
            degreeTotal += degree
            if let shifted = key.shifted {
                neighbours[shifted] = around
                degreeTotal += degree
            }
        }
        self.neighbours = neighbours
        hasShift = anyShift
        startingPositions = Double(neighbours.count)
        averageDegree = neighbours.isEmpty ? 1 : Double(degreeTotal) / Double(neighbours.count)
    }

    static let qwerty = KeyboardGraph(
        rows: [
            (0, ["`~", "1!", "2@", "3#", "4$", "5%", "6^", "7&", "8*", "9(", "0)", "-_", "=+"]),
            (1, ["qQ", "wW", "eE", "rR", "tT", "yY", "uU", "iI", "oO", "pP", "[{", "]}", "\\|"]),
            (1, ["aA", "sS", "dD", "fF", "gG", "hH", "jJ", "kK", "lL", ";:", "'\""]),
            (1, ["zZ", "xX", "cC", "vV", "bB", "nN", "mM", ",<", ".>", "/?"]),
        ], slanted: true)

    static let keypad = KeyboardGraph(
        rows: [
            (1, ["/", "*", "-"]),
            (0, ["7", "8", "9", "+"]),
            (0, ["4", "5", "6"]),
            (0, ["1", "2", "3"]),
            (1, ["0", "."]),
        ], slanted: false)

    static let all: [KeyboardGraph] = [qwerty, keypad]
}
