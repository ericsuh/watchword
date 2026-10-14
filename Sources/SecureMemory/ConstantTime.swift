/// Comparison whose running time does not depend on where two byte strings first differ.
///
/// Used for checksums, fingerprints and key material (docs/04-test-plan.md §6.1, "Timing"). Lengths are not secret
/// in any caller, so a length mismatch returns early.
public enum ConstantTime {
    public static func equal<A: Collection, B: Collection>(_ a: A, _ b: B) -> Bool
    where A.Element == UInt8, B.Element == UInt8 {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for (x, y) in zip(a, b) {
            difference |= x ^ y
        }
        return difference == 0
    }
}
