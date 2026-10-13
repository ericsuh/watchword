import Foundation

/// Entropy estimates derived from the generation process, not from a strength guesser (PRD F3.4).
public enum Entropy {
    /// Bits below which the UI warns.
    public static let warningThresholdBits = 64.0

    /// `log2` of the number of distinct passwords the policy can produce.
    ///
    /// - Without constraints: `length × log2(|alphabet|)`.
    /// - With `requireEachClass`: inclusion–exclusion over the selected classes gives the exact
    ///   count of strings containing at least one character of every class.
    /// - With `forbidRepeatedAdjacent`: `|A| × (|A| − 1)^(length − 1)`.
    /// - With both: the smaller of the two estimates (a conservative bound).
    public static func bits(for policy: RandomPasswordPolicy) throws -> Double {
        try policy.validate()
        let alphabet = try policy.alphabet()
        let a = Double(alphabet.count)
        let n = Double(policy.length)

        var candidates: [Double] = [n * log2(a)]

        if policy.requireEachClass {
            let classSets = policy.classes.members.map { Set(policy.characters(in: $0)) }.filter { !$0.isEmpty }
            let count = countWithEveryClass(alphabetSize: alphabet.count, classSets: classSets, length: policy.length)
            candidates.append(log2(count))
        }
        if policy.forbidRepeatedAdjacent {
            candidates.append(log2(a) + (n - 1) * log2(a - 1))
        }
        return candidates.min() ?? 0
    }

    public static func bits(for policy: PassphrasePolicy, wordlistCount: Int) -> Double {
        guard wordlistCount > 0 else { return 0 }
        var bits = Double(policy.wordCount) * log2(Double(wordlistCount))
        if policy.appendDigit { bits += log2(10) }
        return bits
    }

    public static func bits(forPINDigits digits: Int) -> Double {
        Double(digits) * log2(10)
    }

    /// Inclusion–exclusion: Σ_{S ⊆ classes} (−1)^|S| · (|A| − |∪S|)^n. Classes are disjoint by
    /// construction except that a custom symbol set may overlap digits/letters; overlap is handled
    /// by computing the real union size per subset.
    static func countWithEveryClass(alphabetSize: Int, classSets: [Set<Character>], length: Int) -> Double {
        let k = classSets.count
        guard k > 0 else { return pow(Double(alphabetSize), Double(length)) }
        var total = 0.0
        for mask in 0..<(1 << k) {
            var union = Set<Character>()
            var bitsSet = 0
            for i in 0..<k where mask & (1 << i) != 0 {
                union.formUnion(classSets[i])
                bitsSet += 1
            }
            let remaining = Double(alphabetSize - union.count)
            let term = pow(remaining, Double(length))
            total += (bitsSet % 2 == 0) ? term : -term
        }
        return max(total, 1)
    }
}
