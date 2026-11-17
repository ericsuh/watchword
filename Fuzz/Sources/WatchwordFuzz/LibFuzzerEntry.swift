#if WATCHWORD_LIBFUZZER
    import Foundation

    /// The target libFuzzer drives, named by `WATCHWORD_FUZZ_TARGET`. libFuzzer owns the command line, so the choice
    /// comes from the environment.
    private let selectedTarget: FuzzTarget = {
        let name = ProcessInfo.processInfo.environment["WATCHWORD_FUZZ_TARGET"] ?? ""
        guard let target = FuzzTarget(rawValue: name) else {
            let names = FuzzTarget.allCases.map(\.rawValue).joined(separator: ", ")
            fatalError("set WATCHWORD_FUZZ_TARGET to one of: \(names)")
        }
        return target
    }()

    /// libFuzzer's callback, a C function by its contract: the one declaration in this repository outside
    /// `SecureMemory` that names a pointer type. It copies the input into an array and touches the pointer no further.
    @_cdecl("LLVMFuzzerTestOneInput")
    public func fuzzerTestOneInput(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt {
        let bytes = start.map { Array(UnsafeBufferPointer(start: $0, count: count)) } ?? []
        selectedTarget.run(bytes)
        return 0
    }
#endif
