// Swift 6.2 added `unsafe` expressions (SE-0458), and the `strict-memory-safety` CI job requires every unsafe
// operation in this module to be marked with one. Swift 6.0 and 6.1 (Xcode 16.x, still in the CI matrix) do not know
// the keyword, so on those compilers this function stands in for it.
//
// Write the marker with a space, `unsafe (expression)`: Swift 6.2 and later parse that as the keyword applied to a
// parenthesised expression, and older compilers parse it as a call to this function. Without the space, newer
// compilers also parse it as a call, find no such function, and fail the build — loudly, which is the safe failure.
#if !compiler(>=6.2)
    @discardableResult
    @inline(__always)
    func unsafe<T>(_ value: @autoclosure () throws -> T) rethrows -> T {
        try value()
    }
#endif
