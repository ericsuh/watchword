#if canImport(CryptoKit)
    import CryptoKit

    /// `SymmetricKey` bridging (docs/02-architecture.md §11). CryptoKit keeps its own copy of a key's bytes, zeroised when
    /// the key is released, so `symmetricKey` is meant to live for one operation; the long-lived copy is the
    /// `SecureBytes`, which can be zeroised on lock rather than whenever the last reference happens to go.
    extension SecureBytes {
        public convenience init(copying key: SymmetricKey) {
            self.init(count: key.bitCount / 8, zeroisationProbe: nil)
            // Passing the method reference keeps an unsafe value inside the marked expression, so the marker is required
            // whether or not a given SDK annotates `withUnsafeBytes` as safe.
            unsafe (initializeStorage { destination in unsafe (key.withUnsafeBytes(destination.copyMemory(from:))) })
        }

        public var symmetricKey: SymmetricKey {
            SymmetricKey(data: self)
        }
    }
#endif
