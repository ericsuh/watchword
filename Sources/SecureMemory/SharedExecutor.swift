/// The owner of a serial executor that several actors run on (`SharesExecutor`). It does nothing itself: it exists so
/// that the executor has an owner every actor running on it holds strongly.
package actor SerialExecutorOwner {
    package init() {}
}

/// An actor that runs on the serial executor of `executorOwner`, which other actors share, so that code isolated to
/// one of them can call another's methods synchronously through `assumeIsolated` (ADR 0001, amendment of 2026-11-16).
///
/// What it is for: `VaultSession.lock()` is synchronous, and must drop its hygiene engine's reuse key and everything
/// it derived from a password before it returns, not in a task that runs later (docs/02-architecture.md §13.8,
/// review finding K2). An actor's state can be touched synchronously only from its own executor, so the session and
/// its engine share one. Sharing also means the two never run at the same time, so a lock never races an engine
/// computation that is reading the reuse key on another thread.
///
/// Why it is here: an `UnownedSerialExecutor` refers to its executor without owning it, so strict memory safety
/// classes reading another actor's `unownedExecutor` as unsafe. It is sound when the owner outlives every job
/// enqueued on its executor, and that holds because every conforming actor stores `executorOwner` as a `let`
/// (a job holds its actor, and the actor holds the owner). Conformers must store it, never compute it: a property
/// that returned a new owner on each read would give one actor several executors.
package protocol SharesExecutor: Actor {
    nonisolated var executorOwner: SerialExecutorOwner { get }
}

extension SharesExecutor {
    public nonisolated var unownedExecutor: UnownedSerialExecutor {
        unsafe (executorOwner.unownedExecutor)
    }
}
