# ADR 0001: Memory-safe implementation language

Status: accepted. Date: 2026-10-13.

## Context
A password manager's core handles the most sensitive data a person has. Memory-safety bugs (buffer
overflows, use-after-free) are the dominant class of exploitable vulnerabilities in C/C++ code.
The product requirement (PRD P1) is that all first-party code be written in a memory-safe
language. Candidates: Swift, Rust (as 1Password uses for its core), or a mix.

## Decision
- All first-party code is Swift in Swift 6 language mode with strict concurrency.
- Unsafe constructs (`Unsafe*Pointer`, `unsafeBitCast`, `@unsafe` declarations) are allowed only
  in the `SecureMemory` module, which exists to zeroise and page-lock key material.
- CI builds every other module with `-strict-memory-safety` (SE-0458) and `-warnings-as-errors`
  on Swift 6.2+ toolchains; the SwiftPM `strictMemorySafety()` setting is adopted when the
  package moves to tools version 6.2.
- Cryptography comes only from Apple frameworks (CryptoKit, Security, CommonCrypto). Those are not
  Swift, but they are the platform's audited implementations and the alternative (third-party or
  self-written crypto) is riskier.
- Rust is not used in v1. Reasons: the Swift↔Rust FFI boundary is itself `unsafe`, it doubles the
  toolchain and CI surface, and there is no cross-platform requirement yet. If Android or Windows
  clients become a goal, a Rust core behind a generated (UniFFI-style) binding is the planned path,
  and the module boundaries in `02-architecture.md` §15 are drawn to make that swap possible.

## Amendment (2026-10-14, milestone 1): marking rather than exempting

`SecureMemory` is not exempted from the strict-memory-safety build. Each unsafe construct in it is
marked with an `unsafe` expression, so the CI job proves every pointer use is marked, and a separate
check (`.github/scripts/assert-unsafe-confined.sh`) proves the markers appear nowhere else. Swift
6.0/6.1 do not know the keyword; `unsafe (expression)`, written with a space, parses as the keyword
on 6.2+ and as a call to an identity function on older compilers (`UnsafeMarker.swift`). This
avoids both a per-target exemption, which would hide unmarked uses inside the module, and raising
the tools version, which would drop the Xcode 16 leg of the CI matrix.

## Consequences
- Developers must justify any new `unsafe` use in review and place it in `SecureMemory`.
- Argon2id is unavailable without third-party code; see ADR 0003.
