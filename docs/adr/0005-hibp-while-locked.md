# ADR 0005: Breach scanning only while keys are resident

Status: accepted. Date: 2026-10-13.

## Context
Background Have-I-Been-Pwned scanning needs the plaintext password to compute SHA-1. Running the
scan while the vault is locked would require persisting something derived from each password
(the SHA-1, or its 5-character prefix plus suffix). An unsalted SHA-1 of a password on disk is an
offline-crackable artefact and would defeat the at-rest guarantees.

## Decision
- The scanner runs only while key material is resident (app unlocked, or within the background
  grace period before auto-lock). On macOS, where the app typically stays running and unlocked,
  this yields near-continuous coverage; on iOS, scans run on unlock for changed items and complete
  a weekly full pass opportunistically.
- Nothing derived from a password is persisted; the HIBP prefix cache stores only public range
  responses keyed by prefix.
- The "last scanned" timestamp per item is stored inside the encrypted item.

## Consequences
- On iOS, a person who rarely opens the app may have stale breach status; the Watchtower report
  shows the last scan time to make this visible.
