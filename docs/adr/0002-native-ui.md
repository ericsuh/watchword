# ADR 0002: Native user interface only

Status: accepted. Date: 2026-10-13.

## Context
PRD P2 forbids Electron, Tauri and similar web-view shells. Mac Catalyst is also under
consideration because it would let one UIKit codebase serve iPad and Mac.

## Decision
- SwiftUI for all screens, with AppKit (macOS) and UIKit (iOS/iPadOS) where SwiftUI lacks an API
  (menu bar extra, `NSSharingService`, secure text field behaviours).
- Separate native macOS app target; no Mac Catalyst. Apple's documentation states that
  `ASCredentialProviderViewController` "ignores calls from Mac apps built with Mac Catalyst", so a
  Catalyst app could not provide AutoFill on the Mac.
- No web content in the UI at all (no `WKWebView` for help pages; help is rendered natively).

## Consequences
- Two app targets and two AutoFill extension targets share one Swift package; UI code is kept thin
  so that duplication is limited to platform-specific presentation.
