# Manual test cases

What only a person with real devices can check. Everything a machine can check is in `Tests/` and `Apps/UITests`
(`docs/04-test-plan.md` maps requirements to those); the cases here exist because CI has no Secure Enclave, no
enrolled finger or face, no camera, no signed and entitled build, and no second person. Each file covers one area:

| File | Area | Why it cannot be automated |
|---|---|---|
| [`quick-unlock.md`](quick-unlock.md) | Face ID and Touch ID | The simulator has no Secure Enclave and CI has no enrolled biometrics. |
| [`keychain-and-device-binding.md`](keychain-and-device-binding.md) | What the Keychain keeps, and where it will not follow | Needs a signed, entitled build and a device backup or a second device. |
| [`export-and-backup.md`](export-and-backup.md) | Exported files, the `.watchwordbackup` type, restore | The system file picker and the Files app are outside the app's process. |
| [`emergency-kit.md`](emergency-kit.md) | The Emergency Kit PDF | Printing, and scanning a printed page, need paper and a camera. |
| [`screen-privacy.md`](screen-privacy.md) | The app switcher, locking on leaving | The app switcher's snapshot is taken by the system. |
| [`camera-scanning.md`](camera-scanning.md) | Scanning a vault sharing code (ADR 0010) | CI has no camera, and the permission prompt is the system's. |
| [`vault-sharing-code.md`](vault-sharing-code.md) | Two people checking each other with a vault sharing code | Needs two people at two devices (one, with the UI-test stand-ins, until the board adapter exists). |

Cases are added with the feature they cover, in the same pull request. Not here yet, because the feature is not
built: AutoFill in Safari and other apps, and sync over iCloud. The two sharing-code files use a Debug build launched
with `--uitest`, not the normal launch below, until the sharing board has a production adapter: each says so.

## Before you start

- A Mac with the Xcode version in `CLAUDE.md`, and an iPhone or iPad with a passcode and Face ID or Touch ID set up.
- `mise run app:generate`, open `Apps/Watchword.xcodeproj`, choose your development team for the app targets (do
  not commit it), and run the `Watchword` scheme on the device. Run a **normal launch**: no `--uitest` argument,
  which would replace the Keychain, the database and the file picker with stand-ins.
- Use an account made for testing, with made-up items. Several cases export every item in clear text.

## Format

Every case is a heading that states the behaviour, then numbered steps. A step that begins **Expected** is a check:
the case passes only if every one of them holds.

```
### The behaviour, as a sentence

Steps:
1. Do something.
2. **Expected**: what you must see.
```

When a check fails, note the device, the OS version, the commit, and what you saw in its place, and open an issue
that names the case's heading.
