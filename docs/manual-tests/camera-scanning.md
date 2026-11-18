# Scanning a vault sharing code with the camera

ADR 0010 (Scanning), PRD F4.2 and `docs/02-architecture.md` §8.4. iPhone and iPad scan the other person's screen
with `DataScannerViewController`; a Mac shows codes and scans none. CI has no camera, so the scanner itself is checked
here; what it hands over is parsed and checked by portable code that the tests and the `sharing-code` fuzz target cover.

No production sharing board exists yet, so a session cannot reach another device's: these cases use a **Debug build
launched with `--uitest`** (add it to the scheme's arguments), whose sharing runs in process with the UI-test household
member, unlike the normal launch `README.md` asks for. A code shown by a second device is therefore one this device's
board does not know, which is what the cases expect. Remove the argument when you are done.

### The first scan asks for the camera, and refusing it still leaves typing

Steps:
1. On an iPhone or iPad that has never run Watchword with this build, open Settings, Vaults, a vault you created,
   Share This Vault, Invite Someone, and choose "Show Vault Sharing Code".
2. Choose "The household member types this code (UI test)", then "Scan Their Screen".
3. **Expected**: the system asks for the camera with the text "Watchword uses the camera only to scan the code on
   another person's screen when you share a vault with them."
4. Choose "Don't Allow".
5. **Expected**: the sheet says "Scanning Is Not Available" and points to Settings, Privacy & Security, Camera. Cancel
   closes it, and the field for the six digits is still there and works.
6. Allow the camera for Watchword in the system Settings and choose "Scan Their Screen" again.
7. **Expected**: the live camera appears, with no prompt.

### Only the live camera is a source

Steps:
1. Open the scanner as above.
2. **Expected**: there is no way to choose a photo, a file or the pasteboard. The only controls are the camera view
   and Cancel.
3. Take a screenshot of a Watchword QR code and open it on a second device's screen, then point the camera at that
   second screen.
4. **Expected**: the code is read as any code on a screen would be (a camera cannot tell); nothing on this device
   offered the saved image itself.

### A code that is not Watchword's does nothing

Steps:
1. On the invitation screen's step "Their confirmation code", choose "Scan Their Screen" and point the camera at any
   other QR code (a website's, a Wi-Fi network's).
2. **Expected**: the scanner closes after reading it, the screen says "Type the digits exactly as the other screen
   shows them.", and the number of tries left is unchanged.
3. On the Accept an Invitation screen, scan the same code.
4. **Expected**: the same sentence, and the screen still asks for the eight digits.

### A Watchword code from a device this one cannot reach is refused, not guessed at

Steps:
1. On a Mac running the same build with `--uitest`, open Invite Someone for a shared vault and choose "Show Vault
   Sharing Code".
2. On the iPhone, open Accept an Invitation, choose "Scan Their Screen" and scan the Mac's QR code.
3. **Expected**: "No one is sharing under that code." The iPhone joins nothing and pins nothing (each build's board
   is in its own process; with the production board this joins the Mac's session).

### The digits are read aloud as digits

Steps:
1. Turn on VoiceOver and open a screen showing a vault sharing code or a confirmation code.
2. Move to the digits.
3. **Expected**: VoiceOver reads each digit on its own, with a pause between the groups ("1 2 3 4, 5 6 7 8"), never
   "twelve million…".
4. Move to the QR code.
5. **Expected**: "QR code for the other person to scan".

### A Mac shows codes and offers no scan

Steps:
1. On a Mac, open Invite Someone and Accept an Invitation.
2. **Expected**: the vault sharing code and its QR code are shown; there is no "Scan Their Screen" button, and no
   "Scan the household member's screen (UI test)" stand-in either, even with `--uitest`: the stand-in is for iPhone and
   iPad, as the camera is.

### A release build has no stand-ins

Steps:
1. Build the Release configuration and run it without arguments.
2. **Expected**: no button anywhere ends in "(UI test)", in the sharing screens or in Settings.
