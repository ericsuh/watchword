# The Emergency Kit

Requirements F10.1 and F10.2 and `docs/02-architecture.md` §15. The PDF is drawn with CoreGraphics, so CI checks
that it is made, not that a person can read and use it.

### Setting up an account does not finish until the kit is acknowledged

Steps:
1. Create a new account.
2. **Expected**: the Emergency Kit is shown, with the Secret Key and the warning that Watchword cannot recover the
   account.
3. **Expected**: "Continue" cannot be used until "I have saved or printed my Emergency Kit" is on.

### The PDF holds what is needed to sign in on a new device, and no password

Steps:
1. Choose "Save Emergency Kit PDF…" and save it to "On My iPhone" (on a Mac, the Desktop). Open it.
2. **Expected**: one page titled "Watchword Emergency Kit", with "Account ID", "Secret Key", a QR code, a line to
   write the account password by hand, and the warning that Watchword cannot recover the account.
3. **Expected**: the account password is not printed anywhere on it.
4. Compare the Secret Key on the page with the one the app shows, character by character.
5. **Expected**: they are the same.

### The printed kit can be read back

Steps:
1. Print the PDF, on paper, at its normal size.
2. **Expected**: every character of the Secret Key is legible; `0` and `O`, and `1`, `I` and `l`, cannot be mistaken
   for one another.
3. Scan the printed QR code with the system Camera app.
4. **Expected**: the camera reads it as text that begins `WWKIT1:` and contains the same Account ID and Secret Key
   as the page. It does not offer to open a web page.

### The kit can be shown again from Settings

Steps:
1. Settings, "Show Emergency Kit…".
2. **Expected**: the same Secret Key as on the PDF saved earlier.

### Saving the kit leaves no second copy

Steps:
1. On a Mac, save the kit to the Desktop, then run
   `find ~/Library/Containers -path '*atchword*' -name '*.pdf' 2>/dev/null` in Terminal.
2. **Expected**: nothing is listed.
3. Choose "Save Emergency Kit PDF…" again and cancel the system's sheet.
4. **Expected**: the `find` still lists nothing.
