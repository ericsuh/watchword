# Checking each other with a vault sharing code

ADR 0010, PRD F4.1 and F4.2, `docs/02-architecture.md` §8.4. The protocol is tested end to end in process (two real
sessions over an in-memory board, and `VaultSharingTests` with the UI-test household member); what is left for a person
is what two people see and do: whose screen the digits are on, a slip of the finger, the time limit, a lock.

The sharing board has no production adapter yet, so two physical devices cannot meet: until it exists, run these on
one device with a **Debug build launched with `--uitest`**, where the "(UI test)" buttons stand in for the other
person, exactly as `camera-scanning.md` says. When the board exists, run them again with two people, each on their own
device, the "(UI test)" steps replaced by the other person doing what they say.

### Each person types the other's code, and nothing can be chosen before both match

Steps:
1. Open Settings, Vaults, a vault you created, Share This Vault, Invite Someone.
2. **Expected**: the screen says both devices are needed, warns against digits sent in a message, and offers "Show
   Vault Sharing Code" and, separately, "Use the Full Code Instead".
3. Choose "Show Vault Sharing Code".
4. **Expected**: eight digits in two groups of four, a QR code, "Waiting for their device…", and no role or Send
   button.
5. Choose "The household member types this code (UI test)".
6. **Expected**: within a few seconds the screen asks for the six digits on their screen, with three tries left.
7. Choose "Fill in the household member's code (UI test)", then "Check".
8. **Expected**: your own six digits appear, with the role picker and "Send Invitation"; the line under the invitee
   says their confirmation code matched.
9. Choose "Send Invitation" before the household member types your six digits.
10. **Expected**: "Sent. It appears on their device once it has checked your confirmation code.", with your six digits
    still on the screen.

### The full code: the screen shows only your own

Steps:
1. Open Invite Someone, choose "Use the Full Code Instead", choose "Use the UI-test household member" and "Look Up".
2. **Expected**: a field for their full vault sharing code, which the footer says to take from their own device
   (Settings, Vaults, Your Full Vault Sharing Code), and, in a separate section headed "Your full vault sharing code",
   this account's own sixty digits (the ones in Settings, Vaults, Your Full Vault Sharing Code here). No sixty digits of
   theirs appear anywhere on the screen.
3. Type the digits the screen shows and choose "Check".
4. **Expected**: "does not match"; nothing is pinned.

### A wrong code says how many tries are left, and the third ends the session

Steps:
1. Start a session as above until it asks for their six digits.
2. Type `000000` and choose "Check".
3. **Expected**: "That code does not match. 2 tries left; check each digit with them. If their screen now shows other digits than before, stop and start a new code."
4. Do it twice more.
5. **Expected**: the session ends with "The confirmation code was wrong three times, so this was stopped and nothing
   was shared…", and "Start Over". The member list does not show the household member as verified.

### Ten minutes without progress end the session

Steps:
1. Start a session and leave it at "Waiting for their device…" for more than ten minutes (keep the device awake).
2. Choose "The household member types this code (UI test)".
3. **Expected**: the session ends with "This took more than ten minutes and was stopped. Start again."

### A lock ends the session

Steps:
1. Start a session until it asks for their six digits.
2. Lock Watchword (Settings, Lock), and unlock it again.
3. Open Invite Someone again.
4. **Expected**: the screen is back at its start; the earlier number is gone and nothing was pinned.

### Joining the other person's vault

Steps:
1. Open Settings, Vaults, Accept an Invitation.
2. **Expected**: a field for eight digits, "Scan Their Screen" on iPhone and iPad, and "Paste an Invitation Instead".
3. Choose "The household member starts sharing (UI test)", then "Continue".
4. **Expected**: your six digits and a QR code, and a field for theirs.
5. Choose "The household member types this code (UI test)", "Fill in the household member's code (UI test)", and
   "Check".
6. **Expected**: "You checked each other. Waiting for their invitation…".
7. Choose "The household member sends the invitation (UI test)".
8. **Expected**: "Join a vault shared by the account …?" with Join Vault and Don't Join. Nothing is joined yet.
9. Choose "Join Vault".
10. **Expected**: "You joined the vault." After a sync the vault "Shared by the household member" is in the list.

### Every step shows your account check

Steps:
1. Start Invite Someone with a vault sharing code, and on another device (or the UI-test household) Accept an
   Invitation by scanning it.
2. **Expected**: on every step of both screens (the number, "Type the six digits from their screen", choosing a role,
   the invitation sent; on the other side waiting, the codes, the scan's confirmation, waiting for the invitation) a
   line "Your account check: " and four groups of five digits, the same on every step of one device.
3. **Expected**: the scanning device's "Your camera read a code whose account check is …" names exactly the digits the
   other device shows as its own.

### A shared vault that is not set up on this device

Steps (a debug build with a second device of an account that is a member of a shared vault, or a device whose
`sharing.sqlite` was removed while the app was closed):
1. Open Settings, Vaults.
2. **Expected**: the vault is listed as "Shared · not set up here" (or "Shared · check its owner" when only the
   owner's pin is missing), read-only, with no rename; its items can be read.
3. Open the vault. **Expected**: the banner says why, and offers "Set Up on This Device" (not for "check its owner");
   no "Share This Vault…".
4. Choose "Set Up on This Device". **Expected**: the vault is shared again with its members listed, and every item it
   held is still there.

### An invitation survives a session that ends before it is sent

Steps:
1. Start Invite Someone, check each other, choose a role and Send; before it finishes, choose Start Over (or let the
   device lock).
2. Invite the same person again with a new session. **Expected**: the invitation arrives on their device; they are not
   added twice. With "Use the Full Code Instead" the invitation is shown as text.

### An administrator's invitation waits while you check the owner

Steps (once the production board exists, or with a second account in a `--uitest` build that offers one):
1. Have an administrator who is not the vault's owner invite you with a vault sharing code.
2. **Expected**: after your codes match, "This vault belongs to the account …, not to the person you just checked",
   with "Check the Owner" and "Don't Join".
3. Choose "Check the Owner"; have the owner open the vault's member list, choose to check you, and read you their
   eight digits; type them, and exchange the six-digit codes.
4. **Expected**: "Join a vault shared by the account …?" for the owner's account. Nothing was joined before.

### With two people: the digits come from the other screen

Steps (once the production board exists):
1. With a second person beside you, each on your own device, run "Each person types the other's code…" above, the
   other person typing your eight digits on their device and reading their six to you.
2. **Expected**: your device shows its own six only after you typed theirs correctly; theirs accepts only the six
   your screen shows.
3. Have them read you six digits that are not on their screen.
4. **Expected**: refused, with the tries left.
