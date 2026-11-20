# What the screen shows when you are not looking at the app

Requirement F5.7 and `docs/02-architecture.md` §5 (auto-lock).

### The app switcher shows a cover, not your items (iPhone and iPad)

Steps:
1. Unlock Watchword, open an item, and reveal its password.
2. Swipe up to the app switcher and look at Watchword's card.
3. **Expected**: the card shows a plain cover. No title, user name or password can be read on it.

### Leaving the app locks it

Steps:
1. Unlock Watchword, go to the Home Screen, and come straight back.
2. **Expected**: "Watchword is locked".

### A revealed password is hidden again after a lock

Steps:
1. Open an item, reveal its password, leave the app and unlock again.
2. **Expected**: the item's password is concealed (`••••••••`) until revealed again.

### A copied password leaves the clipboard

Steps:
1. Copy a password from an item. Paste it into Notes to see that it was copied.
2. Wait a little over a minute, then paste into Notes again.
3. **Expected**: the password is no longer pasted.
4. Copy a password again, lock Watchword at once, and paste into Notes.
5. **Expected**: the password is not pasted.
6. On a Mac with an iPhone nearby and Handoff on, copy a password on one and try to paste on the other.
7. **Expected**: it does not paste on the other device.

### The Mac app locks on sleep and on the screen lock

Steps:
1. Unlock Watchword on a Mac. Lock the screen (Control-Command-Q) and unlock the Mac.
2. **Expected**: "Watchword is locked".
3. Unlock Watchword, close the lid or choose Sleep, and wake the Mac.
4. **Expected**: "Watchword is locked".
