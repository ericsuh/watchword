# The Keychain, and what stays on this device

`docs/02-architecture.md` §5 and §11. The Secret Key and the quick-unlock key are stored for this device only
(`ThisDeviceOnly`), so a backup or a transfer to another device must not carry them. `mise run app:test-keychain
--team <ID>` checks the Keychain round trip itself on a Mac; these cases check what a person can see.

### The account survives quitting and reopening the app

Steps:
1. Create an account, add an item, and quit Watchword from the app switcher.
2. Open Watchword.
3. **Expected**: "Watchword is locked". The account password unlocks, and the item is there. The Secret Key is not
   asked for.

### A wrong account password never unlocks

Steps:
1. On the lock screen, type a wrong password and choose "Unlock".
2. **Expected**: an error, and the app stays locked. The message does not say whether the password or anything
   else was the cause.

### A device restored from a backup has no Secret Key

Steps:
1. Back the device up (to a Mac, encrypted, or to iCloud).
2. Erase a second device, or this one, and restore the backup onto it.
3. Open Watchword on the restored device.
4. **Expected**: Watchword does not unlock with the account password alone. It behaves as a device that has not
   been set up (it asks to create an account or for the Emergency Kit's details), or says its key is missing.
5. **Expected**: Face ID or Touch ID is not offered.

### Deleting the app removes the account from the device

Steps:
1. Delete Watchword from the device and install it again.
2. **Expected**: the first screen is "Create your Watchword account". Nothing from the earlier account is shown or
   offered.

### The device passcode is required for the Keychain items

Steps:
1. On a device with no passcode, install Watchword and try to create an account.
2. **Expected**: account creation either explains that a device passcode is needed, or completes without offering
   quick unlock. It never stores the account without the protection `docs/02-architecture.md` §11 states. Note
   which of the two you saw.
