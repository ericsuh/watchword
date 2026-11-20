# Exported files, backups and restore

Requirements F8.x and `docs/02-architecture.md` §14.1. In UI tests a button stands in for the system file picker;
these cases use the real one, the Files app and Finder.

### A plaintext export is refused without the account password

Steps:
1. Settings, "Export and Back Up". Choose "Apple Passwords CSV (not encrypted)".
2. **Expected**: a warning that the file is not encrypted is on screen before anything is typed.
3. Type a wrong account password and choose "Export".
4. **Expected**: an error. No "Save File…" button appears.
5. Type the right password and choose "Export".
6. **Expected**: a section "Before you save it" with the number of items in the file, then "Save File…".

### The exported file reaches the place you choose, and no copy stays behind

Steps:
1. After the case above, choose "Save File…" and pick a folder in "On My iPhone" (on a Mac, the Desktop).
2. **Expected**: the file is there, and it opens as CSV with every item, each value exactly as stored.
3. On a Mac, in Terminal: `find ~/Library/Containers -path '*atchword*' -name '*.csv' 2>/dev/null`.
4. **Expected**: nothing is listed.
5. Export again, and this time cancel the system's save sheet.
6. **Expected**: back in Watchword nothing was saved, and the `find` above still lists nothing.

### Locking while the save sheet is open withdraws the file

Steps:
1. Export a CSV and choose "Save File…". With the system's sheet open, leave the app for the Home Screen.
2. Come back and unlock.
3. **Expected**: the export screen no longer offers the file made before the lock. Saving needs a new export, with
   the password typed again.

### A backup is saved as a Watchword Backup

Steps:
1. "Export and Back Up", choose "Encrypted Watchword archive", type the account password and an archive passphrase
   twice, and choose "Create Backup".
2. **Expected**: the screen says that restoring needs this passphrase and the Secret Key, and that neither is
   stored in the file.
3. Choose "Save File…" and save it to "On My iPhone" (on a Mac, the Desktop).
4. **Expected**: the file's name ends in `.watchwordbackup`.
5. In the Files app, long-press the file and choose "Get Info" (on a Mac, select it in Finder and choose Get Info).
6. **Expected**: its kind is "Watchword Backup".

### Opening a backup from Files or Finder does not open Watchword

Steps:
1. Tap the saved `.watchwordbackup` file in the Files app (on a Mac, double-click it in Finder).
2. **Expected**: Watchword does not open and nothing is restored. The system shows a preview that cannot read it, or
   says no app opens it.
3. Share the file from Files and look at the apps offered.
4. **Expected**: Watchword is not offered as a place to open it.

### Restore offers only backups, and restores one

Steps:
1. Settings, "Restore from a Backup". Choose "Choose Backup…".
2. **Expected**: in the picker, the `.watchwordbackup` file can be chosen; the CSV exported earlier, and photos or
   documents beside it, cannot.
3. Choose the backup, type its passphrase, leave the Secret Key empty, and continue.
4. **Expected**: the date the backup was made is shown, with the advice to stop if a newer one was expected.
5. **Expected**: every item in the backup is listed, and items already in the vault are shown as duplicates to
   decide on, one by one.

### A backup does not open with a wrong passphrase, and says no more than that

Steps:
1. Restore the same backup with a wrong passphrase.
2. **Expected**: an error that the backup could not be opened. It does not say whether the passphrase or the
   Secret Key was wrong.
3. Open the `.watchwordbackup` file in a text or hex editor.
4. **Expected**: no item title, user name, website or password can be read in it.

### A backup of another account needs that account's Secret Key

Steps:
1. On a second test account (another device, or after deleting and reinstalling the app), choose "Restore from a
   Backup" and pick the first account's backup.
2. Type the right passphrase and leave the Secret Key empty.
3. **Expected**: the backup does not open.
4. Type the first account's Secret Key from its Emergency Kit, and the passphrase.
5. **Expected**: the backup opens and its items are listed.

### An exported file is protected while the device is locked (iPhone and iPad)

Steps:
1. Export a CSV and choose "Save File…", and leave the system's sheet open without saving.
2. Lock the device with the side button and wait a minute.
3. Connect the device to a Mac and look for the app's files in Finder's file sharing, or in a device backup made
   now.
4. **Expected**: no CSV from Watchword is readable there.
5. Unlock the device and cancel the sheet.
