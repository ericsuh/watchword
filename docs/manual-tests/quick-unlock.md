# Quick unlock (Face ID and Touch ID)

Requirements F5.2 to F5.5 and `docs/02-architecture.md` §5. On a real device the Local Unlock Key is held by the
Keychain behind the Secure Enclave; none of that exists in the simulator.

### Turning quick unlock on asks for the account password

Steps:
1. Unlock Watchword with the account password and open Settings.
2. Under "Quick unlock", turn on "Unlock with biometrics".
3. **Expected**: an alert titled "Enter your account password" appears. Nothing is turned on yet.
4. Type a wrong password and choose "Turn On".
5. **Expected**: an error is shown and the switch is off.
6. Turn the switch on again, type the right password and choose "Turn On".
7. **Expected**: the switch stays on.

### Face ID or Touch ID unlocks the app

Steps:
1. With quick unlock on, leave Watchword for the Home Screen and come back.
2. **Expected**: the screen says "Watchword is locked" and offers "Use biometrics".
3. Choose "Use biometrics" and let the device recognise you.
4. **Expected**: the system's Face ID or Touch ID prompt appears, and then the item list.

### A face or finger that is not recognised does not unlock, and three failures require the password

Steps:
1. Lock Watchword. Choose "Use biometrics" and make the recognition fail (cover the camera, or use a finger that is
   not enrolled) until the system gives up.
2. **Expected**: Watchword stays locked.
3. Repeat until that has happened three times.
4. **Expected**: "Use biometrics" is no longer offered, or choosing it says the password is required. Only the
   account password unlocks.
5. Unlock with the account password.
6. **Expected**: after the next lock, "Use biometrics" is offered again.

### Cancelling the system prompt does not unlock

Steps:
1. Lock Watchword, choose "Use biometrics", and cancel the system prompt.
2. **Expected**: Watchword stays locked, with no error that suggests anything was wrong.

### Enrolling a new face or finger requires the password again

Steps:
1. With quick unlock on, lock Watchword.
2. In the system Settings, add a fingerprint, or set up an alternative appearance for Face ID.
3. Open Watchword and choose "Use biometrics".
4. **Expected**: Watchword does not unlock with biometrics. It asks for the account password.
5. Unlock with the account password, lock, and choose "Use biometrics".
6. **Expected**: biometrics work again.

### Removing the passcode removes quick unlock

Steps:
1. With quick unlock on, lock Watchword and turn the device passcode off in the system Settings.
2. Open Watchword.
3. **Expected**: only the account password is offered. After unlocking with it, the "Unlock with biometrics" switch
   in Settings is off or cannot be turned on.
4. Turn the passcode back on when you are done.

### Turning quick unlock off takes effect at once

Steps:
1. In Settings, turn "Unlock with biometrics" off. Leave the app and come back.
2. **Expected**: only the account password is offered.

### Restarting the device does not skip the password rules

Steps:
1. With quick unlock on, restart the device and unlock it with its passcode.
2. Open Watchword and choose "Use biometrics".
3. **Expected**: either the biometric prompt appears and unlocks, or the account password is asked for. The item
   list never appears without one of the two.
