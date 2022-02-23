# Qt2FA
A desktop 2FA authenticator written in Python with Qt.  
My first Qt application, not properly organized and has a tendency to have a segmentation fault for some reason.

This small program emulates the functionality of a 2FA app you might find on your phone, removing the security factor in favor of convenience by having the 2FA tokens generated on the same machine you're authenticating...  
A key feature of this app is the screenshot function, which decodes and imports 2FA QR codes intended for phones on your screen. If the QR code is in an irregular format, it will allow users to manually extract the data by displaying the QR code's contents as plaintext.

## Screenshots
![Password dialog](https://user-images.githubusercontent.com/63184095/155293791-646cdc6d-76ad-4606-8361-aa4f16ec229d.png)

![Main window](https://user-images.githubusercontent.com/63184095/155304233-c64efd7a-574d-46e2-8c20-0defc2245ee2.png)

![Edit dialog](https://user-images.githubusercontent.com/63184095/155293779-52f25d33-fd49-4779-959f-56cd46d50f78.png)

## Dependencies
- `opencv-python`
- `pyqt5`
- `pyautogui`
- `cryptography`
- `pyzbar`

## Usage
### Loading, saving, and encryption
The secret keys stored by the app are hashed with a password, which is asked of the user at launch. If there are no secrets to load, entering a password sets the encryption used to save entered codes to `secrets.json` once the program closes.  
If there _are_ 2FA codes in `secrets.json`, but none can be loaded, it will ask the user to retry unless the "Ignore Errors" checkbox is checked. In that case, despite none of the secrets being decrypted and usable, the user will still be able to add codes. This potentially allows for multi-user access, as only decrypted codes will be processed.

### Main Window
The progress bar in the top-left indicates how much time there is until a new code is generated. Press the "New Code" button to create and edit a blank code, or "Screenshot" to import and edit a QR code visible on the screen.  
The table in the center of the window displays the 2FA codes. Double-clicking on the left 2 columns of a code will open the edit dialog for it, while double-clicking on the right column will copy the 2FA token to the clipboard. While a code is selected, you can press the "Up" and "Down" buttons in the lower-right to reorder the list.  
To change the password used to hash your secret keys, press the "Recrypt" button. When the program closes, it will encrypt your codes with a new password rather than the one used to decrypt the codes initially.  
To export your 2FA code data with no encryption, press the "Export Keys" button. It will save to `exported_secrets.json`.

### Editing codes
The edit dialog will show you fields to edit a code's custom name, its secret key, and issuer/account data. These will only be applied when pressing the "Apply" button - closing the dialog will reset any changes made.  
To delete a code, you must apply all empty fields - this allows you to cancel the deletion by closing the window. The "Delete" button automatically clears all the fields.  
If a QR code is read with no apparent data, it will be displayed on the right for manual extraction of data.
