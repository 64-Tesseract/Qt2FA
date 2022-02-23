#!/usr/bin/python3

import sys, os, time, json, math  # Random stuff
# import PyQt5, PyQt5.QtWidgets  # UI stuff
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from pyautogui import screenshot  # Screengrabs QR codes
from pyzbar.pyzbar import decode as zbardecode  # Reads QR codes
import cv2  # Format used by zbar
import numpy as np # Convert PIL image to cv2
from urllib import parse  # Parses QR code data

from securesecret import * # Loads & saves codes encrypted with a password
from oauthcode import *  # Key & data manipulation class


def next_interval (interval):
    """Gets time in seconds until the next multiple of `interval`."""
    return time.time() + interval - (time.time()) % interval


def parse_url_query (url):
    """Extracts URL queries"""
    vals = {}
    for param in url.split("&"):
        k, v = param.split("=")
        vals[k] = v
    return vals


class AutoButton (QPushButton):
    """Define button text, function, and tooltip all at once."""
    def __init__ (self, text, func, txt = None):
        super().__init__(text)
        self.setStatusTip(txt)
        self.pressed.connect(func)


class PermStatus (QStatusBar):
    """Status bar that defaults to a permanent message once a tooltip message is cleared."""
    def __init__ (self):
        super().__init__()
        self.perm_txt = None
        self.messageChanged.connect(self.update_message)
    
    def perm_message (self, txt):
        """Sets new permanent message."""
        self.perm_txt = f"[{time.strftime('%H:%M:%S')}] {txt}"
        self.showMessage(self.perm_txt)
    
    def update_message (self, txt):
        """When message is cleared, set it back to permanent message."""
        if txt == "" and self.perm_txt != "":
            self.showMessage(self.perm_txt)


class WidgetBox (QWidget):
    """Sets a layout and adds widgets all at once."""
    def __init__ (self, layout: QLayout, *widgets: QWidget, parent = None):
        super().__init__(parent)
        
        box = layout()
        for widget in widgets:
            box.addWidget(widget)
        self.setLayout(box)


class PasswordDialog (QDialog):
    """Asks user for a password and whether to ignore decryption errors."""
    def __init__ (self, pass_fail = False):
        super().__init__()
        self.setFixedSize(180, 120)
        self.setWindowTitle("Decrypt Secrets")
        
        self.password = QLineEdit()
        self.password.setGraphicsEffect(RedGlow())
        self.password.graphicsEffect().set_on(pass_fail)
        self.ignore_errors_chk = QCheckBox("Ignore\nErrors")
        self.accept_btn = AutoButton("Decrypt", self.accept)
        
        box = WidgetBox(QVBoxLayout,
                        QLabel("Password"),
                        self.password,
                        WidgetBox(QHBoxLayout,
                                  self.ignore_errors_chk,
                                  self.accept_btn),
                        parent = self
                        )
        
        box.resize(180, 120)
        
        self.setModal(True)
    
    def exec_ (self):
        """Will return both the accepted value and dialog inputs."""
        accepted = super().exec_()
        return accepted, self.password.text(), self.ignore_errors_chk.isChecked()


class RedGlow (QGraphicsDropShadowEffect):
    """Effect applied to invalid fields that can be toggled."""
    def __init__ (self):
        super().__init__()
        self.setOffset(0)
        self.setColor(QColor("#f00"))
        self.set_on(False)
    
    def set_on (self, on):
        self.setBlurRadius(5 if on else 0)


class ThreadWorker (QThread):
    """Runs a passed function in a QThread."""
    def __init__ (self, func):
        super().__init__()
        self.func = func
        self.start()
    
    def run (self):
        self.func()
                

class MainWin (QMainWindow):
    """Main Auth application window."""
    def __init__ (self):
        app = QApplication(sys.argv)
        super().__init__()
        self.clipboard = app.clipboard()
        
        self.setFixedSize(350, 400)
        self.setWindowTitle("Qt2FA")
        self.codes = []  # OAuthCodes stored in here
        
        self.bar = QProgressBar()  # Shows how much time until next tokens generated
        self.bar.setTextVisible(False)
        self.bar.setMaximum(30)
        
        self.table = QTableWidget()  # Shows token info
        self.table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContentsOnFirstShow)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)  # Select rows instead of individual cells
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)  # Only select 1 row at a time
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Custom Name", "Service", "Token"])
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # Read-only
        self.table.cellDoubleClicked.connect(self.handle_table_click)
        self.table.itemSelectionChanged.connect(self.able_move_btns)  # When selected/deselected, enable/disable move buttons
        
        self.up_btn = AutoButton("Up", lambda: self.row_move(-1), "Move selected row up")  # Move rows up/down in table
        self.dn_btn = AutoButton("Down", lambda: self.row_move(1), "Move selected row down")
        self.up_btn.setFixedWidth(40)
        self.dn_btn.setFixedWidth(40)
        self.up_btn.setEnabled(False)
        self.dn_btn.setEnabled(False)
        
        self.top_btns = WidgetBox(QHBoxLayout,  # Top & bottom widget rows
                                  self.bar,
                                  AutoButton("New Code", self.create_code, "Manually add code info"),
                                  AutoButton("Screenshot", self.screenshot, "Scan the screen for a QR code to import"))
        self.btm_btns = WidgetBox(QHBoxLayout,
                                  AutoButton("Recrypt", self.recrypt, "Change password used for hashing codes on exit"),
                                  AutoButton("Export Keys", self.export, "Export codes as decrypted JSON"),
                                  self.up_btn,
                                  self.dn_btn)
        self.top_btns.layout().setContentsMargins(0, 0, 0, 0)
        self.btm_btns.layout().setContentsMargins(0, 0, 0, 0)
        
        w = WidgetBox(QVBoxLayout,  # Main widget column
                      self.top_btns,
                      self.table,
                      self.btm_btns)
        
        self.status = PermStatus()
        self.setStatusBar(self.status)
        self.setCentralWidget(w)
        
        self.refresh_thread = ThreadWorker(self.refresh_loop)  # Refresh progress bar & tokens in a thread
        
        # Continue asking for decryption password until at least one code has imported without errors
        pass_fail = False
        while True:
            accepted, password, ignore_errors = PasswordDialog(pass_fail).exec_()
            # QInputDialog.getText(self, "Decrypt secrets", "Could not decrypt, try again" if pass_fail else "Enter decryption password")
            if not accepted:
                sys.exit()
            
            fernet.gen_fernet(password)  # Generate key based on password & try decrypting codes with it
            decrypted_codes, some_corrupt = fernet.load_json()
            
            code_count = len(decrypted_codes)  # At least 1 code should import successfuly
            if (not ignore_errors) and code_count != 0 and some_corrupt >= code_count:
                pass_fail = True
                continue
            
            self.add_codes(decrypted_codes)
            break
        
        if some_corrupt == 0:  # Show message based on codes imported
            if code_count == 0:
                self.set_status(f"Welcome to Qt2FA, create some codes!")
            else:
                self.set_status(f"Successfully loaded {code_count} auth codes")
        else:
            self.set_status(f"Loaded {len(decrypted_codes)} auth codes with {some_corrupt} errors")
        
        
        app.aboutToQuit.connect(lambda: fernet.save_json(self.codes))
        
        self.show()
        sys.exit(app.exec_())
    
    def set_status (self, txt):
        self.status.perm_message(txt)
    
    def recrypt (self):
        """Give Fernet new password to encrypt with on exit."""
        password, accepted = QInputDialog.getText(self, "Recrypt", "Set new password")
        if accepted:
            fernet.gen_fernet(password)
            self.set_status("Updated password")
    
    def export (self):
        self.set_status("Exported secrets as plaintext")
        fernet.export_json(self.codes)
    
    def add_codes (self, codes: list):
        for code in codes:
            self.add_code(code)
    
    def add_code (self, code = None):
        """Add OAuthCode to start of list and add it to top of table."""
        if code == None:
            code = OAuthCode("", "", "", "")
        self.codes = [code] + self.codes
        self.table.insertRow(0)
        self.table.setItem(0, 0, QTableWidgetItem())
        self.table.setItem(0, 1, QTableWidgetItem())
        self.table.setItem(0, 2, QTableWidgetItem())
        self.refresh_row(0)  # Update text
    
    def handle_table_click (self, row, col):
        """Perform different function based on where a row was double-clicked."""
        if col == 2:
            self.copy_token(row)
        else:
            self.edit_row(row)
    
    def create_code (self):
        """Create empty code and get user to edit it."""
        self.add_code()
        self.edit_row(0, True)
    
    def edit_row (self, row, new = False, qr_data = None):
        """Show dialog to edit a code."""
        edit_dialog = EditDialog("1")
        edit_dialog.set_edit(self.codes[row], qr_data)  # Set dialog's fields to mirror code
        row_name = self.codes[row].name  # Old name to show what has been renamed
        accepted = edit_dialog.exec_()
        
        if self.codes[row].empty() or new and accepted == 0:  # If code emptied & accepted, or new already empty code cancelled, delete code
            del self.codes[row]
            self.table.removeRow(row)
            if not new:
                self.set_status(f"Deleted code '{row_name}'")
            else:
                self.set_status("Cancelled adding code")
        
        elif accepted == 1:  # If dialog accepted, update table
            new_name = self.codes[row].name
            self.refresh_row(row)
            if row_name == new_name or new:
                self.set_status(f"Saved code '{new_name}'")
            else:
                self.set_status(f"Saved code '{new_name}' (was '{row_name}')")
    
    def copy_token (self, row):
        """Copy current token to clipboard, when double-clicked."""
        token = self.codes[row].gen_token()
        if token:
            self.clipboard.setText(token)
            self.set_status("Copied token")
        else:
            self.set_status("Invalid secret")
    
    def able_move_btns (self):
        """Check if a code is selected, if it is enable the movement buttons."""
        enabled = self.table.currentRow() != -1
        self.up_btn.setEnabled(enabled)
        self.dn_btn.setEnabled(enabled)
    
    def row_move (self, updown):
        """Move a row along the table in a direction."""
        row1 = self.table.currentRow()
        if row1 == -1:
            return
        
        row2 = row1 + updown
        if row2 == -1 or row2 == len(self.codes):
            return
        
        temp = self.codes[row1]  # Swap in list
        self.codes[row1] = self.codes[row2]
        self.codes[row2] = temp
        
        self.refresh_row(row1)  # Update table data
        self.refresh_row(row2)
        self.table.setCurrentItem(self.table.item(row2, 0))  # Set selected row to moved code
    
    def refresh_row (self, row):
        """Update data in a row to match data in list."""
        code = self.codes[row]
        styled_name = f"[{code.name}]" if code.hash != "" and code.secret == "" else code.name
        self.table.item(row, 0).setText(styled_name)
        self.table.item(row, 1).setText(f"{code.issuer}{':' if code.issuer != '' and code.account != '' else ''}{code.account}")
        self.table.item(row, 2).setText(code.format_token())
    
    def refresh_loop (self):
        """Loop run in thread - refreshes progress bar & tokens when needed."""
        next_bar_run = 0
        next_token_run = 0
        while True:
            if time.time() >= next_bar_run:  # Every second, update bar
                self.bar.setValue(min(math.floor(time.time() % 30 + 1), 30))  # Set bar progress
                self.bar.update()
                next_bar_run = next_interval(1)
                
                if time.time() >= next_token_run:  # Every 30 seconds, update tokens, but only needs to be checked every second
                    for c in range(self.table.rowCount()):  # Regen every code's token
                        self.table.item(c, 2).setText(self.codes[c].format_token())
                    next_token_run = next_interval(30)
            time.sleep(0.01)
    
    def screenshot (self):
        """Take a screenshot and look for QR codes to import."""
        self.setWindowState(Qt.WindowMinimized)  # Minimize window
        time.sleep(0.25)
        ss = screenshot()
        time.sleep(0.25)
        self.setWindowState(Qt.WindowActive)  # Restore window

        # ss.save("tempqr.png")  # Why was I doing this???
        # img = cv2imread("tempqr.png")
        # data = zbardecode(img)
        # os.remove("tempqr.png")
        
        img = np.asarray(ss)  # Convert PIL image to cv2 image for zbar
        data = zbardecode(img)
        
        if data == None or len(data) == 0:  # Make sure there is a QR code on screen
            self.set_status("Could not find QR code!")
            return
        
        url = parse.unquote(data[0].data.decode("utf-8"), encoding = "utf-8", errors = "replace")  # Decode QR data
        parsed_url = parse.urlparse(url)
        query = parse_url_query(parsed_url.query)
        
        if parsed_url.scheme != "otpauth" or parsed_url.netloc != "totp" or "secret" not in query:  # Validate QR code
            self.set_status("Can't recognize format! Extract manually?")
            self.add_code()
            self.edit_row(0, True, url)  # Show edit dialog with raw data
            return
        
        self.set_status("Found a QR code!")
        
        new_name = parsed_url.path[1:]  # Try to extract info from QR code data
        split_name = new_name.split("@")
        issuer = query["issuer"] if "issuer" in query else split_name[1] if len(split_name) == 2 else ""
        account = parsed_url.username if parsed_url.username else query["account"] if "account" in query else split_name[0] if len(split_name) == 2 else ""
        self.add_code(OAuthCode(new_name,
                                query["secret"],
                                issuer,
                                account))
    
        self.edit_row(0, True)
    
    def not_implemented_message (self):
        d = QMessageBox()
        d.setIcon(QMessageBox.Critical)
        d.setWindowTitle("WIP")
        d.setText("This isn't implemented yet.")
        d.setDetailedText("can't be bothered")
        d.exec_()


class EditDialog (QDialog):
    """Shows a dialog box that allows users to edit an OAuthCode object."""
    def __init__ (self, qr_data = None):
        super().__init__()
        self.setFixedSize(250, 180)
        self.setWindowTitle("Edit 2FA Code")
        
        w = QWidget(self)
        form = QFormLayout()
        self.name_line = QLineEdit()
        self.secret_line = QLineEdit()
        self.issuer_line = QLineEdit()
        self.account_line = QLineEdit()
        form.addRow("Name", self.name_line)
        form.addRow("Secret", self.secret_line)
        form.addRow("Issuer", self.issuer_line)
        form.addRow("Account", self.account_line)
        
        self.secret_line.setGraphicsEffect(RedGlow())
        self.secret_line.textChanged.connect(self.check_secret)
        
        box = QHBoxLayout()
        self.apply_btn = AutoButton("Apply", self.apply_edit)
        box.addWidget(AutoButton("Delete", self.clear))
        self.apply_btn.setDefault(True)
        box.addWidget(self.apply_btn)
        box.setContentsMargins(0, 0, 0, 0)
        form.addRow(box)
        
        w.setLayout(form)
        w.resize(250, 180)
        
        self.setModal(True)
    
    def set_edit (self, code, qr_data = None):
        """Sets dialog input fields to OAuthCode vars - separate as the dialog used to be static, now could be merged into `__init__`."""
        self.name_line.setText(code.name.strip())
        self.secret_line.setText(code.secret.strip())
        self.issuer_line.setText(code.issuer.strip())
        self.account_line.setText(code.account.strip())
        
        if qr_data:  # If raw QR code data passed (bad read), show it on the side
            raw_qr_data = QTextEdit()
            raw_qr_data.setReadOnly(True)
            error_box = WidgetBox(QVBoxLayout,
                                  QLabel("Raw QR Data"),
                                  raw_qr_data,
                                  parent = self)
            error_box.setFixedSize(150, 180)
            error_box.move(250, 0)
            error_box.setContentsMargins(0, 0, 0, 0)
            
            raw_qr_data.setText(qr_data)
            
            self.setFixedSize(400, 180)
        
        self.editing = code
        self.check_secret()
    
    def clear (self):
        self.name_line.clear()
        self.secret_line.clear()
        self.issuer_line.clear()
        self.account_line.clear()
    
    def apply_edit (self):
        """Sets the OAuthObject's vars to inputted values."""
        self.editing.set_vals(self.name_line.text().strip(), self.secret_line.text().strip(), self.issuer_line.text().strip(), self.account_line.text().strip())
        self.accept()
    
    def check_secret (self):
        """Gives secret line red glow if it's not valid."""
        self.secret_line.graphicsEffect().set_on(not valid_secret(self.secret_line.text(), True))


fernet = SecureSecret()
win = MainWin()