#!/usr/bin/python3

import os, json
from hashlib import sha256
from base64 import b64encode
from cryptography.fernet import Fernet

from oauthcode import *


class SecureSecret:
    def __init__ (self):
        self.fernet = None
    
    def gen_fernet (self, password):
        """Creates a hash object `Fernet` with the password."""
        sha = sha256(password.encode("utf-8"))
        b64 = b64encode(sha.digest())
        self.fernet = Fernet(b64)
    
    def encrypt (self, value):
        """If the Fernet has been set, encrypt a string."""
        if self.fernet == None:
            raise UninitializedException()
        
        return self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")
    
    def decrypt (self, value):
        """If the Fernet has been set and the encrypted string is valid, decrypt it."""
        if self.fernet == None:
            raise UninitializedException()
        
        try:
            return self.fernet.decrypt(value.encode("utf-8")).decode("utf-8")
        except:
            return ""
    
    def load_json (self):
        """Loads saved OAuthCodes and tries to decrypt their secrets."""
        if self.fernet == None:
            raise UninitializedException()
        
        if os.path.isfile("secrets.json"):
            with open("secrets.json", "r") as f:
                json_codes = json.load(f)
            
            codes = []
            some_corrupt = 0
            for code in json_codes["services"]:  # Try to extract info from JSON
                secret = self.decrypt(code["secure_secret"]) if "secure_secret" in code else code["secret"] if "secret" in code else ""
                codes += [OAuthCode(code["name"] if "name" in code else "???",
                                    secret,
                                    code["otp"]["issuer"] if "otp" in code and "issuer" in code["otp"] else "",
                                    code["otp"]["account"] if "otp" in code and "account" in code["otp"] else "",
                                    code["secure_secret"] if "secure_secret" in code else None)]
                
                if "name" not in code or "secret" not in code and "secure_secret" not in code or not valid_secret(secret, False):
                    some_corrupt += 1  # Add to error counter if there is no name or any valid secret
            return codes[::-1], some_corrupt
        
        else:
            return [], 0
    
    def save_json (self, services):
        """Saves OAuthCodes and encrypts their secrets."""
        if self.fernet == None:
            raise UninitializedException()
        
        d = {"services": [code.dict(self) for code in services]}  # Gets the dictionary objects of codes, which automatically encrypt themselves
        with open("secrets.json", "w") as f:
            json.dump(d, f)
    
    def export_json (self, services):
        """Saves OAuthCodes as plaintext."""
        d = {"services": [code.dict() for code in services]}  # Gets the dictionary objects of codes, which automatically encrypt themselves
        with open("exported_secrets.json", "w") as f:
            json.dump(d, f)


class UninitializedException (Exception):
    def __init__ (self):
        super().__init__("Fernet hash has not been set")