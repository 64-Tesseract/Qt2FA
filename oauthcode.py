#!/usr/bin/python3

import authenticator  # Generates 2FA codes
from re import match  # Checks if keys are in right format


class OAuthCode:
    """Stores data on OAuth codes and generates tokens."""
    def __init__ (self, name, secret, issuer, account, hash_ = None):
        self.name = name
        self.secret = secret
        self.issuer = issuer
        self.account = account
        self.hash = hash_
    
    def dict (self, fernet = None):
        """Returns a dictionary representation for use in JSON saving, encrypting if necessary."""
        if fernet:
            self.regen_hash(fernet)
        
        if fernet and self.hash:  # Save hash instead of plain secret if possible
            return {"name": self.name, "otp": {"issuer": self.issuer, "account": self.account}, "secure_secret": self.hash}
        else:
            return {"name": self.name, "otp": {"issuer": self.issuer, "account": self.account}, "secret": self.secret}
    
    def gen_token (self):
        """Generates a token, if it's valid."""
        if valid_secret(self.secret):
            return authenticator.get_totp_token(self.secret)
        
        return None
    
    def format_token (self):
        """Formats the token with a space, or an error message if the secret's invalid."""
        if valid_secret(self.secret):
            token = self.gen_token()
            return f"{token[:3]} {token[3:]}"
        
        return "INVALID"
    
    def set_vals (self, name, secret, issuer, account):
        """Sets variables to whatever's passed."""
        self.name = name
        self.secret = secret
        self.issuer = issuer
        self.account = account
    
    def empty (self):
        return self.name == "" and self.secret == "" and self.issuer == "" and self.account == ""
    
    def regen_hash (self, fernet):
        """Regenerates the hash if the secret's valid, leaves it as-is if not."""
        if valid_secret(self.secret):
            self.hash = fernet.encrypt(self.secret)


def valid_secret (secret, allow_empty = False):
    return (secret == "" and allow_empty) or len(secret) % 8 == 0 and bool(match("^[A-Za-z0234567]+$", secret))