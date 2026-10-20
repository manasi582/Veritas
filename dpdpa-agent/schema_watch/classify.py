"""
Guesses, from a column's name, which kind of personal data it holds (the same kinds as the recognizer pack and the data
map: phone, email, aadhaar, pan, card, name, dob, address, account, passport, voter, upi). A guess, not a finding: it will
miss a column called `col_7` and may take a harmless column for personal data. The organization can correct it in its
policy (`schema_hints`), including declaring a column as not personal.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Dict, Optional

CATEGORIES = ("phone", "email", "aadhaar", "pan", "card", "name", "dob", "address", "account", "passport", "voter", "upi")

# token sets: a column matches a category when its name, split into words, contains the words in one of the sets
_RULES = [
    ("aadhaar", [{"aadhaar"}, {"aadhar"}, {"uidai"}, {"aadhaar", "no"}]),
    ("pan", [{"pan"}, {"pan", "no"}, {"pan", "number"}, {"pancard"}, {"pan", "card"}]),
    ("card", [{"card", "number"}, {"card", "no"}, {"card", "num"}, {"cc", "number"}, {"cvv"}, {"cardnumber"}, {"debit", "card"}, {"credit", "card"}]),
    ("phone", [{"phone"}, {"mobile"}, {"msisdn"}, {"telephone"}, {"cell", "number"}, {"contact", "no"}, {"contact", "number"}, {"contactno"}, {"whatsapp"}]),
    ("email", [{"email"}, {"e", "mail"}, {"mail", "id"}, {"emailid"}]),
    ("dob", [{"dob"}, {"birth"}, {"birthdate"}, {"birthday"}, {"date", "of", "birth"}]),
    ("address", [{"address"}, {"addr"}, {"street"}, {"pincode"}, {"postal"}, {"zipcode"}, {"zip", "code"}, {"residence"}]),
    ("account", [{"account", "number"}, {"account", "no"}, {"acct", "no"}, {"acct", "number"}, {"iban"}, {"bank", "account"}, {"accountno"}]),
    ("passport", [{"passport"}]),
    ("voter", [{"voter"}, {"epic", "no"}]),
    ("upi", [{"upi"}, {"vpa"}]),
]
_PERSON_PREFIX = {"first", "last", "middle", "full", "customer", "user", "person", "applicant", "borrower", "nominee", "guardian",
                  "surname", "given", "father", "mother", "spouse", "patient"}
_NOT_POSTAL = {"ip", "mac", "url", "web", "wallet", "contract", "bitcoin", "host", "memory", "smtp"}
_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def tokens(column: str) -> list:
    words = []
    for part in _SPLIT.split(_CAMEL.sub("_", column or "")):
        if part:
            words.append(part.lower())
    return words


def category_of(column: str, hints: Optional[Dict[str, str]] = None) -> Optional[str]:
    """The kind of personal data a column name suggests, or None. `hints` maps a column name or pattern to a kind or "none"."""
    name = (column or "").strip()
    for pattern, value in (hints or {}).items():
        if fnmatch.fnmatchcase(name.lower(), pattern.lower()):
            return None if value.lower() == "none" else value.lower()
    words = set(tokens(name))
    if not words:
        return None
    for category, sets in _RULES:
        if any(s <= words for s in sets):
            if category == "address" and words & _NOT_POSTAL:     # ip_address, mac_address, wallet_address...
                return None
            return category
    if "name" in words and words & _PERSON_PREFIX:
        return "name"
    if words & {"surname", "fullname", "firstname", "lastname"}:
        return "name"
    return None
