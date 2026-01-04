#!/usr/bin/env python3
import re, base64, math, string
from collections import Counter

# =====================
# KONFIGURASI
# =====================

COMMON_WORDS = ["flag", "ctf", "the", "this", "that", "you", "cipher", "alphabet"]
VIGENERE_KEYS = ["key", "flag", "ctf", "crypto", "secret", "password"]

# =====================
# BANNER
# =====================

BANNER = r"""
   ___ _      _            _           _   
  / __(_)_ __| |_  ___ _ _| |_ _____ _| |_ 
 | (__| | '_ \ ' \/ -_) '_|  _/ -_) \ /  _|
  \___|_| .__/_||_\___|_|  \__\___/_\_\\__|
        |_|                                

                       Ciphertext
"""

def print_banner():
    """
    Print the ASCII banner for Ciphertext.
    """
    print(BANNER)

CAESAR_SCORE_THRESHOLD = 18
CAESAR_TOP_RESULTS = 3

# =====================
# UTILITIES
# =====================

def entropy(s):
    if not s: return 0
    p = [n/len(s) for n in Counter(s).values()]
    return -sum(x * math.log2(x) for x in p)

def is_printable(s):
    return all(c in string.printable for c in s)

def english_score(s):
    freq = "etaoinshrdlu"
    return sum(s.lower().count(c) for c in freq)

def keyword_hit(s):
    return any(w in s.lower() for w in COMMON_WORDS)

def bonus_score(s):
    return s.count(" ") * 2 + s.count(",") + s.count(".")

# =====================
# ENCODING DETECTION
# =====================

def is_base64(s): return len(s)%4==0 and re.fullmatch(r'[A-Za-z0-9+/=]+', s)
def is_base32(s): return re.fullmatch(r'[A-Z2-7=]+', s)
def is_hex(s): return re.fullmatch(r'[0-9a-fA-F]+', s) and len(s)%2==0
def is_binary(s): return re.fullmatch(r'[01 ]+', s)

def decode_base64(s):
    try:
        d = base64.b64decode(s).decode(errors="ignore")
        return d if is_printable(d) else None
    except: return None

def decode_base32(s):
    try:
        d = base64.b32decode(s).decode(errors="ignore")
        return d if is_printable(d) else None
    except: return None

def decode_hex(s):
    try:
        d = bytes.fromhex(s).decode(errors="ignore")
        return d if is_printable(d) else None
    except: return None

def decode_binary(s):
    try:
        s = s.replace(" ", "")
        d = ''.join(chr(int(s[i:i+8],2)) for i in range(0,len(s),8))
        return d if is_printable(d) else None
    except: return None

# =====================
# CIPHERS
# =====================

def caesar(text, shift, decrypt=True):
    r=""
    for c in text:
        if c.isalpha():
            b = ord('A') if c.isupper() else ord('a')
            r += chr((ord(c)-b + (-shift if decrypt else shift))%26 + b)
        else:
            r+=c
    return r

def atbash(s):
    r=""
    for c in s:
        if c.isupper(): r+=chr(90-(ord(c)-65))
        elif c.islower(): r+=chr(122-(ord(c)-97))
        else: r+=c
    return r

# =====================
# AUTO CHAIN
# =====================

def auto_chain(cipher):
    print("\n===== AUTO CHAIN (ATBASH → CAESAR) =====")
    ab = atbash(cipher)
    results = []

    for i in range(26):
        r = caesar(ab, i, decrypt=True)
        score = english_score(r) + bonus_score(r)
        if score > 25:
            results.append((score, f"[ATBASH + SHIFT {i}] {r}"))

    results.sort(reverse=True)
    for _, r in results[:2]:
        print(r)

# =====================
# MAIN ANALYSIS
# =====================

def analyze(cipher):
    print("\n===== ANALISIS =====")
    print("Ciphertext:", cipher)
    print("Panjang   :", len(cipher))
    e = entropy(cipher)
    print("Entropy   :", round(e,3))
    print("Hint      :", "Cipher klasik" if e < 5.5 else "Encoding/XOR")

    print("\n===== ENCODING =====")
    for name, chk, dec in [
        ("Base64", is_base64, decode_base64),
        ("Base32", is_base32, decode_base32),
        ("Hex", is_hex, decode_hex),
        ("Binary", is_binary, decode_binary)
    ]:
        if chk(cipher):
            r = dec(cipher)
            if r:
                print(f"[+] {name} → {r}")

    print("\n===== ATBASH =====")
    print(atbash(cipher))

    print("\n===== CAESAR / ROT (FILTERED) =====")
    results = []

    for i in range(26):
        dec = caesar(cipher, i, decrypt=True)
        score = english_score(dec) + bonus_score(dec)
        if score >= CAESAR_SCORE_THRESHOLD or keyword_hit(dec):
            results.append((score, f"[DEC SHIFT {i:02}] {dec}"))

        enc = caesar(cipher, i, decrypt=False)
        score = english_score(enc) + bonus_score(enc)
        if score >= CAESAR_SCORE_THRESHOLD or keyword_hit(enc):
            results.append((score, f"[ENC SHIFT {i:02}] {enc}"))

    results.sort(reverse=True)
    for _, r in results[:CAESAR_TOP_RESULTS]:
        print(r)

    auto_chain(cipher)
    print("\n===== SELESAI =====")

# =====================
# ENTRY POINT
# =====================


if __name__ == "__main__":
    print_banner()
    cipher = input("Masukkan ciphertext: ").strip()
    analyze(cipher)
