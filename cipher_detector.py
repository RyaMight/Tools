#!/usr/bin/env python3
import re, base64, math, string
from collections import Counter

# =====================
# KONFIGURASI
# =====================

COMMON_WORDS = ["flag", "ctf", "the", "this", "that", "you", "cipher", "alphabet"]
VIGENERE_KEYS = ["key", "flag", "ctf", "crypto", "secret", "password"]

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
# CIPHERS (ENCODERS / DECODERS)
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

def affine_encode(text, a, b):
    r=""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            x = ord(c)-base
            r += chr((a*x + b) % 26 + base)
        else: r+=c
    return r

def affine_decode(text, a, b):
    inv = pow(a, -1, 26)
    r=""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            x = ord(c)-base
            r += chr((inv*(x - b))%26 + base)
        else: r+=c
    return r

def vigenere(text, key, decrypt=False):
    r=''; kidx=0; key = key.lower()
    for c in text:
        if c.isalpha():
            s = ord(key[kidx%len(key)])-97
            b = ord('A') if c.isupper() else ord('a')
            if decrypt: r+=chr((ord(c)-b - s)%26 + b)
            else: r+=chr((ord(c)-b + s)%26 + b)
            kidx += 1
        else: r+=c
    return r

def rail_fence_encode(text, rails):
    if rails <=1: return text
    rows = ['']*rails
    rail = 0; step = 1
    for c in text:
        rows[rail] += c
        rail += step
        if rail == 0 or rail == rails-1: step *= -1
    return ''.join(rows)

def rail_fence_decode(text, rails):
    n=len(text)
    fence=[['']*n for _ in range(rails)]
    rail,step=0,1
    for i in range(n):
        fence[rail][i]='*'
        rail+=step
        if rail==0 or rail==rails-1: step*=-1
    idx=0
    for r in range(rails):
        for c in range(n):
            if fence[r][c]=='*':
                fence[r][c]=text[idx]; idx+=1
    res=''; rail,step=0,1
    for i in range(n):
        res+=fence[rail][i]
        rail+=step
        if rail==0 or rail==rails-1: step*=-1
    return res

def columnar_encode(text, key):
    k = len(key)
    cols = ['']*k
    for i,ch in enumerate(text):
        cols[i%k] += ch
    # read columns by sorted key order
    order = sorted(range(k), key=lambda i: (key[i], i))
    return ''.join(cols[i] for i in order)

def columnar_decode(text, key):
    k = len(key)
    n = len(text)
    rows = n // k
    extra = n % k
    order = sorted(range(k), key=lambda i: (key[i], i))
    col_lens = [rows + (1 if i < extra else 0) for i in range(k)]
    cols = [None]*k
    idx = 0
    for pos in order:
        l = col_lens[pos]
        cols[pos] = text[idx:idx+l]
        idx += l
    res = []
    for r in range(rows + (1 if extra>0 else 0)):
        for c in range(k):
            if cols[c] and r < len(cols[c]):
                res.append(cols[c][r])
    return ''.join(res)

def xor_bytes(text, key_byte):
    raw = text.encode()
    return ''.join(chr(b ^ key_byte) for b in raw)

# convenience encoders
def encode_base64(text): return base64.b64encode(text.encode()).decode()
def encode_hex(text): return text.encode().hex()

def smart_output(s):
    if is_printable(s):
        return s
    else:
        return encode_hex(s)

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
# MAIN ANALYSIS (PRINT-FRIENDLY)
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
# INTERACTIVE ENCODER / DECODER
# =====================

def xor_bruteforce(ciphertext, limit=100):
    # accept raw or hex
    raw = None
    if re.fullmatch(r'[0-9a-fA-F]+', ciphertext) and len(ciphertext)%2==0:
        try:
            raw = bytes.fromhex(ciphertext)
        except: raw = ciphertext.encode(errors='ignore')
    else:
        raw = ciphertext.encode(errors='ignore')
    candidates = []
    for k in range(256):
        s = ''.join(chr(b^k) for b in raw)
        sc = english_score(s) + bonus_score(s)
        if is_printable(s) and (sc > 5 or keyword_hit(s) or ' ' in s):
            candidates.append((sc, k, s))
    candidates.sort(reverse=True)
    return candidates[:limit]


def interactive_encode():
    print("\n=== ENCODER ===")
    text = input("Masukkan plaintext: ")
    print("Pilih algoritma: 1=Caesar 2=Atbash 3=Affine 4=Vigenere 5=RailFence 6=Columnar 7=XOR 8=Base64 9=Hex")
    ch = input("Pilihan (nomor): ").strip()
    out = None
    if ch=='1':
        sh = int(input("Shift (0-25): "))
        out = caesar(text, sh, decrypt=False)
    elif ch=='2':
        out = atbash(text)
    elif ch=='3':
        a = int(input("a (must be odd, e.g., 3,5,7...): "))
        b = int(input("b (0-25): "))
        out = affine_encode(text, a, b)
    elif ch=='4':
        key = input("Key (alpha): ")
        out = vigenere(text, key, decrypt=False)
    elif ch=='5':
        r = int(input("Rails: "))
        out = rail_fence_encode(text, r)
    elif ch=='6':
        key = input("Key (e.g., '4312' or 'SECRET'): ")
        out = columnar_encode(text, key)
    elif ch=='7':
        k = int(input("Key byte (0-255): "))
        out = xor_bytes(text, k)
        out = smart_output(out)
    elif ch=='8':
        out = encode_base64(text)
    elif ch=='9':
        out = encode_hex(text)
    else:
        print("Pilihan tidak valid")
        return
    print("\nHasil: ")
    print(out)


def interactive_decode():
    print("\n=== DECODER ===")
    text = input("Masukkan ciphertext: ")
    print("Pilih algoritma: 1=Caesar 2=Atbash 3=Affine 4=Vigenere 5=RailFence 6=Columnar 7=XOR(bruteforce/byte) 8=Base64 9=Hex")
    ch = input("Pilihan (nomor): ").strip()
    if ch=='1':
        sh = int(input("Shift (0-25): "))
        out = caesar(text, sh, decrypt=True)
        print(out)
    elif ch=='2':
        print(atbash(text))
    elif ch=='3':
        a = int(input("a (used to encode): "))
        b = int(input("b (used to encode): "))
        print(affine_decode(text, a, b))
    elif ch=='4':
        key = input("Key (alpha) [leave empty to try common keys]: ")
        if key:
            print(vigenere(text, key, decrypt=True))
        else:
            for k in VIGENERE_KEYS:
                print(f"Key={k}: {vigenere(text,k,decrypt=True)}")
    elif ch=='5':
        r = int(input("Rails: "))
        print(rail_fence_decode(text, r))
    elif ch=='6':
        key = input("Key (e.g., '4312' or 'SECRET'): ")
        print(columnar_decode(text, key))
    elif ch=='7':
        sub = input("Mode: 1=bruteforce 2=single-byte: ").strip()
        if sub=='1':
            for sc,k,s in xor_bruteforce(text, limit=20):
                print(f"[k={k}] {s}")
        else:
            k = int(input("Key byte (0-255): "))
            raw = bytes.fromhex(text) if re.fullmatch(r'[0-9a-fA-F]+', text) and len(text)%2==0 else text.encode(errors='ignore')
            print(''.join(chr(b^k) for b in raw))
    elif ch=='8':
        d = decode_base64(text)
        print(d if d else "Invalid base64 or non-printable result")
    elif ch=='9':
        d = decode_hex(text)
        print(d if d else "Invalid hex or non-printable result")
    else:
        print("Pilihan tidak valid")

# =====================
# ENTRY POINT
# =====================

if __name__ == "__main__":
    print("=== CIPHER TOOL ===")
    print("1) Detect/Analyze  2) Encode  3) Decode  4) Load from file and Analyze")
    m = input("Pilih mode: ").strip()
    if m=='1':
        cipher = input("Masukkan ciphertext: ").strip()
        analyze(cipher)
    elif m=='2':
        interactive_encode()

    elif m=='3':
        interactive_decode()
    
    elif m=='4':
        path = input("File path: ")
        try:
            data = open(path,'r',errors='ignore').read()
            analyze(data)
        except Exception as e:
            print("Gagal membuka file:", e)
    

