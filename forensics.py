#!/usr/bin/env python3
import os
import re
import subprocess
import hashlib
import zipfile
import binascii
import base64

# =====================
# KONFIGURASI
# =====================

FLAG_PATTERNS = [
    rb'flag\{.*?\}',
    rb'ctf\{.*?\}',
    rb'CTF\{.*?\}'
]

# =====================
# UTILITIES
# =====================

def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    except:
        return b""

def find_flags(data):
    res = []
    for p in FLAG_PATTERNS:
        res += re.findall(p, data)
    return res

# =====================
# FILE INFO
# =====================

def file_info(path):
    print("\n===== FILE INFO =====")
    print("[+] File     :", path)
    print("[+] Size     :", os.path.getsize(path), "bytes")
    print("[+] Type     :", run(["file", path]).decode(errors="ignore").strip())

def hash_info(path):
    print("\n===== HASH =====")
    data = open(path, "rb").read()
    print("MD5    :", hashlib.md5(data).hexdigest())
    print("SHA1   :", hashlib.sha1(data).hexdigest())
    print("SHA256 :", hashlib.sha256(data).hexdigest())

# =====================
# MAGIC BYTES
# =====================

def magic_check(path):
    print("\n===== MAGIC BYTES =====")
    head = open(path, "rb").read(16)
    print("Magic:", binascii.hexlify(head).decode())

# =====================
# STRINGS (FILTERED)
# =====================

def strings_scan(path):
    print("\n===== STRINGS (FLAG & BASE64 ONLY) =====")

    ascii_s = run(["strings", "-a", path])
    utf16_s = run(["strings", "-el", path])
    data = ascii_s + utf16_s

    found = set()

    # 1️⃣ Flag langsung
    for f in find_flags(data):
        found.add(("FLAG", f, f))

    # 2️⃣ String dengan {}
    for s in re.findall(rb'.{0,40}\{.{0,40}\}', data):
        if 10 < len(s) < 120:
            found.add(("CURLY", s, s))

    # 3️⃣ Base64
    for s in re.findall(rb'[A-Za-z0-9+/=]{24,}', data):
        try:
            dec = base64.b64decode(s, validate=True)
            if b"{" in dec or b"flag" in dec.lower():
                found.add(("BASE64", s, dec))
        except:
            pass

    # 4️⃣ Hex
    for s in re.findall(rb'[0-9a-fA-F]{24,}', data):
        try:
            dec = binascii.unhexlify(s)
            if b"{" in dec or b"flag" in dec.lower():
                found.add(("HEX", s, dec))
        except:
            pass

    if not found:
        print("[-] Tidak ada kandidat flag / base64")
        return

    for t, raw, dec in found:
        print(f"\n[{t}]")
        print("RAW     :", raw.decode(errors="ignore"))
        if dec != raw:
            print("DECODED :", dec.decode(errors="ignore"))

# =====================
# METADATA
# =====================

def metadata_scan(path):
    print("\n===== METADATA =====")
    meta = run(["exiftool", "-a", "-u", "-g1", path])
    if not meta:
        print("[-] Tidak ada metadata")
        return

    print(meta.decode(errors="ignore"))

    flags = find_flags(meta)
    if flags:
        print("\n[!] FLAG DI METADATA:")
        for f in flags:
            print("[FLAG]", f.decode(errors="ignore"))

# =====================
# ZSTEG
# =====================

def zsteg_scan(path):
    print("\n===== ZSTEG =====")
    out = run(["zsteg", "-a", path])
    if not out:
        print("[-] zsteg tidak mendukung file ini")
        return

    print(out.decode(errors="ignore"))

    flags = find_flags(out)
    for f in flags:
        print("[FLAG]", f.decode(errors="ignore"))

# =====================
# STEGHIDE
# =====================

def steghide_scan(path):
    print("\n===== STEGHIDE =====")
    info = run(["steghide", "info", path])
    if info:
        print(info.decode(errors="ignore"))

    extract = run([
        "steghide", "extract",
        "-sf", path,
        "-p", "",
        "-xf", "steghide_out.txt"
    ])

    if b"wrote" in extract.lower():
        print("[+] Steghide extracted → steghide_out.txt")
        try:
            data = open("steghide_out.txt", "rb").read()
            flags = find_flags(data)
            for f in flags:
                print("[FLAG]", f.decode(errors="ignore"))
        except:
            pass
    else:
        print("[-] Tidak bisa extract (password?)")

# =====================
# ZIP
# =====================

def extract_zip(path):
    if zipfile.is_zipfile(path):
        print("\n===== ZIP EXTRACT =====")
        os.makedirs("extracted", exist_ok=True)
        with zipfile.ZipFile(path) as z:
            z.extractall("extracted")
        print("[+] Extracted ke ./extracted")

# =====================
# BINWALK
# =====================

def binwalk_scan(path):
    print("\n===== BINWALK =====")
    out = run(["binwalk", path])
    print(out.decode(errors="ignore"))

# =====================
# MAIN
# =====================

def analyze(path):
    if not os.path.exists(path):
        print("File tidak ditemukan")
        return

    file_info(path)
    hash_info(path)
    magic_check(path)
    strings_scan(path)
    metadata_scan(path)
    extract_zip(path)
    zsteg_scan(path)
    steghide_scan(path)
    binwalk_scan(path)

    print("\n===== ANALISIS SELESAI =====")

# =====================
# ENTRY
# =====================

if __name__ == "__main__":
    target = input("Masukkan file target: ").strip()
    analyze(target)
