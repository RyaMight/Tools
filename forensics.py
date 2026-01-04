#!/usr/bin/env python3
"""
Forensics helper (upgraded):
 - CLI with file or directory input (recursive)
 - JSON output option
 - Tool availability reporting (exiftool, strings, steghide, zsteg, binwalk)
 - Pure-Python fallback for strings extraction when 'strings' is missing
 - Improved base64/hex detection and decoding
 - Per-file structured results for easier automation
"""

import os
import re
import subprocess
import hashlib
import zipfile
import binascii
import base64
import argparse
import json
import shutil
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# =====================
# KONFIGURASI
# =====================

FLAG_PATTERNS = [
    rb'flag\{.*?\}',
    rb'ctf\{.*?\}',
    rb'CTF\{.*?\}'
]

MIN_STRING_LEN = 4
MIN_BASE64_LEN = 24
MIN_HEX_LEN = 24

# =====================
# UTILITIES
# =====================

def check_tool(name):
    return shutil.which(name) is not None

TOOLS = {
    'strings': check_tool('strings'),
    'exiftool': check_tool('exiftool'),
    'steghide': check_tool('steghide'),
    'zsteg': check_tool('zsteg'),
    'binwalk': check_tool('binwalk'),
    'file': check_tool('file')
}


def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    except Exception:
        return b""


def find_flags(data):
    res = []
    for p in FLAG_PATTERNS:
        res += re.findall(p, data)
    return list(set(res))

# pure-python strings extractor
def extract_strings_py(data, min_len=MIN_STRING_LEN):
    res = []
    current = []
    for b in data:
        if 32 <= b <= 126:  # printable ASCII
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                res.append(''.join(current))
            current = []
    if len(current) >= min_len:
        res.append(''.join(current))
    # UTF-16 LE
    try:
        u16 = data.decode('utf-16le', errors='ignore')
        for s in re.findall(r'[\x20-~]{%d,}' % min_len, u16):
            res.append(s)
    except Exception:
        pass
    return res

# =====================
# FILE ANALYSIS (structured)
# =====================

def file_info_dict(path):
    p = Path(path)
    info = {
        'path': str(p),
        'size': p.stat().st_size,
        'mtime': datetime.fromtimestamp(p.stat().st_mtime).isoformat()
    }
    if TOOLS['file']:
        info['type'] = run(['file', str(p)]).decode(errors='ignore').strip()
    else:
        info['type'] = None
    return info


def hash_info_dict(path):
    data = open(path, 'rb').read()
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest()
    }


def magic_bytes(path, n=16):
    return binascii.hexlify(open(path, 'rb').read(n)).decode()


def strings_scan_dict(path):
    data = open(path, 'rb').read()
    found = []

    # use system strings if available
    strings_out = b''
    if TOOLS['strings']:
        strings_out = run(['strings', '-a', str(path)])
    else:
        strings_out = '\n'.join(extract_strings_py(data)).encode()

    # check for flags
    for f in find_flags(strings_out):
        found.append({'type': 'flag', 'raw': f.decode(errors='ignore'), 'decoded': f.decode(errors='ignore')})

    # curly-brace candidates
    for s in re.findall(rb'.{0,40}\{.{0,40}\}', strings_out):
        s = s.strip()
        if 10 < len(s) < 200:
            found.append({'type': 'curly', 'raw': s.decode(errors='ignore'), 'decoded': s.decode(errors='ignore')})

    # base64 candidates
    for s in re.findall(rb'[A-Za-z0-9+/=]{%d,}' % MIN_BASE64_LEN, strings_out):
        s = s.strip()
        try:
            dec = base64.b64decode(s, validate=True)
            dec_text = dec.decode(errors='ignore')
            found.append({'type': 'base64', 'raw': s.decode(errors='ignore'), 'decoded': dec_text})
        except Exception:
            pass

    # hex candidates
    for s in re.findall(rb'[0-9a-fA-F]{%d,}' % MIN_HEX_LEN, strings_out):
        s = s.strip()
        if len(s) % 2 != 0:
            continue
        try:
            dec = binascii.unhexlify(s)
            dec_text = dec.decode(errors='ignore')
            found.append({'type': 'hex', 'raw': s.decode(errors='ignore'), 'decoded': dec_text})
        except Exception:
            pass

    # dedupe by raw
    unique = {}
    for it in found:
        unique.setdefault(it['raw'], it)
    return list(unique.values())


def metadata_scan_dict(path):
    if not TOOLS['exiftool']:
        return None
    out = run(['exiftool', '-a', '-u', '-g1', str(path)])
    if not out:
        return None
    out_text = out.decode(errors='ignore')
    flags = [f.decode(errors='ignore') for f in find_flags(out)]
    return {'metadata': out_text[:5000], 'flags': flags}


def steghide_scan_dict(path):
    if not TOOLS['steghide']:
        return None
    info = run(['steghide', 'info', str(path)])
    extract = run(['steghide', 'extract', '-sf', str(path), '-p', '', '-xf', 'steghide_out.txt'])
    extracted = False
    flags = []
    if b'wrote' in extract.lower():
        extracted = True
        try:
            data = open('steghide_out.txt', 'rb').read()
            flags = [f.decode(errors='ignore') for f in find_flags(data)]
        except Exception:
            pass
    return {'info': info.decode(errors='ignore'), 'extracted': extracted, 'flags': flags}


def zsteg_scan_dict(path):
    if not TOOLS['zsteg']:
        return None
    out = run(['zsteg', '-a', str(path)])
    if not out:
        return None
    flags = [f.decode(errors='ignore') for f in find_flags(out)]
    return {'output': out.decode(errors='ignore'), 'flags': flags}

# ---------------------
# STEGO: LSB + text-based stego
# ---------------------

# try to import PIL for image pixel access
try:
    from PIL import Image
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False

IMAGE_EXTS = ('.png', '.bmp', '.tif', '.tiff', '.jpg', '.jpeg')

def bits_to_bytes_ms(bits):
    # bits: list of '0'/'1' chars, MSB-first per byte
    b = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = int(''.join(bits[i:i+8]), 2)
        b.append(byte)
    return bytes(b)

def bits_to_bytes_ls(bits):
    # bits: list of '0'/'1' chars, LSB-first per byte
    b = bytearray()
    for i in range(0, len(bits) - 7, 8):
        val = 0
        for j in range(8):
            val |= (int(bits[i+j]) << j)
        b.append(val)
    return bytes(b)

def lsb_bits_from_bytes(data, bits=1, offset=0):
    mask = (1 << bits) - 1
    out_bits = []
    n = len(data)
    for i in range(offset, n):
        byte = data[i]
        for b in range(bits):
            out_bits.append(str((byte >> b) & 1))
    return out_bits

def lsb_extract_from_image(path, bits=1, max_out=10000):
    # returns candidate decoded bytes (msb-first and lsb-first) limited
    try:
        if not HAVE_PIL:
            return None
        im = Image.open(path)
        im = im.convert('RGB')
        pixels = list(im.getdata())
        flat = []
        for px in pixels:
            flat.extend(px)
        bits_list = lsb_bits_from_bytes(bytes(flat), bits)
        ms = bits_to_bytes_ms(bits_list)
        ls = bits_to_bytes_ls(bits_list)
        return {'ms': ms[:max_out], 'ls': ls[:max_out]}
    except Exception:
        return None

def lsb_extract_from_raw(path, bits=1, max_out=10000):
    try:
        data = open(path, 'rb').read()
        bits_list = lsb_bits_from_bytes(data, bits)
        ms = bits_to_bytes_ms(bits_list)
        ls = bits_to_bytes_ls(bits_list)
        return {'ms': ms[:max_out], 'ls': ls[:max_out]}
    except Exception:
        return None

def zero_width_scan(path):
    # detect zero-width chars and attempt to decode as bits
    ZW_MAP = {'\u200b': '0', '\u200c': '1', '\u200d': '1', '\ufeff': '0'}
    # use actual unicode characters as keys
    ZW_MAP = {k.encode('utf-8').decode('unicode_escape'): v for k, v in ZW_MAP.items()}
    try:
        txt = open(path, 'r', encoding='utf-8', errors='ignore').read()
    except Exception:
        return None
    zw_seq = [ch for ch in txt if ch in ZW_MAP]
    if not zw_seq:
        return None
    bits = [ZW_MAP[ch] for ch in zw_seq]
    data = bits_to_bytes_ms(bits)
    decoded = data.decode(errors='ignore')
    flags = [f.decode(errors='ignore') for f in find_flags(data)]
    return {'raw_count': len(zw_seq), 'decoded': decoded, 'flags': flags, 'sample': ''.join(zw_seq[:50])}


def trailing_whitespace_scan(path):
    try:
        lines = open(path, 'r', encoding='utf-8', errors='ignore').read().splitlines()
    except Exception:
        return None
    bits = []
    for ln in lines:
        if ln.endswith('\t'):
            bits.append('1')
        elif ln.endswith(' '):
            bits.append('0')
    if not bits:
        return None
    data = bits_to_bytes_ms(bits)
    decoded = data.decode(errors='ignore')
    flags = [f.decode(errors='ignore') for f in find_flags(data)]
    return {'bits_len': len(bits), 'decoded': decoded, 'flags': flags}
    return {'bits_len': len(bits), 'decoded': decoded, 'flags': flags}


def stego_scan_dict(path):
    res = {}
    # existing tool-based checks
    s = zsteg_scan_dict(path)
    if s:
        res['zsteg'] = s
    sh = steghide_scan_dict(path)
    if sh:
        res['steghide'] = sh

    # LSB attempts
    lsb_candidates = []
    for b in (1,2):
        if Path(path).suffix.lower() in IMAGE_EXTS and HAVE_PIL:
            out = lsb_extract_from_image(path, bits=b)
        else:
            out = lsb_extract_from_raw(path, bits=b)
        if not out:
            continue
        for k,blob in out.items():
            # search for printable sequences
            strings = []
            for s in re.findall(rb'[\x20-~]{6,}', blob):
                strings.append(s.decode(errors='ignore'))
            flags = [f.decode(errors='ignore') for f in find_flags(blob)]
            if strings or flags:
                lsb_candidates.append({'bits': b, 'mode': k, 'strings': strings[:8], 'flags': flags})
                if flags:
                    res.setdefault('flags', []).extend(flags)
    if lsb_candidates:
        res['lsb_candidates'] = lsb_candidates

    # zero-width
    zw = zero_width_scan(path)
    if zw:
        res['zero_width'] = zw
        if zw.get('flags'):
            res.setdefault('flags', []).extend(zw.get('flags'))

    # trailing whitespace
    tw = trailing_whitespace_scan(path)
    if tw:
        res['trailing_whitespace'] = tw
        if tw.get('flags'):
            res.setdefault('flags', []).extend(tw.get('flags'))

    return res if res else None


def binwalk_scan_dict(path):
    if not TOOLS['binwalk']:
        return None
    out = run(['binwalk', str(path)])
    return {'output': out.decode(errors='ignore')}


def extract_zip_if_any(path):
    extracted = False
    if zipfile.is_zipfile(path):
        os.makedirs('extracted', exist_ok=True)
        with zipfile.ZipFile(path) as z:
            z.extractall('extracted')
        extracted = True
    return extracted


def analyze_file(path):
    path = Path(path)
    if not path.exists():
        return None
    res = {
        'file': file_info_dict(path),
        'hashes': hash_info_dict(path),
        'magic': magic_bytes(path),
        'strings': strings_scan_dict(path),
        'metadata': metadata_scan_dict(path),
        'steghide': steghide_scan_dict(path),
        'zsteg': zsteg_scan_dict(path),
        'binwalk': binwalk_scan_dict(path),
        'zip_extracted': extract_zip_if_any(path),
        'stego': stego_scan_dict(path),
        'flags': []
    }
    # collect flags from strings
    for s in res['strings']:
        if s['type'] == 'flag':
            res['flags'].append(s['raw'])
    # from metadata, steghide, zsteg, stego
    if res['metadata'] and res['metadata'].get('flags'):
        res['flags'].extend(res['metadata']['flags'])
    if res['steghide'] and res['steghide'].get('flags'):
        res['flags'].extend(res['steghide']['flags'])
    if res['zsteg'] and res['zsteg'].get('flags'):
        res['flags'].extend(res['zsteg']['flags'])
    if res['stego']:
        # aggregate detected flags
        if res['stego'].get('flags'):
            res['flags'].extend(res['stego']['flags'])
        # also include steghide/zsteg nested keys if present
        if 'steghide' in res['stego'] and res['stego']['steghide'].get('flags'):
            res['flags'].extend(res['stego']['steghide']['flags'])
        if 'zsteg' in res['stego'] and res['stego']['zsteg'].get('flags'):
            res['flags'].extend(res['stego']['zsteg']['flags'])

    # dedupe flags
    res['flags'] = list(set(res['flags']))
    return res

# =====================
# DIRECTORY SCAN
# =====================

def analyze_directory(path, recursive=True, threads=4, stop_on_flag=False):
    results = []
    p = Path(path)
    files = [str(f) for f in p.rglob('*') if f.is_file()] if recursive else [str(f) for f in p.iterdir() if f.is_file()]
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(analyze_file, f): f for f in files}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
                if stop_on_flag and r['flags']:
                    print(f"[!] Flag found in {r['file']['path']}: {r['flags']}")
                    return results
    return results

# =====================
# OUTPUT
# =====================

def save_json(obj, path):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)

# =====================
# SIMPLE HUMAN-READABLE OUTPUT
# =====================

def print_report_for_file(path):
    res = analyze_file(path)
    if not res:
        print(f"Cannot analyze: {path}")
        return
    f = res['file']
    print('\n===== FILE REPORT =====')
    print(f"File: {f['path']}")
    print(f"Size: {f['size']} bytes  Modified: {f['mtime']}")
    if f.get('type'):
        print(f"Type: {f['type']}")
    hashes = res.get('hashes', {})
    print(f"MD5: {hashes.get('md5')}  SHA1: {hashes.get('sha1')}  SHA256: {hashes.get('sha256')}")
    print(f"Magic bytes: {res.get('magic')}")
    if res.get('flags'):
        print(f"Flags found: {res['flags']}")
    strings = res.get('strings') or []
    if strings:
        print('Candidate strings:')
        for s in strings[:8]:
            print(f" - [{s['type']}] {s['raw']}")
    if res.get('metadata'):
        print('Metadata available (snippet):')
        print(res['metadata'].get('metadata')[:400])
    if res.get('stego'):
        print('\nStego findings:')
        st = res['stego']
        if st.get('lsb_candidates'):
            for c in st['lsb_candidates']:
                print(f" - LSB bits={c['bits']} mode={c['mode']} strings={c['strings'][:3]} flags={c.get('flags')}")
        if st.get('zero_width'):
            print(f" - Zero-width chars: {st['zero_width'].get('raw_count')} decoded snippet: {st['zero_width'].get('decoded')[:120]}")
        if st.get('trailing_whitespace'):
            print(f" - Trailing whitespace bits: {st['trailing_whitespace'].get('bits_len')} decoded snippet: {st['trailing_whitespace'].get('decoded')[:120]}")
    print('--- End report ---')


# =====================
# CLI
# =====================

def main():
    parser = argparse.ArgumentParser(description='Forensics - file and directory analysis (simple mode available)')
    parser.add_argument('target', help='File or directory to analyze')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan directories')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of worker threads for directory scan')
    parser.add_argument('--save', help='Save JSON output to file')
    parser.add_argument('--check-tools', action='store_true', help='Print available external tools')
    parser.add_argument('--stop-on-flag', action='store_true', help='Stop scanning if a flag is found')
    parser.add_argument('--simple', action='store_true', help='Print a compact human-friendly report per file')
    args = parser.parse_args()

    if args.check_tools:
        print('Tool availability:')
        for k, v in TOOLS.items():
            print(f" - {k}: {'yes' if v else 'no'}")

    target = Path(args.target)
    if not target.exists():
        print('Target not found')
        return

    if target.is_file():
        if args.simple:
            print_report_for_file(str(target))
        else:
            res = analyze_file(str(target))
            print(json.dumps(res, indent=2, ensure_ascii=False))
            if args.save:
                save_json(res, args.save)
    else:
        if args.simple:
            results = analyze_directory(str(target), recursive=args.recursive, threads=args.threads, stop_on_flag=args.stop_on_flag)
            for r in results:
                print(f"\n>> {r['file']['path']} : flags={r['flags']}")
        else:
            res = analyze_directory(str(target), recursive=args.recursive, threads=args.threads, stop_on_flag=args.stop_on_flag)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            if args.save:
                save_json(res, args.save)

if __name__ == '__main__':
    main()
