#!/usr/bin/env python3
import requests, sys

WORDLIST = [
    "admin", "login", "uploads", "backup",
    "config", "robots.txt", ".git", ".env"
]

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dirbuster_ctf.py <url>")
        return

    url = sys.argv[1].rstrip("/")
    print("Target:", url)

    for w in WORDLIST:
        u = f"{url}/{w}"
        try:
            r = requests.get(u, timeout=3)
            if r.status_code in [200, 403]:
                print(f"[+] {u} ({r.status_code})")
        except:
            pass

if __name__ == "__main__":
    main()
