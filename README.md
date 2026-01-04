# Tools

A small collection of command-line security tooling for CTF and basic reconnaissance.

Included tools
- `forensics.py` — file and directory forensic helper (strings, metadata, steghide/zsteg/binwalk hooks, JSON output)
- `cipher_detector.py` — cipher detector and encoder/decoder utilities

Quick setup
1. Create and activate a virtual environment (recommended):
   - python -m venv .venv
   - On Windows: `.venv\Scripts\activate`  (PowerShell: `.\.venv\Scripts\Activate.ps1`)
2. Install required packages (only `requests` is required for `disbuster.py`):
   - python -m pip install -r requirements.txt

Usage examples

forensics.py (simple human-friendly report):

- Single file, simple report:
  - python Tools/forensics.py /path/to/file --simple
  - This also runs basic steganography checks (LSB extraction attempts, zero-width character detection, and trailing-whitespace stego heuristics)

- Recursive directory scan and save JSON:
  - python Tools/forensics.py /path/to/dir -r --save results.json

- Check availability of external tools (exiftool, strings, steghide, zsteg, binwalk):
  - python Tools/forensics.py . --check-tools


cipher_detector.py

- Run interactive UI for detect/encode/decode:
  - python Tools/cipher_detector.py

Notes & safety
- These tools are intended for educational/CTF use and non-intrusive reconnaissance only.
- Do not run against targets you do not have explicit permission to test.
- Consider adding `.venv/` to your `.gitignore` to avoid committing local environments.

Contributing
- Improve wordlists and add unit tests for key functions (strings extraction, decoders).
- If you want, I can add CI checks and unit tests — tell me which functions to cover.
