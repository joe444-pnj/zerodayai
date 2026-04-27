# PoC Downloader & Safety Scanner

This tool helps you safely use public exploit Proof-of-Concepts (PoCs) from CVE references.

## How it works

1. **Extracts PoC links** from CVE references (GitHub, ExploitDB, etc).
2. **Downloads** the PoC scripts to a sandboxed `poc_scripts/` directory.
3. **Scans** each script for dangerous operations (e.g., `rm -rf`, `curl | sh`, `pip install`).
4. **Only allows safe PoCs** to be used in exploitation or simulation.

## Usage Example

```python
from tools.poc_downloader import get_safe_pocs_for_cve

# Example: references from a CVE
refs = [
    "https://github.com/username/repo/blob/main/exploit.py",
    "https://www.exploit-db.com/exploits/12345",
    "https://gist.github.com/username/abcdef"
]

safe_pocs = get_safe_pocs_for_cve(refs)
for poc in safe_pocs:
    print(f"Safe PoC: {poc}")
    # You can now simulate or review this PoC
```

## How to Integrate
- Use this tool in your exploitation phase to fetch and vet PoCs before running or simulating them.
- Never run a PoC that is flagged as unsafe!

## Customizing Safety
- Edit `DANGEROUS_PATTERNS` in `poc_downloader.py` to add/remove blocked operations.
- Only allow extensions in `SAFE_EXTENSIONS`.

---

**Warning:**
- This tool does not guarantee 100% safety. Always review PoCs before running them, especially on production or sensitive systems.
