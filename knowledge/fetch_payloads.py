import os
import urllib.request
from pathlib import Path

PAYLOAD_DIR = Path(__file__).parent / "payloads"
PAYLOAD_DIR.mkdir(exist_ok=True, parents=True)

# Curated, highly specific dictionary lists so it stays fast!
SOURCES = {
    "sqli_seclists": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
    "xss_seclists": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
    "lfi_seclists": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    "ssrf_seclists": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF/SSRF-Filter-Bypass.txt",
    "cmd_injection_seclists": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt"
}

def main():
    print("Downloading curated lightweight fuzzing payloads...")
    for target_name, url in SOURCES.items():
        base_cat = target_name.split("_")[0] # 'sqli', 'xss', etc
        if base_cat == "cmd": base_cat = "cmd_injection" # Fix map
        target_file = PAYLOAD_DIR / f"{base_cat}.txt"
        
        try:
            print(f"Fetch -> {url}")
            # Fetch content
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
            # Take top 100 to ensure speed
            lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
            top_100 = lines[:100]
            
            # Append to existing
            existing_lines = []
            if target_file.exists():
                existing_lines = target_file.read_text(errors='ignore').splitlines()
                
            merged = list(dict.fromkeys(existing_lines + top_100))
            
            target_file.write_text("\n".join(merged), encoding='utf-8')
            print(f"  [+] Injected {len(top_100)} premium payloads into {target_file.name}")
        except Exception as e:
            print(f"  [-] Failed to download {url}: {e}")
            
if __name__ == "__main__":
    main()
