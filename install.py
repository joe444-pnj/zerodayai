#!/usr/bin/env python3
"""
ZeroDay AI — Unified Installation Script
Automates the setup of dependencies, databases, and external tools.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def print_step(msg):
    print(f"\n[*] {msg}...")

def run_command(cmd, shell=False):
    try:
        subprocess.run(cmd, check=True, shell=shell)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error executing command: {cmd}")
        print(f"[!] Details: {e}")
        return False
    return True

def main():
    print("""
    =========================================
       ZeroDay AI — Installation Wizard
    =========================================
    """)

    base_dir = Path(__file__).parent.absolute()
    os.chdir(base_dir)

    # 1. Python Dependencies
    print_step("Installing Python dependencies from requirements.txt")
    if not run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]):
        print("[!] Failed to install dependencies. Please check your internet connection.")
        sys.exit(1)

    # 2. Database Initialization
    print_step("Initializing local database")
    # Assuming there's a script or we can just run the main with an init flag
    # If not, we'll create an empty DB or run migrations
    if (base_dir / "zeroday.db").exists():
        print("[+] Database already exists.")
    else:
        # Create an empty file to ensure it's there, or run a setup script if available
        open(base_dir / "zeroday.db", 'a').close()
        print("[+] Database initialized.")

    # 3. Playwright Browsers
    print_step("Installing Playwright browsers (for SiteImager)")
    run_command([sys.executable, "-m", "playwright", "install", "chromium"])

    # 4. External Tool Checks
    print_step("Checking for external security tools")
    tools = ["nmap", "ollama", "git"]
    for tool in tools:
        if shutil.which(tool):
            print(f"[+] Found {tool}")
        else:
            print(f"[?] {tool} not found. Some features might be limited.")

    # 5. Environment Setup
    print_step("Setting up .env file")
    env_path = base_dir / ".env"
    if not env_path.exists():
        with open(env_path, "w") as f:
            f.write("# ZeroDay AI Configuration\n")
            f.write("OLLAMA_HOST=http://localhost:11434\n")
            f.write("OLLAMA_MODEL=mistral\n")
            f.write("OUTPUT_DIR=reports\n")
        print("[+] Created default .env file.")
    else:
        print("[+] .env file already exists.")

    print("\n" + "="*41)
    print("   ZeroDay AI Installation Complete!")
    print("="*41)
    print("\nTo start the tool, run:")
    print(f"  python {base_dir / 'main.py'}")
    print("\nHappy Hunting! ⚡\n")

if __name__ == "__main__":
    main()
