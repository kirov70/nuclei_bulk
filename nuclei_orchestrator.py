#!/usr/bin/env python3
"""
Nuclei Scan Automation Script
Author: CISO Office
Description: Updates Nuclei templates, prompts for a target file, and runs a 
             multi-category scan with custom headers and JSONL output.
Usage: python nuclei_scan_automation.py
"""

import subprocess
import os
import sys
import datetime

def update_templates():
    """Updates the local Nuclei templates repository."""
    print("[*] Updating Nuclei templates repository...")
    try:
        # Use check=True to raise an exception if the update fails
        subprocess.run(["nuclei", "-update-templates"], check=True)
        print("[+] Templates updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to update templates. Exit code: {e.returncode}")
        sys.exit(1)
    print()

def run_scan(target_file: str) -> None:
    """Executes the Nuclei scan with specified categories, severities, and headers."""
    if not os.path.isfile(target_file):
        print(f"[-] Error: Target file '{target_file}' not found.")
        return

    # Generate a safe, timestamped output filename based on the input file
    base_name = os.path.splitext(os.path.basename(target_file))[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"nuclei_results_{base_name}_{timestamp}.jsonl"

    print(f"[*] Target List: {target_file}")
    print(f"[*] Output File: {output_file}\n")
    print("[*] Running Nuclei scan...")
    print("-" * 50)

    # Construct command as a list to prevent shell injection and handle quoting safely
    command = [
        "nuclei",
        "-l", target_file,
        "-t", "http/technologies,http/exposures,http/misconfiguration,http/vulnerabilities,http/cves",
        "-severity", "critical,high,medium,low,info",
        "-jsonl",
        "-o", output_file,
        "-rate-limit", "80",
        "-rate-limit-minute", "1500",
        "-retries", "2",
        "-concurrency", "50",
        "-timeout", "15",
        "-system-resolvers",
        "-header", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "-header", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-header", "Accept-Language: en-US,en;q=0.9",
        "-header", "Connection: keep-alive"
    ]

    try:
        result = subprocess.run(command, check=True)
        print("-" * 50)
        print(f"[+] Scan completed successfully.")
        print(f"[+] Results saved to: {os.path.abspath(output_file)}")
    except subprocess.CalledProcessError as e:
        print("-" * 50)
        print(f"[-] Scan encountered errors. Exit code: {e.returncode}")
    except FileNotFoundError:
        print("[-] Error: 'nuclei' executable not found in PATH. Please ensure it is installed.")

if __name__ == "__main__":
    print("=" * 50)
    print("  Discovery Senior Living - Nuclei Scanner")
    print("=" * 50)
    
    try:
        update_templates()
        
        # Prompt for input with cleanup of surrounding quotes/whitespace
        file_path = input("Enter the full path to your target file: ").strip().strip('"\'')
        
        if file_path:
            run_scan(file_path)
        else:
            print("[-] No path provided. Exiting.")
            
    except KeyboardInterrupt:
        print("\n[-] Operation cancelled by user.")
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
