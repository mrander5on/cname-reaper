#!/usr/bin/env python3

ASCII_ART = r"""
  ____ _   _    _    __  __ _____   ____                            
 / ___| \ | |  / \  |  \/  | ____| |  _ \ ___  __ _ _ __   ___ _ __ 
| |   |  \| | / _ \ | |\/| |  _|   | |_) / _ \/ _` | '_ \ / _ \ '__|
| |___| |\  |/ ___ \| |  | | |___  |  _ <  __/ (_| | |_) |  __/ |   
 \____|_| \_/_/   \_\_|  |_|_____| |_| \_\___|\__,_| .__/ \___|_|   
                                                   |_|                          

                 ☠️  Reaping Dead DNS Records ⚔️
             
"""

# -----------------------------
# CNAME Reaper: A Dangling DNS Detection Tool
# -----------------------------
# Detects dangling DNS records that are potentially vulnerable 
# to hijacking/takeover through subdomain enumeration, DNS lookups, 
# and banner-grabbing.
# 
# Acceptable inputs including single entry or lists of apex and subdomains.
#
# Results are grouped by provider: Azure, AWS, Google, etc. Outputs include
# screen, text, csv, and JSON.
# -----------------------------

# -----------------------------
# Imports
# -----------------------------

import argparse
import subprocess
import socket
import json
import csv
import os
import time
import re
import shlex  # Import shlex for parsing quoted strings

# -----------------------------
# Argument Parsing
# -----------------------------
class CustomHelpParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        print(ASCII_ART)
        super().print_help(file)

parser = CustomHelpParser(description='CNAME Reaper: A Dangling DNS Detection Tool')
parser.add_argument('-d', '--domain', help='Single apex domain')
parser.add_argument('-dl', '--domain-list', help='File with apex domains')
parser.add_argument('-s', '--subdomain', help='Single subdomain')
parser.add_argument('-sl', '--subdomain-list', help='File with subdomains')
parser.add_argument('--incl-safe', dest='incl_safe', action='store_true', help='Include safe domains in output')
parser.add_argument('-ot', '--text', action='store_true', help='Output to text file')
parser.add_argument('-oc', '--csv', action='store_true', help='Output to CSV file')
parser.add_argument('-oj', '--json', action='store_true', help='Output to JSON file')
parser.add_argument('-oa', '--output-all', action='store_true', help='Output to all formats')
args = parser.parse_args()

# -----------------------------
# Utility Functions
# -----------------------------

def load_subdomains():
    # Loads subdomains from various input methods:
    # 1. Single subdomain
    # 2. Subdomain list file
    # 3. Single apex domain via crt.sh
    # 4. Apex domain list via crt.sh

    subdomains = set()

    # Option 1: Single subdomain (direct use)
    if args.subdomain:
        subdomains.add(args.subdomain.strip())

    # Option 2: File with list of subdomains
    elif args.subdomain_list:
        with open(args.subdomain_list) as f:
            for line in f:
                line = line.strip()
                if line:
                    subdomains.add(line)

    # Option 3: Single apex domain (enumerate with crt.sh)
    elif args.domain:
        subdomains.update(query_crtsh(args.domain))

    # Option 4: File with list of apex domains
    elif args.domain_list:
        with open(args.domain_list) as f:
            for line in f:
                domain = line.strip()
                if domain:
                    subdomains.update(query_crtsh(domain))

    return list(subdomains)


def query_crtsh(domain):
    # Queries crt.sh for subdomains related to the given apex domain
    try:
        # Add user-agent header to avoid silent blocking
        response = subprocess.check_output([
            'curl', '-s', '-A', 'Mozilla/5.0',
            f'https://crt.sh/?q=%25.{domain}&output=json'
        ], timeout=15)

        # Validate response before parsing
        if not response or not response.strip().startswith(b'['):
            raise ValueError("Invalid or empty JSON response")

        import json as jsonlib
        entries = jsonlib.loads(response.decode())

        found = set()
        for entry in entries:
            names = entry.get('name_value', '')
            for name in names.split('\n'):
                if domain in name:
                    cleaned = name.strip().lstrip('*.').lower()
                    if cleaned:
                        found.add(cleaned)
        return found

    except Exception as e:
        print(f"Warning: Failed to fetch from crt.sh for {domain}: {e}")
        return set()

def get_cname(subdomain):
    try:
        # Use '+short' to simplify the output to just the CNAME target
        result = subprocess.run(['dig', subdomain, 'CNAME', '+short'], capture_output=True, text=True, timeout=5)
        output = result.stdout.strip()

        # If the output is empty, there is no CNAME
        if not output:
            return "No CNAME"

        # Return the CNAME target (last line of the output)
        return output.split('\n')[-1].rstrip('.')
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return "Error"
    
def get_cname_status(subdomain):
    try:
        result = subprocess.run(['dig', subdomain], capture_output=True, text=True, timeout=5)
        output = result.stdout
        return "status: NXDOMAIN" in output
    except subprocess.TimeoutExpired:
        return False

def cname_resolves(cname):
    # Checks if the CNAME target resolves to an IP
    try:
        socket.gethostbyname(cname.strip('.'))
        return True
    except socket.gaierror:
        return False

def load_hosting_signatures(file_path='hosting_sigs.txt'):
    """
    Loads hosting provider signatures from a file.
    The file should have the format:
    provider_name:"signature1","signature2","signature3"
    """
    signatures = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    provider, sigs = line.split(':', 1)
                    # Remove surrounding quotes from the entire string
                    if sigs.startswith('"') and sigs.endswith('"'):
                        sigs = sigs[1:-1]
                    # Split the signatures and strip quotes from each one
                    signatures[provider.strip()] = [sig.strip().strip('"') for sig in sigs.split(',')]
    except FileNotFoundError:
        print(f"Error: Hosting signatures file '{file_path}' not found.")
    except Exception as e:
        print(f"Error: Failed to load hosting signatures: {e}")
    return signatures

def get_hosting_provider(cname, signatures):
    """
    Determines the hosting provider based on the CNAME and loaded signatures.
    """
    cname = cname.lower()
    for provider, sigs in signatures.items():
        if any(sig in cname for sig in sigs):
            return provider
    return 'Other'

def curl_banner(subdomain):
    # Uses curl to grab the HTTP response content from the subdomain
    try:
        output = subprocess.check_output(['curl', '-s', f'http://{subdomain}'], stderr=subprocess.STDOUT, timeout=5)
        return output.decode(errors='ignore')
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors='ignore')
    except:
        return ''

def load_error_signatures(file_path='error_sigs.txt'):
    """
    Loads error signatures from a file.
    The file should contain one quoted error signature per line.
    """
    error_signatures = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Ignore empty lines
                    # Remove surrounding quotes if present
                    if line.startswith('"') and line.endswith('"'):
                        line = line[1:-1]
                    error_signatures.append(line.lower())
    except FileNotFoundError:
        print(f"Error: Error signatures file '{file_path}' not found.")
    return error_signatures

def is_misconfigured_page(banner, error_signatures):
    """
    Checks if the banner contains any known error signatures.
    """
    banner = banner.lower()
    return any(signature in banner for signature in error_signatures)

def print_progress(index, total):
    # Displays a progress bar in the terminal
    percent = int((index + 1) / total * 100)
    bar = '=' * (percent // 2) + '-' * (50 - percent // 2)
    print(f"\r[{bar}] {percent}%", end='')

# -----------------------------
# Main Logic
# -----------------------------
def main():
    print(ASCII_ART)
    
    # Load subdomains, error signatures, and hosting signatures
    subdomains = load_subdomains()
    error_signatures = load_error_signatures()
    hosting_signatures = load_hosting_signatures()
    
    total = len(subdomains)
    print(f"\nLoaded {total} subdomains. Beginning analysis...\n")

    # Dynamically initialize results dictionary based on hosting signatures
    results = {provider: [] for provider in hosting_signatures.keys()}
    results['Other'] = []  # Add "Other" category
    results['Safe'] = []   # Add "Safe" category

    # Analyze each subdomain
    for idx, sub in enumerate(subdomains):
        print_progress(idx, total)
        cname = get_cname(sub)

        # Case 1: No CNAME at all
        if cname == "No CNAME":
            if args.incl_safe:
                results['Safe'].append({
                    'subdomain': sub,
                    'cname': cname,
                    'provider': 'None',
                    'status': 'Safe',
                    'reason': 'No CNAME'
                })
            continue

        # Determine the hosting provider
        provider = get_hosting_provider(cname, hosting_signatures)

        # Case 2: CNAME resolves (check for misconfigured page)
        if cname_resolves(cname):
            banner = curl_banner(sub)
            if is_misconfigured_page(banner, error_signatures):
                results[provider].append({
                    'subdomain': sub,
                    'cname': cname,
                    'provider': provider,
                    'status': 'Vulnerable',
                    'reason': 'Misconfigured Page'
                })
            else:
                if args.incl_safe:
                    results['Safe'].append({
                        'subdomain': sub,
                        'cname': cname,
                        'provider': provider,
                        'status': 'Safe',
                        'reason': 'Resolved'
                    })
        else:
            # Case 3: CNAME exists but doesn't resolve — NXDOMAIN
            results[provider].append({
                'subdomain': sub,
                'cname': cname,
                'provider': provider,
                'status': 'Vulnerable',
                'reason': 'NXDOMAIN'
            })

    # Display results
    print("\n\n=== Potentially Vulnerable Subdomains ===\n")
    is_vulnerable = any(results[p] for p in results if p not in ['Safe'])

    if is_vulnerable:
        for provider, entries in results.items():
            if provider == 'Safe' or not entries:
                continue
            print(f"\n--- {provider} ---")
            for entry in entries:
                print(f"{entry['subdomain']} -> {entry['cname']} -> {entry['reason']}")
    else:
        print("No vulnerable subdomains found.\n")

    if args.incl_safe:
        print("\n=== Safe Subdomains ===")
        if results['Safe']:
            for entry in results['Safe']:
                print(f"{entry['subdomain']} -> {entry['cname']}")
        else:
            print("No safe subdomains found.\n")
    
    # Write output files as requested
    if args.text or args.output_all:
        with open('reaper-output.txt', 'w') as f:
            for provider, entries in results.items():
                if provider == 'Safe' and not args.incl_safe:
                    continue  # Skip Safe section unless --incl-safe is used
                if not entries:
                    continue
                f.write(f"\n--- {provider} ---\n")
                for entry in entries:
                    f.write(f"{entry['subdomain']} -> {entry['cname']} -> {entry['reason']}\n")

    if args.csv or args.output_all:
        with open('reaper-output.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['Subdomain', 'CNAME', 'Provider', 'Status', 'Reason'])
            writer.writeheader()
            for provider, entries in results.items():
                for entry in entries:
                    writer.writerow({
                        'Subdomain': entry['subdomain'],
                        'CNAME': entry['cname'],
                        'Provider': entry['provider'],
                        'Status': entry['status'],
                        'Reason': entry['reason']
                    })

    if args.json or args.output_all:
        with open('reaper-output.json', 'w') as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()