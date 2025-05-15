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
# This tool detects dangling DNS records that are potentially vulnerable 
# to hijacking/takeover through subdomain enumeration, DNS lookups, 
# and banner-grabbing.
# 
# It supports various input methods, including single entries or lists of 
# apex domains and subdomains.
#
# Results are grouped by hosting provider (e.g., Azure, AWS, Google, etc.) 
# and can be output to the screen, text, CSV, or JSON files.
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
import re
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# Argument Parsing
# -----------------------------
class CustomHelpParser(argparse.ArgumentParser):
    """
    Custom argument parser to display ASCII art along with the help message.
    """
    def print_help(self, file=None):
        print(ASCII_ART)
        super().print_help(file)

# Define command-line arguments
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
    """
    Loads subdomains from various input methods:
    1. Single subdomain provided via the `-s` argument.
    2. File containing a list of subdomains provided via the `-sl` argument.
    3. Single apex domain (enumerates subdomains using crt.sh) via the `-d` argument.
    4. File containing a list of apex domains (enumerates subdomains for each) via the `-dl` argument.

    Returns:
        list: A list of unique subdomains.
    """
    subdomains = set()

    # Option 1: Single subdomain
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
    """
    Queries crt.sh for subdomains of a given apex domain.

    Args:
        domain (str): The apex domain to query.

    Returns:
        set: A set of subdomains found via crt.sh.
    """
    try:
        response = subprocess.check_output([
            'curl', '-s', '-A', 'Mozilla/5.0',
            f'https://crt.sh/?q=%25.{domain}&output=json'
        ], timeout=15)

        if not response or not response.strip().startswith(b'['):
            raise ValueError("Invalid or empty JSON response")

        entries = json.loads(response.decode())
        return {name.strip().lstrip('*.').lower()
                for entry in entries
                for name in entry.get('name_value', '').split('\n')
                if domain in name}
    except Exception as e:
        print(f"Warning: Failed to fetch from crt.sh for {domain}: {e}")
        return set()


def get_cname(subdomain):
    """
    Retrieves the CNAME record for a given subdomain using the `dig` command.

    Args:
        subdomain (str): The subdomain to query.

    Returns:
        str: The CNAME record or an error message (e.g., "No CNAME", "Timeout").
    """
    try:
        result = subprocess.run(['dig', subdomain, 'CNAME', '+short'], capture_output=True, text=True, timeout=5)
        output = result.stdout.strip()
        if not output:
            return "No CNAME"
        return output.split('\n')[-1].rstrip('.')
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return "Error"


def cname_resolves(cname):
    """
    Checks if a CNAME resolves to an IP address.

    Args:
        cname (str): The CNAME to resolve.

    Returns:
        bool: True if the CNAME resolves, False otherwise.
    """
    try:
        socket.gethostbyname(cname.strip('.'))
        return True
    except socket.gaierror:
        return False


def load_hosting_signatures(file_path='hosting_sigs.txt'):
    """
    Loads hosting provider signatures from a file.

    Args:
        file_path (str): Path to the hosting signatures file.

    Returns:
        dict: A dictionary mapping provider names to their signatures.
    """
    signatures = {}
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    provider, sigs = line.split(':', 1)
                    signatures[provider.strip()] = [sig.strip().strip('"') for sig in sigs.split(',')]
    except FileNotFoundError:
        print(f"Error: Hosting signatures file '{file_path}' not found.")
    except Exception as e:
        print(f"Error: Failed to load hosting signatures: {e}")
    return signatures


def get_hosting_provider(cname, signatures):
    """
    Determines the hosting provider based on the CNAME and loaded signatures.

    Args:
        cname (str): The CNAME to check.
        signatures (dict): Hosting provider signatures.

    Returns:
        str: The hosting provider name or 'Other' if not found.
    """
    cname = cname.lower()
    for provider, sigs in signatures.items():
        if any(sig in cname for sig in sigs):
            return provider
    return 'Other'


def curl_banner(subdomain):
    """
    Uses curl to grab the HTTP response content from the subdomain.

    Args:
        subdomain (str): The subdomain to query.

    Returns:
        str: The HTTP response content.
    """
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

    Args:
        file_path (str): Path to the error signatures file.

    Returns:
        list: A list of error signatures.
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

    Args:
        banner (str): The HTTP response content.
        error_signatures (list): Known error signatures.

    Returns:
        bool: True if a known error signature is found, False otherwise.
    """
    banner = banner.lower()
    return any(signature in banner for signature in error_signatures)

def write_output_file(file_type, results, file_name):
    """
    Writes the analysis results to a file.

    Args:
        file_type (str): The type of file to write (e.g., 'text', 'csv', 'json').
        results (dict): The analysis results.
        file_name (str): The name of the output file.
    """
    if file_type == 'text':
        with open(file_name, 'w') as f:
            for provider, entries in results.items():
                if provider == 'Safe' and not args.incl_safe:
                    continue
                if not entries:
                    continue
                f.write(f"\n--- {provider} ---\n")
                for entry in entries:
                    f.write(f"{entry['subdomain']} -> {entry['cname']} -> {entry['reason']}\n")
    elif file_type == 'csv':
        with open(file_name, 'w', newline='') as f:
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
    elif file_type == 'json':
        with open(file_name, 'w') as f:
            json.dump(results, f, indent=2)


def analyze_subdomain(sub, hosting_signatures, error_signatures):
    """
    Analyzes a single subdomain for vulnerabilities.

    Args:
        sub (str): The subdomain to analyze.
        hosting_signatures (dict): Hosting provider signatures.
        error_signatures (list): Known error signatures.

    Returns:
        dict: Analysis result for the subdomain, or None if safe and not included.
    """
    cname = get_cname(sub)

    # Case 1: No CNAME at all
    if cname == "No CNAME":
        if args.incl_safe:
            return {
                'subdomain': sub,
                'cname': cname,
                'provider': 'None',
                'status': 'Safe',
                'reason': 'No CNAME'
            }
        return None

    # Determine the hosting provider
    provider = get_hosting_provider(cname, hosting_signatures)

    # Case 2: CNAME resolves (check for misconfigured page)
    if cname_resolves(cname):
        banner = curl_banner(sub)
        if is_misconfigured_page(banner, error_signatures):
            return {
                'subdomain': sub,
                'cname': cname,
                'provider': provider,
                'status': 'Vulnerable',
                'reason': 'Misconfigured Page'
            }
        elif args.incl_safe:
            return {
                'subdomain': sub,
                'cname': cname,
                'provider': provider,
                'status': 'Safe',
                'reason': 'Resolved'
            }
    else:
        # Case 3: CNAME exists but doesn't resolve — NXDOMAIN
        return {
            'subdomain': sub,
            'cname': cname,
            'provider': provider,
            'status': 'Vulnerable',
            'reason': 'NXDOMAIN'
        }

    return None


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

    # Use ThreadPoolExecutor for parallel analysis with tqdm for progress tracking
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(analyze_subdomain, sub, hosting_signatures, error_signatures): sub
            for sub in subdomains
        }

        # Use tqdm to track progress
        for future in tqdm(as_completed(futures), total=len(futures), desc="Analyzing Subdomains"):
            try:
                result = future.result()
                if result:
                    provider = result['provider']
                    if provider not in results:
                        provider = 'Other'
                    results[provider].append(result)
            except Exception as e:
                print(f"Error analyzing subdomain: {e}")

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
        write_output_file('text', results, 'reaper-output.txt')

    if args.csv or args.output_all:
        write_output_file('csv', results, 'reaper-output.csv')

    if args.json or args.output_all:
        write_output_file('json', results, 'reaper-output.json')


if __name__ == "__main__":
    main()
