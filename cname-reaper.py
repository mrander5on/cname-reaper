#!/usr/bin/env python3

import argparse
import subprocess
import socket
import json
import csv
import os
import time
import re

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

def print_progress(index, total):
    # Displays a progress bar in the terminal
    percent = int((index + 1) / total * 100)
    bar = '=' * (percent // 2) + '-' * (50 - percent // 2)
    print(f"\r[{bar}] {percent}%", end='')

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

def run_dig(subdomain):
    # Runs dig for general DNS query
    try:
        output = subprocess.check_output(['dig', subdomain, '+short'], stderr=subprocess.STDOUT, timeout=5)
        return output.decode().strip().split('\n')
    except:
        return []

def get_cname(subdomain):
    # Gets the CNAME record for the subdomain or the last CNAME if multiple lines are returned.
    try:
        output = subprocess.check_output(['dig', subdomain, 'CNAME', '+short'], stderr=subprocess.STDOUT, timeout=5)
        lines = output.decode().strip().split('\n')
        lines = [line.strip('.') for line in lines if line.strip()]
        return lines[-1] if lines else None
    except:
        return None

def cname_resolves(cname):
    # Checks if the CNAME target resolves to an IP
    try:
        socket.gethostbyname(cname.strip('.'))
        return True
    except socket.gaierror:
        return False

def get_provider(cname):
    # Detects cloud provider based on known CNAME patterns
    cname = cname.lower()
    if any(x in cname for x in ['azure', 'windows','cloudapp']):
        return 'Azure'
    elif any(x in cname for x in ['amazon', 'aws', 'cloudfront']):
        return 'Amazon'
    elif any(x in cname for x in ['google', 'apigee', 'appspot', 'firebase']):
        return 'Google'
    elif any(x in cname for x in ['heroku']):
        return 'Heroku'
    elif any(x in cname for x in ['fastly']):
        return 'Fastly'
    elif any(x in cname for x in ['github']):
        return 'GitHub Pages'
    elif any(x in cname for x in ['shopify']):
        return 'Shopify'
    elif any(x in cname for x in ['bitbucket']):
        return 'Bitbucket'
    elif any(x in cname for x in ['cloudflare']):
        return 'Cloudflare'
    elif any(x in cname for x in ['wordpress']):
        return 'Wordpress'
    elif any(x in cname for x in ['hubspot']):
        return 'HubSpot'        
    else:
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

def is_unconfigured_page(banner):
    banner = banner.lower()
    error_signatures = [
        # General
        "404", "not found", "does not exist", "could not be satisfied", "not configured",
        "not served",

        # AWS
        "nosuchbucket", 
        "The bucket you are attempting to access must be addressed using the specified endpoint",
        "CloudFront", "Bad request. We can't connect to the server for this app or website at this time.",

        # Azure
        "azure", "this web app has been stopped", 
        "The resource you are looking for has been removed", "Azure App Service",
        
        # Bitbucket
        "We couldn’t find that page", "There is no site configured at this address",
        
        # Cloudflare
        "Error 1016: Origin DNS error", "CLOUDFLARE_ERROR:1001",

        # Fastly
        "fastly error: unknown domain", "Unknown Fastly domain",
        
        # GitHub Pages
        "there isn't a github pages site here",
        "The site configured at this address does not contain the requested file",
        "Create a repository at github.com",

        # Google Cloud / Firebase
        "no such object", "that’s all we know",

        # Heroku
        "heroku | no such app", "there's nothing here, yet.", "Application Error", 
        "This app is currently unavailable", "herokuapp.net",

        # Shopify
        "shop is currently unavailable", "store is not available", "This store is closed",
        "Looking for a store?",
        
        # Wordpress
        "Do you want to register", "This blog has been removed", "wordpress.com doesn’t exist",
        "No Site Here Yet",
    ]

    return any(signature in banner for signature in error_signatures)

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

# -----------------------------
# Main Logic
# -----------------------------
def main():
    print(ASCII_ART)
    subdomains = load_subdomains()
    total = len(subdomains)
    print(f"\nLoaded {total} subdomains. Beginning analysis...\n")

    results = {
        'Amazon': [], 'Azure': [], 'Bitbucket': [], 'Cloudflare': [], 'Fastly': [], 'GitHub Pages': [], 'Google': [], 'Heroku': [], 'HubSpot': [], 'Shopify': [], 'Wordpress': [], 'Other': [], 'Safe': []
    }

    for idx, sub in enumerate(subdomains):
        print_progress(idx, total)
        cname = get_cname(sub)

        # Case 1: No CNAME at all
        if not cname:
            if args.incl_safe:
                results['Safe'].append({
                    'subdomain': sub,
                    'cname': cname,
                    'provider': provider if cname else 'None',
                    'status': 'Safe',
                    'reason': 'None'
                })
            continue

        provider = get_provider(cname)

        # Case 2: CNAME resolves (check for banner)
        if cname_resolves(cname):
            banner = curl_banner(sub)
            if is_unconfigured_page(banner):
                results[provider].append({
                    'subdomain': sub,
                    'cname': cname,
                    'provider': provider if cname else 'None',
                    'status': 'Vulnerable',
                    'reason': 'NXDOMAIN' or 'Banner'  # dynamically set
                })
            else:
                if args.incl_safe:
                    results['Safe'].append({
                        'subdomain': sub,
                        'cname': cname,
                        'provider': provider if cname else 'None',
                        'status': 'Safe',
                        'reason': 'None'
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

    print("\n\n=== Potentially Vulnerable Subdomains ===\n")
    
    providers = ['Amazon', 'Azure', 'Bitbucket', 'Cloudflare', 'Fastly', 'GitHub Pages', 'Google', 'Heroku', 'HubSpot', 'Shopify', 'Wordpress', 'Other']
    is_vulnerable = any(results[p] for p in providers)
    
    if is_vulnerable:
	    for p in providers:     
		    if results[p]:
			    print(f"\n--- {p} ---")
			    for entry in results[p]:
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
        with open('output.txt', 'w') as f:
            for p in results:
                if p == 'Safe' and not args.incl_safe:
                    continue  # Skip Safe section unless --incl-safe is used
                if not results[p]:
                    continue
                f.write(f"\n--- {p} ---\n")
                for entry in results[p]:
                    print(f"{entry['subdomain']} -> {entry['cname']} -> {entry['reason']}")

    if args.csv or args.output_all:
        with open('output.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['Subdomain', 'CNAME', 'Provider', 'Status', 'Reason'])
            writer.writeheader()
            for provider_group in results.values():
                for entry in provider_group:
                    writer.writerow({
                        'Subdomain': entry['subdomain'],
                        'CNAME': entry['cname'],
                        'Provider': entry['provider'],
                        'Status': entry['status'],
                        'Reason': entry['reason']
                    })

    if args.json or args.output_all:
        with open('output.json', 'w') as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()