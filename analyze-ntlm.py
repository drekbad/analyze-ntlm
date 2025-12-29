#!/usr/bin/env python3

import argparse
import collections
import sys
import os
import re

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[1;33m"  # "Orange" / Warning
CYAN = "\033[96m"      # For Admin<->User correlation
RESET = "\033[0m"
BOLD = "\033[1m"

# Constants
EMPTY_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

# Admin naming patterns to strip for comparison
PREFIXES = ("a.", "adm.", "adm_", "admin", "da.", "da_")
SUFFIXES = ("_adm", ".admin", "_admin", ".a", "_da", ".da")

def get_args():
    parser = argparse.ArgumentParser(
        description="""
        [ NTLM Reuse Analyzer - Advanced ]
        ------------------------------------------------------------------
        Identifies password reuse with advanced heuristic tagging.
        
        Highlights:
          1. [ORANGE] Confirmed DA/EA users (via --privileged list)
          2. [CYAN]   Admin accounts sharing pass with non-admin self
          3. [RED]    Suspected admin accounts (via naming convention)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-f", "--file", required=True, help="Path to the .ntds file from secretsdump")
    parser.add_argument("-p", "--privileged", help="Path to a text file containing DA/EA usernames (one per line)")
    parser.add_argument("--include-empty", action="store_true", help="Include empty/disabled password hashes")
    
    return parser.parse_args()

def load_privileged_users(filepath):
    """Loads a list of high-value targets from a file."""
    priv_users = set()
    if not filepath:
        return priv_users
        
    if not os.path.exists(filepath):
        print(f"{RED}[!] Warning: Privileged user file '{filepath}' not found.{RESET}")
        return priv_users

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            u = line.strip().lower()
            if u:
                # Store simple username if domain is present
                if "\\" in u:
                    priv_users.add(u.split("\\")[-1])
                else:
                    priv_users.add(u)
    return priv_users

def get_base_username(full_username):
    """
    Strips admin prefixes/suffixes to find the 'base' user.
    Example: 'adm_bob' -> 'bob'
    """
    if "\\" in full_username:
        user = full_username.split("\\")[-1].lower()
    else:
        user = full_username.lower()

    # Strip prefixes
    for pre in PREFIXES:
        if user.startswith(pre):
            return user[len(pre):] # Remove prefix
            
    # Strip suffixes
    for suf in SUFFIXES:
        if user.endswith(suf):
            return user[:-len(suf)] # Remove suffix
            
    return user

def is_pattern_admin(full_username):
    """Checks regex patterns for suspected admins."""
    if "\\" in full_username:
        user = full_username.split("\\")[-1].lower()
    else:
        user = full_username.lower()
        
    if user.startswith(PREFIXES) or user.endswith(SUFFIXES):
        return True
    return False

def analyze_hashes(filename, priv_file, include_empty):
    # Load inputs
    priv_users = load_privileged_users(priv_file)
    hash_map = collections.defaultdict(list)
    
    if not os.path.exists(filename):
        print(f"{RED}[!] Error: File '{filename}' not found.{RESET}")
        sys.exit(1)

    # 1. Parse the NTDS dump
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or len(line.split(':')) < 4:
                    continue
                
                parts = line.split(':')
                user = parts[0]
                nt_hash = parts[3].lower()
                
                if not include_empty and nt_hash == EMPTY_HASH:
                    continue
                    
                hash_map[nt_hash].append(user)
    except Exception as e:
        print(f"{RED}[!] Error reading NTDS file: {e}{RESET}")
        sys.exit(1)

    # 2. Filter for shared hashes
    shared_hashes = {k: v for k, v in hash_map.items() if len(v) > 1}
    sorted_hashes = sorted(shared_hashes.items(), key=lambda item: len(item[1]), reverse=True)

    # 3. Calculate Stats
    total_priv_reuse = 0
    total_self_reuse = 0
    
    # Pre-scan for stats
    for _, users in sorted_hashes:
        # Check for priv users in this group
        for u in users:
            u_clean = u.split("\\")[-1].lower() if "\\" in u else u.lower()
            if u_clean in priv_users:
                total_priv_reuse += 1
                
        # Check for self-reuse (admin vs normal) in this group
        base_names = [get_base_username(x) for x in users]
        # If the number of unique base names is less than total users, 
        # it means "bob" and "adm_bob" both reduced to "bob" in the same group.
        if len(set(base_names)) < len(base_names):
            # This is a rough count of groups containing self-reuse
            total_self_reuse += 1

    # 4. Print Summary
    print(f"\n{BOLD}[ Analysis Summary ]{RESET}")
    print(f"[-] Total Unique Hashes:    {len(hash_map)}")
    print(f"[-] Shared Hash Groups:     {len(shared_hashes)}")
    print(f"[-] {YELLOW}DA/EA Reuse Instances:  {total_priv_reuse}{RESET}")
    print(f"[-] {CYAN}Admin/User Self-Reuse:    {total_self_reuse} groups{RESET}")
    print("-" * 70)
    
    # 5. Print Details
    for nt_hash, users in sorted_hashes:
        formatted_users = []
        
        # Create a set of base names in this group to detect collisions quickly
        group_base_names = [get_base_username(u) for u in users]
        
        for i, u in enumerate(users):
            u_clean = u.split("\\")[-1].lower() if "\\" in u else u.lower()
            u_base = get_base_username(u)
            
            # Determining the Color Priority
            
            # Priority 1: Explicit Privileged List (DA/EA) -> ORANGE/YELLOW
            if u_clean in priv_users:
                formatted_users.append(f"{YELLOW}{u} (DA){RESET}")
                
            # Priority 2: Self-Reuse (Admin shares with User) -> CYAN
            # We check if the 'base' name appears more than once in this group's base names
            elif group_base_names.count(u_base) > 1:
                formatted_users.append(f"{CYAN}{u}{RESET}")
                
            # Priority 3: Pattern Match (Suspected Admin) -> RED
            elif is_pattern_admin(u):
                formatted_users.append(f"{RED}{u}{RESET}")
                
            # Priority 4: Standard User -> Default
            else:
                formatted_users.append(u)

        print(f"Hash:  {nt_hash}")
        print(f"Count: {len(users)}")
        print(f"Users: {', '.join(formatted_users)}")
        print("-" * 70)

if __name__ == "__main__":
    args = get_args()
    analyze_hashes(args.file, args.privileged, args.include_empty)
