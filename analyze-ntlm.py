import collections

# CONFIGURATION
INPUT_FILE = "domain_hashes.ntds"  # Ensure this matches your filename
IGNORE_EMPTY = True                # Ignore empty password hashes (31d6cf...)

# ANSI Colors
RED = "\033[91m"
RESET = "\033[0m"

# Constants
EMPTY_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

def is_target_user(full_username):
    """
    Checks if the username matches specific admin patterns.
    Handles 'DOMAIN\user' format by splitting the string.
    """
    # Split domain to get the actual user part (e.g., "CONTOSO\a.smith" -> "a.smith")
    if "\\" in full_username:
        user_part = full_username.split("\\")[-1]
    else:
        user_part = full_username

    user_lower = user_part.lower()

    # 1. Prefixes (Beginning of user)
    prefixes = ("a.", "adm.", "adm_", "admin", "da.", "da_")
    if user_lower.startswith(prefixes):
        return True

    # 2. Suffixes (End of user)
    suffixes = ("_adm", ".admin", "_admin", ".a", "_da", ".da")
    if user_lower.endswith(suffixes):
        return True
        
    return False

def analyze_hashes(filename):
    hash_map = collections.defaultdict(list)
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split(':')
                if len(parts) < 4:
                    continue
                
                user = parts[0]
                nt_hash = parts[3].lower()
                
                if IGNORE_EMPTY and nt_hash == EMPTY_HASH:
                    continue
                    
                hash_map[nt_hash].append(user)

    except FileNotFoundError:
        print(f"Error: Could not find file '{filename}'")
        return

    # Filter for hashes that appear more than once
    shared_hashes = {k: v for k, v in hash_map.items() if len(v) > 1}
    
    # Sort by number of users (descending)
    sorted_hashes = sorted(shared_hashes.items(), key=lambda item: len(item[1]), reverse=True)

    print(f"[-] Total unique hashes found: {len(hash_map)}")
    print(f"[-] Total shared hash groups: {len(shared_hashes)}")
    print("-" * 60)
    
    for nt_hash, users in sorted_hashes:
        print(f"Hash: {nt_hash}")
        print(f"Count: {len(users)}")
        
        # Colorize users if they match the admin patterns
        colored_users = []
        for u in users:
            if is_target_user(u):
                colored_users.append(f"{RED}{u}{RESET}")
            else:
                colored_users.append(u)
                
        print(f"Users: {', '.join(colored_users)}")
        print("-" * 60)

if __name__ == "__main__":
    analyze_hashes(INPUT_FILE)
