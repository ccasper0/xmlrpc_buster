
Features
XML-RPC Detection: Quickly verify if a WordPress site’s xmlrpc.php endpoint is enabled.

Brute-force (system.multicall): Efficiently attempt multiple username/password combinations in a single request.

SSRF Testing (pingback.ping): Exploit the pingback functionality to see if remote SSRF is possible.

Passive Reconnaissance: Identify WordPress footprints, possible usernames, and readme files.

Version Detection: Attempt to discover the WordPress version using meta tags and/or readme.html.

Plugin & Theme Enumeration: Naive checks for popular plugins/themes at known file paths.

Google Dorking: Search for potential WordPress targets using custom or built-in Google dorks.

Smart Mode: Automate the entire workflow (XML-RPC detection, passive recon, SSRF, enumeration, and brute-force) with a single command.

Multithreaded: Use multiple threads to handle a list of targets efficiently.

Auto-Filling Wordlists: Automatically locate common user/password lists (e.g., ~/rockyou.txt) if you don’t provide them explicitly.



Installation
Clone or Download this repository:

git clone https://github.com/your-org/xmlrpc_buster.git
cd xmlrpc_buster

python xmlrpc_buster.py --url https://example.com

 Provide multiple targets from a file
python xmlrpc_buster.py --targets targets.txt

 Run a Google Dork
python xmlrpc_buster.py --dork 'inurl:"xmlrpc.php" ext:php' --dork-limit 20
Flags & Arguments
Flag / Argument	Description
-u, --url	Single target URL (e.g., https://site.com)
-t, --targets	File with a list of target URLs (one per line)
--pingback	Test for SSRF using the pingback.ping XML-RPC method
--bruteforce	Enable XML-RPC multicall brute-forcing of credentials
--userlist	Username wordlist file (auto-fills from common paths if missing)
--passlist	Password wordlist file (auto-fills from ~/rockyou.txt if found)
--threads	Number of concurrent threads (default: 5)
-o, --output	Output file to store valid credentials
--dork	Perform a Google Dork search (optionally specify a custom query)
--dork-limit	Limit number of dork results (default: 10)
--ssrf-target	Custom URL/IP for SSRF via pingback.ping
--ssrf-scan	File with URLs/IPs to test SSRF in a loop
--scan-public	Scan for public data like readme, possible usernames, etc.
--detect-version	Attempt to detect WP version (via meta or readme.html)
--enum-plugins	Enumerate common plugins
--enum-themes	Enumerate common themes
--smart-mode	Run an “all-in-one” routine (recon, version, SSRF, bruteforce…)
Examples
python xmlrpc_buster.py --url https://example.com
Checks if xmlrpc.php is enabled.

Prints basic info if discovered.

Brute-force Credentials

python xmlrpc_buster.py \
    --url https://example.com \
    --bruteforce \
    --userlist users.txt \
    --passlist passwords.txt \
    --output valid_creds.txt
Checks and attempts multiple user/password combos via XML-RPC multicall.

Outputs valid credentials into valid_creds.txt.

Smart Mode on a List of Targets

python xmlrpc_buster.py \
    --targets targets.txt \
    --smart-mode \
    --enum-plugins \
    --enum-themes \
    --threads 10
Runs detection, version check, SSRF pingback, plugin/theme enumeration, and brute-forcing (if user/pass lists exist or can be auto-filled).

Uses 10 threads for faster processing.

Google Dork + SSRF Scan

python xmlrpc_buster.py \
    --dork 'inurl:"/xmlrpc.php" + "WordPress" -github' \
    --dork-limit 5 \
    --pingback \
    --ssrf-scan local_hosts.txt
Finds up to 5 potential targets with Google Dorking.


Legal Disclaimer
This project is made available by the authors for educational, ethical penetration testing and security research purposes only. You are solely responsible for obeying all applicable laws. Unauthorized attempts to gain access to a computer system are illegal and unethical. The maintainers and contributors to this project disclaim all responsibility for how you choose to use it.

License
MIT License

You’re free to modify and distribute this tool under the terms of the license. Contributions are welcome!
