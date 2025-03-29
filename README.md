
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
--help

Legal Disclaimer
This project is made available by the authors for educational, ethical penetration testing and security research purposes only. You are solely responsible for obeying all applicable laws. Unauthorized attempts to gain access to a computer system are illegal and unethical. The maintainers and contributors to this project disclaim all responsibility for how you choose to use it.

License
MIT License

You’re free to modify and distribute this tool under the terms of the license. Contributions are welcome!
