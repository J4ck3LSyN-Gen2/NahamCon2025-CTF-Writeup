from scapy.all import *
import time
import random
import threading
import queue
import re # Import regular expression module
import datetime # For timestamping files

# --- Configuration ---
target_ip = "137.184.230.90"
target_port = 8080
fixed_ipid = 1337 # The known, fixed IPID to use

# --- Threading Configuration ---
# Since we are using a fixed IPID, we only need one thread to attempt the connection
# and then probe paths. More threads would be redundant for the IPID part.
num_threads = 1 

# --- Web Content Discovery Configuration ---
# List of common and CTF-relevant paths to probe
paths_to_probe = [
    "/",
    "/index.html",
    "/.htaccess",
    "/flag.txt",
    "/secret.txt",
    "/admin/",
    "/robots.txt",
    "/sitemap.xml",
    "/backup/",
    ".git",
    ".svn",
    "/phpinfo.php",
    "/test.php",
    "/config.php",
    ".git",
    ".svn",
    "/phpinfo.php",
    "/test.php",
    "/config.php",
    "/.git/config", # Common for exposed Git repositories
    "/.svn/entries", # Common for exposed SVN repositories
    "/phpinfo.php",
    "/test.php",
    "/config.php",
    "/.env", # Environment variables file
    "/README.md",
    "/LICENSE",
    "/assets/",
    "/images/",
    "/css/",
    "/js/",
    "/login",
    "/dashboard",
    "/api/v1/flag", # Example API endpoint
    "/debug",
    "/dev",
    "/old",
    "/temp",
    "/upload",
    "/data",
    "/files",
    "/hidden",
    "/private",
    "/cgi-bin/",
    "/server-status",
    "/status",
    "/info",
    "/_wpeprivate/config.json", # WordPress specific
    "/wp-content/uploads/", # WordPress specific
    "/wp-includes/", # WordPress specific
    "/wp-admin/", # WordPress specific
    "/admin.php",
    "/panel/",
    "/controlpanel/",
    "/shell.php", # Common web shell name
    "/cmd.php",   # Common web shell name
    "/backdoor.php", # Common web shell name
    "/web.config", # IIS specific
    "/crossdomain.xml", # Flash/Silverlight specific
    "/clientaccesspolicy.xml", # Silverlight specific
    "/server-info", # Apache specific
    "/~root/", # Linux user directories
    "/~admin/",
    "/~webmaster/",
    "/~guest/",
    "/~test/",
    "/config",
    "/config.bak",
    "/config.old",
    "/config.txt",
    "/config.zip",
    "/database.sql",
    "/db.sqlite",
    "/db.json",
    #"/app_config.py",
    #"/settings.py",
    "/credentials.txt",
    "/id_rsa", # SSH private key
    "/id_rsa.pub", # SSH public key
    "/authorized_keys", # SSH authorized keys
    #"/proc/self/cmdline", # Linux procfs
    #"/etc/passwd", # Linux password file
    #"/etc/shadow", # Linux shadow file (unlikely to be directly accessible via HTTP)
    "/var/log/apache2/access.log", # Apache logs
    #"/var/log/nginx/access.log", # Nginx logs
    "/error_log",
    "/access_log",
    "/logs",
    #"/backup.zip",
    #"/archive.tar.gz",
    #"/dump.sql",
    #"/dump.zip",
    #"/phpmyadmin/",
    #"/adminer/",
    #"/pma/",
    #"/sqlitebrowser/",
    "/test/",
    #"/dev/",
    #"/temp/",
    "/tmp/",
    #"/cache/",
    #"/old/",
    #"/new/",
    #"/staging/",
    #"/production/",
    #"/development/",
    #"/beta/",
    #"/alpha/",
    #"/testbed/",
    #"/playground/",
    #"/sandbox/",
    #"/portal/",
    #"/control/",
    #"/manager/",
    #"/console/",
    "/api",
    "/v1/",
    "/v2/",
    "/v3/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    #"/graphql",
    #"/swagger-ui/",
    #"/docs/",
    #"/documentation/",
    #"/help/",
    #"/info/",
    "/status/",
    #"/metrics/",
    #"/health/",
    #"/monitor/",
    #"/debug/",
    #"/trace/",
    #"/error/",
    "/log/",
    #"/report/",
    "/stats/",
    "/data/",
    "/files/",
    "/uploads/",
    "/downloads/",
    "/images/",
    #"/media/",
    #"/videos/",
    #"/audio/",
    #"/fonts/",
    #"/icons/",
    #"/css/",
    "/js/",
    #"/lib/",
    #"/vendor/",
    #"/node_modules/",
    #"/bower_components/",
    #"/vendor/",
    #"/src/",
    #"/dist/",
    #"/build/",
    #"/out/",
    #"/target/",
    #"/bin/",
    #"/obj/",
    #"/tmp/",
    #"/var/",
    #"/etc/",
    #"/usr/",
    #"/opt/",
    #"/srv/",
    #"/mnt/",
    #"/media/",
    #"/dev/",
    #"/proc/",
    #"/sys/",
    #"/boot/",
    #"/root/",
    #"/home/",
    #"/usr/local/",
    #"/usr/share/",
    #"/usr/bin/",
    #"/usr/sbin/",
    #"/usr/lib/",
    #"/usr/include/",
    #"/usr/src/",
    #"/var/www/",
    #"/var/log/",
    #"/var/lib/",
    #"/var/cache/",
    #"/var/tmp/",
    #"/var/run/",
    #"/var/spool/",
    #"/var/mail/",
    #"/var/opt/",
    #"/var/backups/",
    #"/var/crash/",
    #"/var/lock/",
    #"/var/local/",
    #"/var/metrics/",
    #"/var/metrics/prometheus/",
    #"/var/metrics/grafana/",
    #"/var/metrics/influxdb/",
    #"/var/metrics/elasticsearch/",
    #"/var/metrics/kibana/",
    #"/var/metrics/logstash/",
    #"/var/metrics/filebeat/",
    #"/var/metrics/metricbeat/",
    #"/var/metrics/packetbeat/",
    #"/var/metrics/heartbeat/",
    #"/var/metrics/auditbeat/",
    #"/var/metrics/winlogbeat/",
    #"/var/metrics/journalbeat/",
    #"/var/metrics/functionbeat/",
    #"/var/metrics/cloudbeat/",
    #"/var/metrics/apm-server/",
    #"/var/metrics/apm-agent/",
    #"/var/metrics/apm-client/",
    #"/var/metrics/apm-data/",
    #"/var/metrics/apm-server-data/",
    #"/var/metrics/apm-agent-data/",
    #"/var/metrics/apm-client-data/",
    #"/var/metrics/apm-data-stream/",
    #"/var/metrics/apm-data-stream-data/",
    #"/var/metrics/apm-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream/",
    #"/var/metrics/apm-data-stream-data-stream-data/",
    #"/var/metrics/apm-data-stream-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-client-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-agent-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-server-data/",
    #"/var/metrics/apm-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream-data-stream/",
]


# --- Global Variables for Threading ---
found_event = threading.Event() # Event to signal when a response is found
print_lock = threading.Lock() # Lock for synchronized printing

# --- Helper Function for Flag Detection ---
def check_for_flag(response_content):
    """
    Checks the given response content for common CTF flag patterns.
    Args:
        response_content (bytes): The raw bytes of the HTTP response body.
    Returns:
        str or None: The detected flag string if found, otherwise None.
    """
    decoded_content = response_content.decode(errors='ignore')

    # Common flag formats using regex
    flag_patterns = [
        re.compile(r"flag\{[a-zA-Z0-9_!@#$%\^&\*\(\)-=\+\[\]\{\}\|;:'\",.<>\/?`~ ]+\}"),
        re.compile(r"CTF\{[a-zA-Z0-9_!@#$%\^&\*\(\)-=\+\[\]\{\}\|;:'\",.<>\/?`~ ]+\}"),
        re.compile(r"FLAG\{[a-zA-Z0-9_!@#$%\^&\*\(\)-=\+\[\]\{\}\|;:'\",.<>\/?`~ ]+\}"),
        re.compile(r"picoCTF\{[a-zA-Z0-9_!@#$%\^&\*\(\)-=\+\[\]\{\}\|;:'\",.<>\/?`~ ]+\}"),
        re.compile(r"HTB\{[a-zA-Z0-9_!@#$%\^&\*\(\)-=\+\[\]\{\}\|;:'\",.<>\/?`~ ]+\}"),
        # Add more specific patterns if you know the CTF platform
    ]

    for pattern in flag_patterns:
        match = pattern.search(decoded_content)
        if match:
            return match.group(0) # Return the full matched flag string

    # Look for interesting keywords (case-insensitive)
    keywords = ["secret", "key", "password", "admin", "hidden", "challenge", "credentials"]
    for keyword in keywords:
        if keyword in decoded_content.lower():
            # If a keyword is found, it's not the flag itself, but indicates something interesting
            # We'll just return a generic message indicating a keyword match
            return f"Potential interesting content found (keyword: '{keyword}'). Review response manually."

    return None

# --- Worker Function for Threads ---
def ipid_scanner_worker():
    """
    Worker function for the single thread.
    Uses the fixed IPID, sends SYN packets, and checks for responses.
    If a SYN-ACK is received, it completes the handshake and then
    sends HTTP GET requests for various paths, checking for flags and writing responses to file.
    Signals 'found_event' if a successful response or flag is found.
    """
    current_ipid = fixed_ipid # Use the fixed IPID directly

    # This loop allows the thread to gracefully exit if found_event is set by another thread
    # (though with num_threads=1, it effectively runs once).
    while not found_event.is_set():
        try:
            # Craft an IP packet with the specific IPID and a TCP SYN flag
            src_port = random.randint(1024, 65535)
            
            ip_packet = IP(dst=target_ip, id=current_ipid)
            tcp_packet = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 0xFFFFFFFF)) # Initial sequence number

            packet = ip_packet / tcp_packet

            with print_lock:
                # Use \r for in-place update only if not a successful response
                if not found_event.is_set():
                    print(f"[*] Thread {threading.current_thread().name}: Sending SYN packet with fixed IPID: {current_ipid}", end='\r')

            # Send the SYN packet and wait for a SYN-ACK response
            response = sr1(packet, timeout=0.5, verbose=False)

            if response and response.haslayer(TCP) and response[TCP].flags == "SA":
                with print_lock:
                    print(f"\n[+] SUCCESS! Received SYN-ACK from {response.src} with IPID: {response.id} for our fixed IPID: {current_ipid}")
                    print(f"    [+] Response TCP flags: {response[TCP].flags}")
                    print("    [!] Initiating full TCP handshake and HTTP GET requests...")

                # --- Complete TCP 3-way Handshake (ACK) ---
                my_ack = response[TCP].seq + 1 # Server's sequence number + 1
                my_seq = packet[TCP].seq + 1 # Our initial sequence number + 1 (for the ACK)

                ack_packet = IP(dst=target_ip, id=current_ipid) / \
                             TCP(sport=src_port, dport=target_port, flags="A", seq=my_seq, ack=my_ack)
                
                send(ack_packet, verbose=False)
                with print_lock:
                    print(f"    [+] Sent ACK packet with seq={my_seq}, ack={my_ack}")

                # --- Send HTTP GET Requests for various paths ---
                for path in paths_to_probe:
                    if found_event.is_set(): # Stop if flag found by another thread
                        break

                    http_request = (
                        b"GET " + path.encode() + b" HTTP/1.1\r\n"
                        b"Host: " + target_ip.encode() + b":" + str(target_port).encode() + b"\r\n"
                        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36\r\n"
                        b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                        b"Accept-Encoding: gzip, deflate\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    
                    get_packet = IP(dst=target_ip, id=current_ipid) / \
                                 TCP(sport=src_port, dport=target_port, flags="PA", seq=my_seq, ack=my_ack) / \
                                 Raw(load=http_request)
                    
                    send(get_packet, verbose=False)
                    with print_lock:
                        print(f"    [+] Sent HTTP GET request for path: {path}. Expecting response...")
                    
                    # Give the server a moment to respond
                    time.sleep(0.5) 

                    full_response = b""
                    try:
                        # Filter for packets from target IP, to our source port, with ACK or PSH flags
                        # Removed count limit to capture all fragments
                        captured_packets = sniff(
                            filter=f"src host {target_ip} and src port {target_port} and dst port {src_port} and (tcp[13] & 0x08 != 0 or tcp[13] & 0x01 != 0 or tcp[13] & 0x10 != 0)", 
                            timeout=5 # Reduced sniff timeout per request to 5 seconds, as we're doing many
                        )
                        
                        http_status_code = None
                        for recv_pkt in captured_packets:
                            if recv_pkt.haslayer(Raw):
                                payload_data = bytes(recv_pkt[Raw].load)
                                full_response += payload_data
                                # Attempt to parse HTTP status code from the first packet's payload
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

                            # If we see a FIN or RST from the server, it's closing the connection
                            if recv_pkt.haslayer(TCP) and (recv_pkt[TCP].flags == "F" or recv_pkt[TCP].flags == "R"):
                                with print_lock:
                                    print(f"    [!] Server sent FIN/RST for {path}. Connection closing for this request.")
                                break # Stop sniffing if connection is closing

                    except Exception as sniff_e:
                        with print_lock:
                            print(f"[-] Error during sniffing for path {path}: {sniff_e}")

                    if full_response:
                        with print_lock:
                            print(f"    [+] Received HTTP Response for {path} (Status: {http_status_code if http_status_code else 'N/A'}, Length: {len(full_response)} bytes)")
                            # print(f"        Payload (decoded snippet): {full_response[:500].decode(errors='ignore').strip()}...") # Print snippet for debugging

                        # Write response to file
                        try:
                            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                            # Sanitize path for filename
                            sanitized_path = path.strip('/').replace('/', '_').replace('.', '_')
                            if not sanitized_path:
                                sanitized_path = "root" # For "/" path
                            
                            filename = f"response_ipid_{current_ipid}_path_{sanitized_path}_{timestamp}.txt"
                            with open(filename, "wb") as f:
                                f.write(full_response)
                            with print_lock:
                                print(f"    [+] Full HTTP response written to {filename}")
                        except Exception as file_e:
                            with print_lock:
                                print(f"[-] Error writing response to file for path {path}: {file_e}")

                        # Check for flag in the response
                        flag_found = check_for_flag(full_response)
                        if flag_found:
                            found_event.set() # Signal other threads to stop
                            with print_lock:
                                print(f"\n\n[!!!] FLAG FOUND! [!!!]")
                                print(f"[!!!] Path: {path}")
                                print(f"[!!!] Flag: {flag_found}")
                                print(f"[!!!] Full Response:\n{full_response.decode(errors='ignore').strip()}")
                            break # Break from path loop if flag found
                    else:
                        with print_lock:
                            print(f"    [-] No HTTP response content captured for path: {path}.")

                # --- Gracefully Close Connection (FIN) ---
                # The sequence number for the FIN packet should be the last sent sequence number.
                # 'my_seq' was the sequence number for the PSH-ACK (GET request).
                # So, we add the length of the HTTP request to it.
                fin_seq = my_seq + len(http_request)
                fin_ack = my_ack # Acknowledgment number remains the same (server's next expected sequence)

                fin_packet = IP(dst=target_ip, id=current_ipid) / \
                             TCP(sport=src_port, dport=target_port, flags="FA", seq=fin_seq, ack=fin_ack)
                
                send(fin_packet, verbose=False)
                with print_lock:
                    print(f"    [+] Sent FIN packet to close connection for IPID {current_ipid}.")

            elif response: # If response but not SYN-ACK
                with print_lock:
                    print(f"\n[-] Received non-SYN-ACK response from {response.src} with IPID: {response.id} for our fixed IPID: {current_ipid}")
                    if response.haslayer(TCP):
                        print(f"    [+] Response TCP flags: {response[TCP].flags}")
                    if response.haslayer(ICMP):
                        print(f"    [+] Response ICMP type: {response[ICMP].type}, code: {response[ICMP].code}")
            
        except Exception as e:
            with print_lock:
                print(f"[-] Thread {threading.current_thread().name}: Error processing IPID {current_ipid}: {e}")
        finally:
            # Since we're using a fixed IPID and num_threads=1, this loop will naturally break after one attempt.
            if found_event.is_set():
                break
            break # Ensure the thread exits after processing the fixed IPID once

# --- Main Script Logic ---
print(f"[*] Starting web content discovery for {target_ip}:{target_port}")
print(f"[*] Using fixed IPID: {fixed_ipid}")

# Create and start worker threads
threads = []
print(f"[*] Starting {num_threads} worker threads...")
for i in range(num_threads):
    thread = threading.Thread(target=ipid_scanner_worker, name=f"ScannerThread-{i+1}")
    thread.daemon = True # Allow main program to exit even if threads are running
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

if not found_event.is_set():
    print(f"\n[-] No successful HTTP response containing a flag received after attempting with fixed IPID {fixed_ipid} and various paths.")
    print("[!] Review the generated response files for any clues.")

print("[*] Web content discovery attempt complete.")