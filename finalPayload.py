from scapy.all import *
import time
import random
import threading
import queue

# --- Configuration ---
target_ip = "137.184.230.90"
target_port = 8080

# Choose your probing strategy:
# Set to 'sequential' to try IPIDs from start_ipid to end_ipid.
# Set to 'random' to try num_random_probes random IPIDs.
probing_strategy = 'sequential' # Change to 'random' to switch strategy

# --- Sequential Probing Configuration ---
# The full range of IPID is 0-65535. Trying the full range can take time.
start_ipid_sequential = 0
end_ipid_sequential = 65535 # Expanded to full 16-bit range

# --- Random Probing Configuration ---
num_random_probes = 5000 # Number of random IPIDs to try

# --- Threading Configuration ---
num_threads = 10 # Number of concurrent threads to use for scanning

# --- Global Variables for Threading ---
ipid_queue = queue.Queue() # Queue to hold IPIDs to be scanned
found_event = threading.Event() # Event to signal when a response is found
print_lock = threading.Lock() # Lock for synchronized printing

# --- Worker Function for Threads ---
def ipid_scanner_worker():
    """
    Worker function for each thread.
    Pulls IPIDs from the queue, sends SYN packets, and checks for responses.
    If a SYN-ACK is received, it completes the handshake and sends an HTTP GET request.
    Signals 'found_event' if a successful response is received.
    """
    while not found_event.is_set():
        try:
            current_ipid = ipid_queue.get(timeout=1) # Get an IPID from the queue
        except queue.Empty:
            # If queue is empty and no response found yet, this thread is done
            break

        try:
            # Craft an IP packet with the specific IPID and a TCP SYN flag
            # Use a consistent source port for easier tracking, or let Scapy pick one.
            # We'll use a random source port for better realism.
            src_port = random.randint(1024, 65535)
            
            ip_packet = IP(dst=target_ip, id=current_ipid)
            tcp_packet = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 0xFFFFFFFF)) # Initial sequence number

            packet = ip_packet / tcp_packet

            with print_lock:
                # Use \r for in-place update only if not a successful response
                if not found_event.is_set():
                    print(f"[*] Thread {threading.current_thread().name}: Sending SYN packet with IPID: {current_ipid}", end='\r')

            # Send the SYN packet and wait for a SYN-ACK response
            response = sr1(packet, timeout=0.5, verbose=False)

            if response and response.haslayer(TCP) and response[TCP].flags == "SA":
                found_event.set() # Signal other threads to stop
                
                with print_lock:
                    print(f"\n[+] SUCCESS! Received SYN-ACK from {response.src} with IPID: {response.id} for our IPID: {current_ipid}")
                    print(f"    [+] Response TCP flags: {response[TCP].flags}")
                    print("    [!] Initiating full TCP handshake and HTTP GET request...")

                # --- Complete TCP 3-way Handshake (ACK) ---
                # Acknowledge the server's SYN-ACK
                my_ack = response[TCP].seq + 1 # Server's sequence number + 1
                my_seq = packet[TCP].seq + 1 # Our initial sequence number + 1 (for the ACK)

                ack_packet = IP(dst=target_ip, id=current_ipid) / \
                             TCP(sport=src_port, dport=target_port, flags="A", seq=my_seq, ack=my_ack)
                
                # Send the ACK and don't expect a response for just the ACK
                send(ack_packet, verbose=False)
                with print_lock:
                    print(f"    [+] Sent ACK packet with seq={my_seq}, ack={my_ack}")

                # --- Send HTTP GET Request ---
                http_request = (
                    b"GET / HTTP/1.1\r\n"
                    b"Host: " + target_ip.encode() + b":" + str(target_port).encode() + b"\r\n"
                    b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36\r\n"
                    b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                    b"Accept-Encoding: gzip, deflate\r\n"
                    b"Connection: close\r\n\r\n" # Changed back to 'close' for simpler one-off request
                )
                
                get_packet = IP(dst=target_ip, id=current_ipid) / \
                             TCP(sport=src_port, dport=target_port, flags="PA", seq=my_seq, ack=my_ack) / \
                             Raw(load=http_request)
                
                # Send the GET request
                send(get_packet, verbose=False)
                with print_lock:
                    print(f"    [+] Sent HTTP GET request. Expecting response...")
                
                # Give the server a moment to respond
                time.sleep(0.5) 

                full_response = b""
                # Use sniff to capture all relevant packets for a duration
                # Filter for packets from the target IP and port, destined for our source port
                # We also need to capture packets with PSH flag (data) or FIN flag (connection close)
                try:
                    # Filter for packets from target IP, to our source port, with ACK or PSH flags
                    # Increased timeout for sniffing
                    captured_packets = sniff(
                        filter=f"src host {target_ip} and src port {target_port} and dst port {src_port} and (tcp[13] & 0x08 != 0 or tcp[13] & 0x01 != 0 or tcp[13] & 0x10 != 0)", 
                        timeout=15, # Increased sniff timeout to 15 seconds
                        count=10 # Limit the number of packets to avoid infinite loop if something goes wrong
                    )
                    
                    with print_lock:
                        print("\n[+] Received HTTP Response Packets (via sniff):")
                    
                    for recv_pkt in captured_packets:
                        with print_lock:
                            print(f"    [+] Packet received: {recv_pkt.summary()}")
                            if recv_pkt.haslayer(TCP):
                                print(f"        TCP Flags: {recv_pkt[TCP].flags}, Seq: {recv_pkt[TCP].seq}, Ack: {recv_pkt[TCP].ack}")
                                if len(recv_pkt[TCP].payload) > 0:
                                    print(f"        TCP Payload Length: {len(recv_pkt[TCP].payload)}")
                        
                        # Extract payload from Raw layer first, then TCP payload if Raw is not present
                        payload_data = b""
                        if recv_pkt.haslayer(Raw):
                            payload_data = bytes(recv_pkt[Raw].load)
                        elif recv_pkt.haslayer(TCP) and len(recv_pkt[TCP].payload) > 0:
                            payload_data = bytes(recv_pkt[TCP].payload)
                        
                        if payload_data:
                            full_response += payload_data
                            with print_lock:
                                print(f"        Payload (raw bytes, length {len(payload_data)}): {payload_data}")
                                try:
                                    print(f"        Payload (decoded snippet): {payload_data[:200].decode(errors='ignore').strip()}...")
                                except:
                                    pass
                        
                        # If we see a FIN or RST from the server, it's closing the connection
                        if recv_pkt.haslayer(TCP) and (recv_pkt[TCP].flags == "F" or recv_pkt[TCP].flags == "R"):
                            with print_lock:
                                print("    [!] Server sent FIN/RST. Connection closing.")
                            break # Stop sniffing if connection is closing

                except Exception as sniff_e:
                    with print_lock:
                        print(f"[-] Error during sniffing: {sniff_e}")

                if full_response:
                    with print_lock:
                        print("\n[+] Full HTTP Response (Aggregated):")
                        print(full_response.decode(errors='ignore').strip())
                else:
                    with print_lock:
                        print("[-] No HTTP response content captured.")

                # --- Gracefully Close Connection (FIN) ---
                # Increment sequence number by length of HTTP request for FIN
                # This is an approximation for FIN sequence number.
                # For robustness, you'd track the last sent sequence number.
                fin_seq = my_seq + len(http_request) + len(full_response) # Adjust for data sent/received
                fin_ack = my_ack # Acknowledgment number remains the same

                fin_packet = IP(dst=target_ip, id=current_ipid) / \
                             TCP(sport=src_port, dport=target_port, flags="FA", seq=fin_seq, ack=fin_ack)
                
                send(fin_packet, verbose=False)
                with print_lock:
                    print("    [+] Sent FIN packet to close connection.")

            elif response: # If response but not SYN-ACK
                with print_lock:
                    print(f"\n[-] Received non-SYN-ACK response from {response.src} with IPID: {response.id} for our IPID: {current_ipid}")
                    if response.haslayer(TCP):
                        print(f"    [+] Response TCP flags: {response[TCP].flags}")
                    if response.haslayer(ICMP):
                        print(f"    [+] Response ICMP type: {response[ICMP].type}, code: {response[ICMP].code}")
            
        except Exception as e:
            with print_lock:
                print(f"[-] Thread {threading.current_thread().name}: Error processing IPID {current_ipid}: {e}")
        finally:
            ipid_queue.task_done() # Mark the task as done for this IPID
            # If a successful interaction happened, this thread is done.
            if found_event.is_set():
                break

# --- Main Script Logic ---
print(f"[*] Starting IPID spoofing attempt for {target_ip}:{target_port}")

# Populate the IPID queue based on the chosen strategy
if probing_strategy == 'sequential':
    print(f"[*] Strategy: Sequential IPID probing from {start_ipid_sequential} to {end_ipid_sequential}...")
    for ipid in range(start_ipid_sequential, end_ipid_sequential + 1):
        ipid_queue.put(ipid)
elif probing_strategy == 'random':
    print(f"[*] Strategy: Random IPID probing for {num_random_probes} attempts...")
    for _ in range(num_random_probes):
        ipid_queue.put(random.randint(0, 65535))
else:
    print("[!] Invalid probing_strategy. Please choose 'sequential' or 'random'. Exiting.")
    exit()

# Create and start worker threads
threads = []
print(f"[*] Starting {num_threads} worker threads...")
for i in range(num_threads):
    thread = threading.Thread(target=ipid_scanner_worker, name=f"ScannerThread-{i+1}")
    thread.daemon = True # Allow main program to exit even if threads are running
    threads.append(thread)
    thread.start()

# Wait for all IPIDs to be processed or for a success event
ipid_queue.join() # Blocks until all items in the queue have been gotten and processed

if not found_event.is_set():
    print(f"\n[-] No successful HTTP response received after trying IPIDs with the '{probing_strategy}' strategy.")
    print("[!] Consider adjusting the range, number of probes, or switching strategies.")

print("[*] IPID spoofing attempt complete.")