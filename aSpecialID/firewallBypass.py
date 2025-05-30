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
                http_request = b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b":" + str(target_port).encode() + b"\r\nConnection: close\r\n\r\n"
                
                # The HTTP request is part of the TCP payload.
                # The sequence number for the HTTP request packet will be our last sequence number (my_seq)
                # The acknowledgment number will be the server's last sequence number (my_ack)
                get_packet = IP(dst=target_ip, id=current_ipid) / \
                             TCP(sport=src_port, dport=target_port, flags="PA", seq=my_seq, ack=my_ack) / \
                             Raw(load=http_request)
                
                # Send the GET request and wait for the HTTP response
                # We expect multiple packets for the HTTP response, so use sr (send/receive)
                # We'll set a longer timeout for the full HTTP response
                http_response_packets = sr(get_packet, timeout=5, verbose=False)

                if http_response_packets:
                    full_response = b""
                    # http_response_packets[0] contains the answered packets (sent, received)
                    # We need to iterate over the received packets from these tuples
                    for sent_pkt, recv_pkt in http_response_packets[0]: # FIX: Correctly unpack the (sent, received) tuple
                        if recv_pkt.haslayer(Raw):
                            full_response += recv_pkt[Raw].load
                    
                    with print_lock:
                        print("\n[+] Received HTTP Response:")
                        print(full_response.decode(errors='ignore')) # Decode, ignoring errors for non-text content
                else:
                    with print_lock:
                        print("[-] No HTTP response received after sending GET request.")

                # --- Gracefully Close Connection (FIN) ---
                # Increment sequence number by length of HTTP request for FIN
                fin_seq = my_seq + len(http_request)
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