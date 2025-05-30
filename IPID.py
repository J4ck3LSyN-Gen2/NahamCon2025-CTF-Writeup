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
            ip_packet = IP(dst=target_ip, id=current_ipid)
            tcp_packet = TCP(dport=target_port, flags="S") # SYN flag for connection attempt
            packet = ip_packet / tcp_packet

            with print_lock:
                print(f"[*] Thread {threading.current_thread().name}: Sending SYN packet with IPID: {current_ipid}")

            # Send the packet and wait for a response (timeout for no response)
            # verbose=False suppresses Scapy's default output for each packet
            response = sr1(packet, timeout=0.5, verbose=False)

            if response:
                found_event.set() # Signal other threads to stop
                with print_lock:
                    print(f"\n[+] SUCCESS! Received response from {response.src} with IPID: {response.id} for our IPID: {current_ipid}")
                    if response.haslayer(TCP):
                        print(f"    [+] Response TCP flags: {response[TCP].flags}")
                        if response[TCP].flags == "SA": # SYN-ACK indicates a successful handshake initiation
                            print("    [!] This looks like a successful SYN-ACK! The firewall might be bypassed.")
                    if response.haslayer(ICMP):
                        print(f"    [+] Response ICMP type: {response[ICMP].type}, code: {response[ICMP].code}")
            
        except Exception as e:
            with print_lock:
                print(f"[-] Thread {threading.current_thread().name}: Error processing IPID {current_ipid}: {e}")
        finally:
            ipid_queue.task_done() # Mark the task as done for this IPID

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
    print(f"\n[-] No response received after trying IPIDs with the '{probing_strategy}' strategy.")
    print("[!] Consider adjusting the range, number of probes, or switching strategies.")

print("[*] IPID spoofing attempt complete.")