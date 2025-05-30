import socket
import threading
import time
import random
import os
from typing import Optional

import sys

# Copy the encryption functions from the server script for local key generation
def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR with the given key."""
    return bytes(a ^ b for a, b in zip(data, key))

def generate_key(length: int, seed: Optional[float] = None) -> bytes:
    """Generate a random key of given length using the provided seed."""
    if seed is not None:
        random.seed(int(seed)) # Important: seed takes an integer
    return bytes(random.randint(0, 255) for _ in range(length))

def is_printable(data: bytes) -> bool:
    """Checks if all bytes in data are printable ASCII characters."""
    # Common printable ASCII range (space to tilde)
    for byte in data:
        if not (32 <= byte <= 126 or byte == 10 or byte == 13): # Allow space, newline, carriage return
            return False
    return True

def crack_flag(encrypted_flag_hex: str):
    encrypted_flag_bytes = bytes.fromhex(encrypted_flag_hex)
    flag_length = len(encrypted_flag_bytes)

    print(f"Encrypted flag length: {flag_length} bytes")

    # Get current timestamp for a starting point
    current_timestamp = int(time.time())

    # Search window: Try timestamps around the current time.
    # A few minutes before and after should be sufficient if the server is new.
    # Adjust this range based on when you think the server might have started.
    # For a CTF, it's often within a few hours of when the challenge was released or
    # when you first interacted with it.
    search_window_seconds = 3600 * 24 # Try +/- 24 hours

    print(f"Starting timestamp search from {current_timestamp - search_window_seconds} to {current_timestamp + search_window_seconds}")

    found_flag = None
    found_seed = None

    for seed_attempt in range(current_timestamp - search_window_seconds, current_timestamp + search_window_seconds + 1):
        # Generate the key using the guessed seed
        key_attempt = generate_key(flag_length, seed_attempt)

        # Decrypt the flag with the generated key
        decrypted_attempt = encrypt(encrypted_flag_bytes, key_attempt)

        # Check if the decrypted attempt looks like a valid flag
        # We can look for common flag patterns (e.g., "flag{", printable characters)
        if b"flag{" in decrypted_attempt and is_printable(decrypted_attempt):
            print(f"\nPotential flag found!")
            print(f"Seed (timestamp): {seed_attempt} (approx. {time.ctime(seed_attempt)})")
            print(f"Decrypted flag: {decrypted_attempt.decode(errors='ignore')}")
            found_flag = decrypted_attempt
            found_seed = seed_attempt
            break
        # You might also want to check for just printable characters if "flag{" isn't guaranteed
        # elif is_printable(decrypted_attempt) and b'}' in decrypted_attempt:
        #     print(f"Candidate: {decrypted_attempt.decode(errors='ignore')} with seed {seed_attempt}")

    if found_flag:
        print("\nFlag successfully cracked!")
        return found_flag.decode(errors='ignore'), found_seed
    else:
        print("\nCould not crack the flag with the current search window. Try expanding the search_window_seconds.")
        return None, None

if __name__ == "__main__":
    if len(sys.argv) == 1: 
        print("Usage: python serverCrack.py <flag> ");exit(1)
    encrypted_flag = str(sys.argv[1])
    
    # Run the cracking function
    cracked_flag, seed_used = crack_flag(encrypted_flag)

    # You could also interact with the server directly to confirm the key
    # For a more robust solution, you might connect to the server, send a known input,
    # and then calculate the key from the response.

    # Example of how you would calculate the key if you interacted with the server
    # and knew the exact timestamp of connection, or determined it.
    # Let's assume you found the seed_used from the brute-force above.
    if seed_used:
        print("\n--- Verifying the key generation with the found seed ---")
        known_plaintext_example = b"Hello, world!"
        key_for_example = generate_key(len(known_plaintext_example), seed_used)
        encrypted_example = encrypt(known_plaintext_example, key_for_example)
        print(f"Known Plaintext: {known_plaintext_example}")
        print(f"Generated Key (for example): {key_for_example.hex()}")
        print(f"Encrypted Example: {encrypted_example.hex()}")
        print(f"Decrypted Example (using same key): {encrypt(encrypted_example, key_for_example)}")