import random
import time

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR with the given key."""
    return bytes(a ^ b for a, b in zip(data, key))

def generate_key(length: int, seed: int) -> bytes:
    """Generate a random key of given length using the provided seed."""
    random.seed(seed)
    return bytes(random.randint(0, 255) for _ in range(length))

# The plaintext you sent to the server
your_input_plaintext = b'flag{Th3_t1m3_1s_n0w_t0_d3crypt!}'
# The ciphertext the server returned for your input
server_returned_ciphertext_hex = "d624fc7a850bb2f53b424fce0957c8ff03cf6c75d4f705e4abf2f91aa582c3d834"
server_returned_ciphertext_bytes = bytes.fromhex(server_returned_ciphertext_hex)

# The seed (timestamp) we previously found to decrypt the initial flag
known_good_seed = 1748080800 # This is Fri May 23 14:00:00 2025 MDT

# Generate the key using this known seed and the length of your input
# (which is the same length as the flag)
key_for_your_input = generate_key(len(your_input_plaintext), known_good_seed)

# Decrypt the server's response using this key
decrypted_server_response = encrypt(server_returned_ciphertext_bytes, key_for_your_input)

print(f"Your original input: {your_input_plaintext}")
print(f"Server's encrypted response (for your input): {server_returned_ciphertext_bytes.hex()}")
print(f"Key generated with seed {known_good_seed}: {key_for_your_input.hex()}")
print(f"Decrypted server response: {decrypted_server_response}")

# Check if the decrypted response matches your original input
if decrypted_server_response == your_input_plaintext:
    print("\nVerification successful! The key used for your input was indeed generated with the same timestamp.")
else:
    print("\nVerification failed.")