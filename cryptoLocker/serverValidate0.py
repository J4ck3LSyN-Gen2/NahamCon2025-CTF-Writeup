def encrypt(data: bytes, key: bytes) -> bytes:
    """Performs XOR operation. Works for encryption, decryption, and key recovery."""
    return bytes(a ^ b for a, b in zip(data, key))

# --- CORRECTED INPUTS (based on your image) ---

# 1. ORIGINAL ENCRYPTED FLAG from the server's welcome message (THIS IS THE ONE FROM YOUR IMAGE)
initial_encrypted_flag_hex = "d624fc7a856bff2565d1f920238c9b465c23934e5b857d9fa1f1ff5deec78f5e2d55a9fbdaeb"
initial_encrypted_flag_bytes = bytes.fromhex(initial_encrypted_flag_hex)
print(f"Original Encrypted Flag (from image): {initial_encrypted_flag_bytes.hex()}")

# 2. YOUR SENT PLAINTEXT (your input to the server)
your_input_plaintext = b'flag{Th3_t1m3_1s_n0w_t0_d3crypt!}'
print(f"Your Sent Plaintext: {your_input_plaintext}")

# 3. SERVER'S ENCRYPTED RESPONSE (encryption of your input)
server_returned_ciphertext_hex = "d624fc7a850bb2f53b424fce0957c8ff03cf6c75d4f705e4abf2f91aa582c3d834"
server_returned_ciphertext_bytes = bytes.fromhex(server_returned_ciphertext_hex)
print(f"Server's Encrypted Response (of your input): {server_returned_ciphertext_bytes.hex()}")

# --- STEP 1: DERIVE THE KEY ---
# The key for your input is the same key used for the initial flag.
# Key = Ciphertext_of_your_input XOR Your_input_plaintext
derived_key = encrypt(server_returned_ciphertext_bytes, your_input_plaintext)
print(f"\nDerived Key (from C_input XOR P_input): {derived_key.hex()}")

# --- STEP 2: DECRYPT THE *ORIGINAL* ENCRYPTED FLAG using the derived key ---
# Decrypted_Flag = Original_Encrypted_Flag XOR Derived_Key
decrypted_initial_flag = encrypt(initial_encrypted_flag_bytes, derived_key)

print(f"\nDecrypted Original Flag: {decrypted_initial_flag.decode(errors='ignore')}")

# Verification: Check if the decrypted flag matches the expected flag
expected_flag_bytes = b'flag{Th3_t1m3_1s_n0w_t0_d3crypt!}' # This was the flag you found earlier
if decrypted_initial_flag == expected_flag_bytes:
    print("\nSUCCESS! The derived key correctly decrypts the original flag to the expected value.")
else:
    print("\nFAILURE: The derived key does NOT decrypt the original flag to the expected value.")
    print(f"Expected: {expected_flag_bytes}")
    print(f"Got Raw:  {decrypted_initial_flag}")
    print(f"Got Decoded: {decrypted_initial_flag.decode(errors='ignore')}")