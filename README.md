# Team: `LOICPirates`
## Players:
* Captain: J4ck3LSyN
* Co-Player: ChoasFoundry

## [NOTE] This is a copy of the directory and is not sorted, intended for use as future a reference!

## NahamCon 2025
Landing Page: `ctf.nahamcon.com`

### Challenges

# oucast

## Methodology:
1. When going to the site we can see a `/test` directory with a comment: `this should not be accessable`
2. Goto `/test`
3. This is a API Builder page.


# Naham-Commencement 2025
Username: `nahamcon`
Password: `LetTheGameBegins2025`

# Fuzzies

## Methodology:
1. From the name `fuzzies` we can presume that we are going to be doing some fuzzing.
* For this we will use FUFF.
* We also downloaded a file `wordlist.zip`.
- passwords.txt
- wordlist.txt
2. When running `ffuf -u challenge.namahcom.com:... -w wordlist.txt
* We Find:
```
uploads                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 33ms]
admin                   [Status: 200, Size: 2499, Words: 701, Lines: 58, Duration: 46ms]
images                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 85ms]
api                     [Status: 200, Size: 13, Words: 2, Lines: 1, Duration: 189ms]
```
3. We can note `/admin` and `/api`.

#### challenge.nahamcon.com:.../admin
#### challenge.nahamcon.com:.../api
1. There are 2 tools I can think of for fuzzing A

### Solves


# Quartet
# flag{8f667b09d0e821f4e14d59a8037eb376}

## Methodology:
1. Download the files (4x`quartet.z0[NUM]` where NUM is 1-4)
2. Use `binwalk`.
```python
import os
ldir = os.listdir();ldir = [i for i in ldir if os.path.isfile(i)]
for l in ldir: os.system(f"binwalk {str(l)} >> binwalkALL.log")
```
Output:
```

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip multi-volume archive data, at least PKZIP v2.50 to extract


DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
504076        0x7B10C         End of Zip archive, footer length: 22

```
3. Combine into one script.
```
import os

def combine_zip_parts(base_name, num_parts, output_filename):
    """
    Combines multiple parts of a multi-volume ZIP archive into a single ZIP file.

    Args:
        base_name (str): The base name of the archive parts (e.g., 'quartet').
        num_parts (int): The total number of parts (e.g., 4 for z01 to z04).
        output_filename (str): The name for the combined output ZIP file
                               (e.g., 'combined_quartet.zip').
    """
    print(f"Attempting to combine ZIP parts for '{base_name}'...")
    
    # Open the output file in binary write mode.
    # 'wb' creates the file if it doesn't exist, or truncates it if it does.
    try:
        with open(output_filename, 'wb') as outfile:
            # Iterate through each part in numerical order.
            for i in range(1, num_parts + 1):
                # Construct the filename for the current part.
                # Uses f-string formatting to ensure 'z01', 'z02', etc.
                part_filename = f"{base_name}.z0{i}" 
                
                print(f"Reading part: {part_filename}")
                try:
                    # Open each part file in binary read mode.
                    with open(part_filename, 'rb') as infile:
                        # Read the entire content of the part.
                        part_content = infile.read()
                        # Write the content of the current part to the output file.
                        outfile.write(part_content)
                    print(f"Successfully appended {part_filename}.")
                except FileNotFoundError:
                    print(f"Error: Part file '{part_filename}' not found. "
                          "Please ensure all parts are in the same directory as the script.")
                    # If a part is missing, the combination cannot be completed correctly.
                    return
                except Exception as e:
                    print(f"Error reading or writing part '{part_filename}': {e}")
                    return
        
        print(f"\nSuccessfully combined all parts into '{output_filename}'.")
        print(f"You can now extract '{output_filename}' using a standard ZIP utility.")
        print("For example, on Linux/macOS: `unzip combined_quartet.zip`")
        print("On Windows, you can simply double-click the file or use 7-Zip/WinRAR.")

    except Exception as e:
        print(f"An error occurred while creating the output file '{output_filename}': {e}")

if __name__ == "__main__":
    # Define the base name of your archive parts.
    base_archive_name = 'quartet'
    # Define the total number of parts.
    total_parts = 4
    # Define the desired name for the combined ZIP file.
    combined_zip_name = 'combined_quartet.zip'

    # Call the function to combine the ZIP parts.
    combine_zip_parts(base_archive_name, total_parts, combined_zip_name)
```
4. Extract `quartet.zip`
5. Move in extracted location.
6. Check for strings: `strings quartet.jpeg > quartet.txt`
7. PWN.

# fradle
# flag{bec42475a614b9c9ba80d0eb7ed258c5}

## Sploit:
```python
import requests, string, time
# --- Configuration ---
URL = "http://challenge.nahamcon.com:31651/guess"
FLAG_PREFIX = "flag{"
FLAG_SUFFIX = "}"
FLAG_LENGTH_INSIDE_BRACES = 32 # As specified in the challenge: "exactly 32 characters inside the braces"
MAX_RETRIES = 5 # Number of times to retry a request in case of transient errors
RETRY_DELAY = 1 # Seconds to wait before retrying a request

# --- Character Set for Brute-forcing ---
# We'll start with common alphanumeric characters.
# Depending on the challenge, you might need to expand this.
# For CTF flags, lowercase letters and digits are very common.
# Sometimes uppercase letters or special characters are included.
ALPHABET = string.ascii_lowercase + string.digits

# --- Helper Function for Making Requests ---
def make_post_request(guess_payload: str) -> dict | None:
    """
    Sends a POST request to the challenge URL with the given guess payload.
    Handles potential network errors and retries.

    Args:
        guess_payload (str): The full flag guess string (e.g., "flag{...}").

    Returns:
        dict | None: The JSON response from the server if successful, None otherwise.
    """
    headers = {"Content-Type": "application/json"};data = {"guess": guess_payload}
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(URL, headers=headers, json=data, timeout=10)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error for guess '{guess_payload}': {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else: print("Max retries reached. Giving up on this request.")
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error for guess '{guess_payload}': {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else: print("Max retries reached. Giving up on this request.")
        except requests.exceptions.Timeout as e:
            print(f"Timeout error for guess '{guess_payload}': {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...");time.sleep(REPLY_DELAY)
            else:print("Max retries reached. Giving up on this request.")
        except Exception as e:
            print(f"An unexpected error occurred for guess '{guess_payload}': {e}");break # For unexpected errors, break immediately

    return None

# --- Main Automation Logic ---
def solve_challenge():
    """
    Automates the process of guessing the flag character by character.
    """
    print(f"Starting flag guessing for {URL}")
    # Initialize our knowledge of the flag. Use a placeholder for unknown characters.
    # For example, '_' or '?' are common. We'll use a dash '-' here.
    current_flag_content = ['-'] * FLAG_LENGTH_INSIDE_BRACES
    flag_entry = []
    # Loop through each position of the flag content
    for i in range(FLAG_LENGTH_INSIDE_BRACES):
        print(f"\nAttempting to find character at position {i+1}/{FLAG_LENGTH_INSIDE_BRACES}")
        found_char_for_position = False
        # Iterate through our alphabet for the current position
        for char_to_try in ALPHABET:
            test_guess_content = list(current_flag_content) # Create a mutable copy
            test_guess_content[i] = char_to_try
            # Form the full flag string
            full_guess = FLAG_PREFIX + "".join(test_guess_content) + FLAG_SUFFIX
            print(f"  Trying guess: {full_guess} // Character: {str(char_to_try)}\n\tCurrent Flag Compile: {''.join(flag_entry)}")
            response_json = make_post_request(full_guess)
            if response_json and "result" in response_json:
                result = response_json["result"]
                # print(f"  Server response likeness: {likeness}"
                if str("🟩") in str(result): flag_entry.append(str(char_to_try))
                

        if not found_char_for_position:
            print(f"Could not find a character for position {i+1} using the current ALPHABET. "
                  "You might need to expand the ALPHABET or check network connectivity.")
            # Depending on the challenge, you might want to stop here or try a different approach.
            # For simplicity, we'll continue, but the final flag might be incomplete.

    final_flag = FLAG_PREFIX + "".join(flag_entry) + FLAG_SUFFIX
    print("\n--- Flag Guessing Complete ---")
    print(f"Attempted Flag: {final_flag}")
    print(flag_entry)

if __name__ == "__main__":
    solve_challenge()
```

# The Marian
# flag{0db031ac265b3e6538aff0d9f456004f}

## Methodology:
1. Download `challenge.martian`
2. Run `binwalk challenge.martian`
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
52            0x34            bzip2 compressed data, block size = 900k
12511         0x30DF          bzip2 compressed data, block size = 900k
32896         0x8080          bzip2 compressed data, block size = 900k
38269         0x957D          bzip2 compressed data, block size = 900k
50728         0xC628          bzip2 compressed data, block size = 900k
```
3. Extract the data `binwalk -e challenge.martian`
4. cd `_challenge.martian.extracted`
5. Use `file` on the extracted data to get the types and move them accordingly.
6. Use `binwalk` as you go through, 2 main file types (jpeg,bz2)
7. Extract `.bz2` data (rabbit hole)
8. Flag was extracted as `957D` which is a `jpeg`
9. PWN

# Cube: 
# flag{4b7063c24950b524e559ef509ba7dc23}
Netcat to provided link, make sure to use inspect and get dropped into BBS style text adventure. Make sure to listen to clues from inspect. Find opening and get flag.

# FreeFlags
# flag{ae6b6fb0686ec594652afe9eb6088167}

## Methodology:
1. Download `free_flags.txt`
2. `Ctrl+f` Enter Regex from rules.
3. pwn

# CryptoLock:
# flag{0e42ba180089ce6e3bb50e52587d3724}

## Sploit:
1. serverCrack.py 
```python
import socket, threading, time, random, os, sys
from typing import Optional

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
    encrypted_flag_bytes = bytes.fromhex(encrypted_flag_hex);flag_length = len(encrypted_flag_bytes)
    print(f"Encrypted flag length: {flag_length} bytes")
    current_timestamp = int(time.time());search_window_seconds = 3600 * 24 # Try +/- 24 hours
    print(f"Starting timestamp search from {current_timestamp - search_window_seconds} to {current_timestamp + search_window_seconds}")
    ;found_flag = None;found_seed = None
    for seed_attempt in range(current_timestamp - search_window_seconds, current_timestamp + search_window_seconds + 1):
        # Generate the key using the guessed seed
        key_attempt = generate_key(flag_length, seed_attempt);decrypted_attempt = encrypt(encrypted_flag_bytes, key_attempt)
        if b"flag{" in decrypted_attempt and is_printable(decrypted_attempt):
            print(f"\nPotential flag found!")
            print(f"Seed (timestamp): {seed_attempt} (approx. {time.ctime(seed_attempt)})")
            print(f"Decrypted flag: {decrypted_attempt.decode(errors='ignore')}")
            found_flag = decrypted_attempt;found_seed = seed_attempt;break
        # You might also want to check for just printable characters if "flag{" isn't guaranteed
        # elif is_printable(decrypted_attempt) and b'}' in decrypted_attempt:
        #     print(f"Candidate: {decrypted_attempt.decode(errors='ignore')} with seed {seed_attempt}")

    if found_flag:
        print("\nFlag successfully cracked!");return found_flag.decode(errors='ignore'), found_seed
    else:
        print("\nCould not crack the flag with the current search window. Try expanding the search_window_seconds.");return None, None

if __name__ == "__main__":
    if len(sys.argv) == 1: print("Usage: python serverCrack.py <flag> ");exit(1)
    encrypted_flag = str(sys.argv[1]);cracked_flag, seed_used = crack_flag(encrypted_flag)
    if seed_used:
        print("\n--- Verifying the key generation with the found seed ---")
        known_plaintext_example = b"Hello, world!"
        key_for_example = generate_key(len(known_plaintext_example), seed_used)
        encrypted_example = encrypt(known_plaintext_example, key_for_example)
        print(f"Known Plaintext: {known_plaintext_example}")
        print(f"Generated Key (for example): {key_for_example.hex()}")
        print(f"Encrypted Example: {encrypted_example.hex()}")
        print(f"Decrypted Example (using same key): {encrypt(encrypted_example, key_for_example)}")
```
2. Connect to server `ncat challenge.nahamcon.com ...` 
* Look for the flag in string: `The encrypted flag is: `
* Copy
3. Run `python serverCrack.py 'flag-paste'`
4. PWN


# SNAD:
# flag{6ff0c72ad11bf174139e970559d9b5d2}

## Sploit:

```
// In your browser's developer console:
window.targetPositions
// Output will look something like this (exact values from your code):
/*
[
  { x: 367, y: 238, colorHue: 0 },
  { x: 412, y: 293, colorHue: 40 },
  { x: 291, y: 314, colorHue: 60 },
  { x: 392, y: 362, colorHue: 120 },
  { x: 454, y: 319, colorHue: 240 },
  { x: 349, y: 252, colorHue: 280 },
  { x: 433, y: 301, colorHue: 320 }
]
*/

// (InConsole)
particles = [];
resetGrid();
// In your browser's developer console:
window.targetPositions.forEach(target => {
    // injectSand(x, y, hue)
    window.injectSand(target.x, target.y, target.colorHue);
});
```

# Rules:
# flag{90bc54705794a62015369fd8e86e557b}

# Techinchal Difficulties:
# flag{a98373a74abb8c5ebb8f5192e034a91c}
