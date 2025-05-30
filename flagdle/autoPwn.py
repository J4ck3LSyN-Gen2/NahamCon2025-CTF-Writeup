import requests
import string
import time


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
    headers = {"Content-Type": "application/json"}
    data = {"guess": guess_payload}
    
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
            else:
                print("Max retries reached. Giving up on this request.")
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error for guess '{guess_payload}': {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                print("Max retries reached. Giving up on this request.")
        except requests.exceptions.Timeout as e:
            print(f"Timeout error for guess '{guess_payload}': {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(REPLY_DELAY)
            else:
                print("Max retries reached. Giving up on this request.")
        except Exception as e:
            print(f"An unexpected error occurred for guess '{guess_payload}': {e}")
            break # For unexpected errors, break immediately

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
            
    
    # Keep track of characters we know are correct (green) or in the wrong position (yellow)
    # This might be useful for more advanced Wordle-like solvers, but for this specific
    # challenge where we get exact position feedback (green squares), we can simplify.
    
    # Loop through each position of the flag content
    for i in range(FLAG_LENGTH_INSIDE_BRACES):
        print(f"\nAttempting to find character at position {i+1}/{FLAG_LENGTH_INSIDE_BRACES}")
        found_char_for_position = False
        
        # Iterate through our alphabet for the current position
        for char_to_try in ALPHABET:
            # Construct a test guess: take the current known flag,
            # and insert the 'char_to_try' at the current position 'i'.
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

    # Final verification (optional, but good practice)
    print("\nAttempting final verification of the full flag...")
    final_response = make_post_request(final_flag)
    if final_response and "likeness" in final_response:
        print(f"Server response for final flag: {final_response['likeness']}")
        if all(c == '🟩' for c in final_response['likeness']):
            print("🎉🎉🎉 Successfully found the flag! 🎉🎉🎉")
            print(f"The flag is: {final_flag}")
        else:
            print("Final verification failed. The guessed flag is not entirely green.")
            print("This could mean some characters are still incorrect, or the character set is incomplete.")
    else:
        print("Failed to get a verification response for the final flag.")

if __name__ == "__main__":
    solve_challenge()