import binascii
import zipfile
import io
import re

# The new, continuous string of hexadecimal data you provided.
# It still contains embedded offsets and potentially other non-hex characters.
raw_hex_string_with_offsets = "00000000504b03040a0000000000c933b55a0000000000100000000008000000666c61672e7478740000002001002400000000000000000000000000000000300000000004000000000000000000000000000040000000000000000000000000000000000000005000000000000000000000000000000000000000600000000000000000000000000000000000000070504b010214030a0000000000c933b55a00000080000000000000000008000000666c6167000000902e747874000000000000000000000000000000a000000000000000000000000000000000000000b000000000000000000000000000000000000000c000000000000000000000000000000000000000d0504b0506000000000100010065000000000000e074000000000000000000000000000000"

# Use regex to extract only valid hexadecimal pairs (bytes)
# This will effectively strip out the embedded offsets (like '00000000', '00000010', etc.)
# and any other non-hex characters if they were present.
cleaned_full_hex_string = "".join(re.findall(r'[0-9a-fA-F]{2}', raw_hex_string_with_offsets))

# Convert hex string to bytes
try:
    zip_bytes = binascii.unhexlify(cleaned_full_hex_string)
    print(f"Successfully converted {len(cleaned_full_hex_string) // 2} hex bytes to binary.")
    # print(f"Raw binary data (first 50 bytes): {zip_bytes[:50].hex()}") # For debugging
except binascii.Error as e:
    print(f"Error converting hex to bytes: {e}")
    print("This usually means there are non-hexadecimal characters or an odd number of hex digits after cleaning.")
    exit()

# The known password for the zip file
zip_password = b"password" # Passwords for zipfile module should be bytes

# Use BytesIO to treat the bytes as a file
zip_file_object = io.BytesIO(zip_bytes)

# Attempt to open and extract the zip file with the password
try:
    with zipfile.ZipFile(zip_file_object, 'r') as zf:
        zf.setpassword(zip_password)

        print("Successfully opened the zip file object.")
        print("Files in the zip archive:")
        for name in zf.namelist():
            print(f"- {name}")
            try:
                with zf.open(name) as extracted_file:
                    content = extracted_file.read()
                    print(f"  Content of {name}:\n{content.decode(errors='ignore')}\n")
            except RuntimeError as e:
                print(f"  Error extracting '{name}': {e}")
                print("  This might indicate an incorrect password, or that the file within the ZIP is not encrypted.")
            except Exception as e:
                print(f"  An unexpected error occurred while extracting '{name}': {e}")
except zipfile.BadZipFile as e:
    print(f"Error opening zip file: {e}")
    print("The binary data is not a valid ZIP file. This could be due to:")
    print("1. Truncated/Incomplete data.")
    print("2. Corruption within the ZIP structure (e.g., CRC errors, incorrect offsets).")
    print("3. The file is not actually a ZIP file at all, despite containing 'PK' bytes.")
    print("\nIf you are *sure* it's a zip and still getting this error, it's severely malformed.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")