import binascii
import zipfile
import io
import re # Import the regular expression module

# The hexdump data from the screenshot.
# I'm using the lines as they appeared, including offsets and ASCII.
# The crucial step will be to clean these lines.
hexdump_raw_lines = [
    "00000000: 504b 0304 0a00 0000 0000 c933 b55a 0000  PK... . . . 3.Z.",
    "00000010: 0000 0000 0800 0000 666c 6167 2e74 7874  ......flag.txt",
    "00000020: 0100 2400 0000 0000 0000 0000 0000 0000  ..$.............",
    "00000030: 0000 0000 0400 0000 0000 0000 0000 0000  ................",
    "00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................",
    "00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................",
    "00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................",
    "00000070: 504b 0102 1403 0a00 0000 0000 c933 b55a  PK... . . . 3.Z",
    "00000080: 0000 0000 0000 0000 0800 0000 666c 6167  ..........flag",
    "00000090: 2e74 7874 0000 0000 0000 0000 0000 0000  .txt............",
    "000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................",
    "000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................",
    "000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................",
    "000000d0: 504b 0506 0000 0000 0100 0100 6500 0000  PK......e...",
    "000000e0: 7400 0000 0000 0000 0000 0000 0000 0000  t...............",
]

cleaned_hex_parts = []
# Regex to find sequences of 2 hexadecimal characters (a byte)
hex_byte_pattern = re.compile(r'[0-9a-fA-F]{2}')

for line in hexdump_raw_lines:
    # Find all sequences of 2 hex characters in the line
    # This automatically ignores offsets, spaces, and ASCII representations
    hex_bytes_in_line = hex_byte_pattern.findall(line)
    cleaned_hex_parts.extend(hex_bytes_in_line)

# Join the extracted hex bytes into a single string
full_hex_string = "".join(cleaned_hex_parts)

# Convert hex string to bytes
try:
    zip_bytes = binascii.unhexlify(full_hex_string)
    with open("flag.zip","wb") as fileHandle: fileHandle.write(zip_bytes)
    print(f"Successfully converted {len(full_hex_string) // 2} hex bytes to binary.")
except binascii.Error as e:
    print(f"Error converting hex to bytes: {e}")
    print("Please double-check the hexdump for any non-hex characters or odd lengths.")
    exit()

exit(1)
# The known password for the zip file
zip_password = b"password" # Passwords for zipfile module should be bytes

# Use BytesIO to treat the bytes as a file
zip_file_object = io.BytesIO(zip_bytes)

# Attempt to open and extract the zip file with the password
try:
    # Create the ZipFile object first
    with zipfile.ZipFile(zip_file_object, 'r') as zf:
        # Set the password for the zip file object
        zf.setpassword(zip_password)

        print("Successfully opened the zip file object.")
        print("Files in the zip archive:")
        for name in zf.namelist():
            print(f"- {name}")
            try:
                # When opening individual members, the password set by setpassword() will be used
                with zf.open(name) as extracted_file:
                    content = extracted_file.read()
                    print(f"  Content of {name}:\n{content.decode(errors='ignore')}\n")
            except RuntimeError as e:
                # This error occurs if the password is incorrect for an encrypted file
                print(f"  Error extracting '{name}': {e}")
                print("  This might indicate an incorrect password, or that the file within the ZIP is not encrypted/corrupted.")
            except Exception as e:
                print(f"  An unexpected error occurred while extracting '{name}': {e}")
except zipfile.BadZipFile as e:
    print(f"Error opening zip file: {e}")
    print("The reconstructed data might be corrupted, incomplete, or not a valid ZIP file (bad magic number).")
    print("Ensure all parts of the ZIP structure (Local Header, Central Directory, End of Central Directory) are present.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")