import os

def find_and_note_differences(file_paths):
    """
    Reads multiple files, compares them byte by byte, and notes all differences.

    Args:
        file_paths (list): A list of strings, where each string is the path to a file.
                           Expected format: ['quartet_1.jpg', 'quartet_2.jpg', ...]

    Returns:
        list: A list of dictionaries, where each dictionary represents a differing
              offset and contains the 'offset' and a list of 'bytes' (integers)
              from each file at that specific offset.
              Returns an empty list if no differences are found, or if files
              cannot be read.
    """
    file_contents = []
    # Initialize min_length to a very large number to ensure the first file's
    # length correctly sets the initial minimum.
    min_length = float('inf')

    print("Attempting to read files...")
    # Read all files and store their contents as byte arrays.
    # We use 'rb' mode for reading binary files.
    for path in file_paths:
        try:
            with open(path, 'rb') as f:
                content = f.read()
                file_contents.append(content)
                # Update min_length to the smallest file size encountered so far.
                min_length = min(min_length, len(content))
            print(f"Successfully read {path} (length: {len(content)} bytes).")
        except FileNotFoundError:
            print(f"Error: File not found at '{path}'. Please ensure the file exists.")
            return [] # Return empty list if a file is missing, as comparison won't be complete.
        except Exception as e:
            print(f"Error reading file '{path}': {e}")
            return [] # Return empty list on any other read error.

    # Check if any files were successfully loaded.
    if not file_contents:
        print("No files were successfully read. Cannot perform comparison.")
        return []

    # Check if all files are empty.
    if min_length == 0:
        print("One or more files are empty. No bytes to compare.")
        return []

    # Inform the user if files have different lengths.
    # Comparison will proceed up to the shortest file's length.
    all_same_length = all(len(content) == len(file_contents[0]) for content in file_contents)
    if not all_same_length:
        print(f"\nWarning: Files have different lengths. Comparing up to the minimum length of {min_length} bytes.")
    else:
        print(f"\nAll files have the same length ({min_length} bytes).")

    differences = []

    print("\nComparing bytes...")
    # Iterate through each byte position up to the minimum length of all files.
    for i in range(min_length):
        # Collect the byte at the current position 'i' from each file.
        current_bytes_at_offset = [content[i] for content in file_contents]
        
        # Check if all bytes at the current position are identical.
        # If not all bytes are the same as the first byte at this position,
        # then we have found a difference.
        if not all(b == current_bytes_at_offset[0] for b in current_bytes_at_offset):
            differences.append({
                'offset': i,
                'bytes': current_bytes_at_offset # Store the list of differing bytes (integers)
            })
    
    return differences

def get_printable_char(byte_value):
    """
    Returns the ASCII character for a byte value if it's printable, otherwise a dot.
    """
    # Check if the byte value corresponds to a printable ASCII character.
    if 32 <= byte_value <= 126: # ASCII printable range
        return chr(byte_value)
    return '.' # Return a dot for non-printable characters

if __name__ == "__main__":
    # Define the paths to your JPG files.
    # Make sure these files are in the same directory as the script,
    # or provide their full paths.
    file_names = [f'quartet_{i}.jpg' for i in range(1, 5)]

    print("Starting file comparison script...")
    # Find the differences between the specified files.
    found_differences = find_and_note_differences(file_names)

    if found_differences:
        print("\n--- Differences Found ---")
        # Iterate through the list of differences and print them in a readable format.
        for diff in found_differences:
            offset = diff['offset']
            bytes_list = diff['bytes']
            
            # Print the offset in hexadecimal format.
            print(f"\nOffset 0x{offset:08X}:") # 08X ensures 8 hex digits, padded with zeros
            
            # Print the byte from each file at the current offset.
            for i, byte_value in enumerate(bytes_list):
                file_name = file_names[i]
                # Print hex value and its printable ASCII representation.
                print(f"  File {file_name}: 0x{byte_value:02X} ('{get_printable_char(byte_value)}')")
        
        print("\n--- Suggestions for 'Compiling' the Flag ---")
        print("Based on common techniques, here are ways you might 'compile' the flag from these differences:")
        print("1.  **Direct Concatenation:** Look for sequences of differing bytes that form readable ASCII characters. The flag might simply be these characters concatenated in order of their offsets.")
        print("2.  **Unique Byte Extraction:** At each differing offset, identify the byte that is unique or an 'outlier' compared to the others. Concatenate these unique bytes.")
        print("3.  **XOR Operation:** If the differences seem random, try XORing the bytes at each differing offset. For example, `byte_file1 ^ byte_file2 ^ byte_file3 ^ byte_file4` or `byte_file1 ^ byte_file2` etc. The result of the XOR might reveal a character of the flag.")
        print("4.  **Pattern Recognition:** Look for patterns in the hexadecimal values or their ASCII representations. Sometimes, flags are hidden in specific byte sequences (e.g., 'flag{...}' or 'CTF{...}').")
        print("5.  **Byte from a Specific File:** The flag might be entirely contained within one of the files, and the other files simply have a 'filler' byte at those positions. Try extracting all differing bytes from just one of the files.")
        print("\nGood luck with your cyber security research!")
    else:
        print("\nNo differences found between the specified files. All files are identical byte for byte up to their minimum length.")

