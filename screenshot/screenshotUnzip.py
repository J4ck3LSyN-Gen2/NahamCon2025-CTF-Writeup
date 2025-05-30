import zipfile
import os

zip_file_to_extract = "flag.zip"
# The password must be a bytes object for the zipfile module.
extraction_password = b"password"
extraction_directory = "extracted_flag_content"

# Ensure the zip file exists before attempting to extract
if not os.path.exists(zip_file_to_extract):
    print(f"Error: '{zip_file_to_extract}' not found. Please run the reconstruction step first.")
else:
    # Create an extraction directory if it doesn't exist
    if not os.path.exists(extraction_directory):
        os.makedirs(extraction_directory)
        print(f"Created directory: '{extraction_directory}' for extraction.")

    try:
        # Open the ZIP file in read mode ('r')
        with zipfile.ZipFile(zip_file_to_extract, 'r') as zf:
            print(f"Attempting to extract '{zip_file_to_extract}' to '{extraction_directory}'...")

            # Check if any members are encrypted (optional, but good practice for CTFs)
            encrypted_members_found = False
            for member in zf.infolist():
                # Bit 0 (0x1) of the flag_bits indicates encryption
                if member.flag_bits & 0x1:
                    encrypted_members_found = True
                    break

            if encrypted_members_found:
                print(f"Encrypted members detected. Using password: '{extraction_password.decode()}'")
                # extractall() extracts all members; pwd argument for password
                zf.extractall(path=extraction_directory, pwd=extraction_password)
                print("Files extracted successfully with password!")
            else:
                print("No encrypted members found. Extracting without password.")
                zf.extractall(path=extraction_directory)
                print("Files extracted successfully!")

        # After successful extraction, list the contents of the extraction directory
        print(f"\n--- Contents of '{extraction_directory}' ---")
        for root, dirs, files in os.walk(extraction_directory):
            for file in files:
                # Assuming the flag is in a file named 'flag.txt' or similar
                print(os.path.join(root, file))
        print("---------------------------------------")

    except zipfile.BadZipFile:
        print(f"Error: '{zip_file_to_extract}' is not a valid ZIP file. This could indicate an issue with the hex-to-binary conversion.")
    except RuntimeError as e:
        if "Bad password" in str(e) or "Password required but no password supplied" in str(e):
            print(f"Error: Incorrect or missing password for '{zip_file_to_extract}'. Please verify the password ('{extraction_password.decode()}').")
        else:
            print(f"An unexpected runtime error occurred during extraction: {e}")
    except Exception as e:
        print(f"An general error occurred: {e}")