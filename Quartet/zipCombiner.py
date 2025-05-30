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