import zipfile
import os
import shutil # Used for optional cleanup of the output directory
import subprocess # For running binwalk commands
from collections import deque # For managing the queue of files to process

class RecursiveBinwalkExtractor:
    """
    A class to recursively extract embedded files from archives using binwalk.
    It will process files until no further extractions are possible.
    """

    def __init__(self, initial_file, output_base_directory='recursive_binwalk_output'):
        """
        Initializes the extractor with the starting file and output directory.

        Args:
            initial_file (str): The path to the initial file to start extraction from.
            output_base_directory (str): The base directory where all extracted
                                         content will be organized.
        """
        self.initial_file = initial_file
        self.output_base_directory = output_base_directory
        # Use a set to keep track of files that have already been processed by binwalk
        # to prevent infinite loops or redundant processing.
        self.processed_files = set()
        # Use a deque (double-ended queue) for efficient adding and popping of files
        # that need to be processed. Each item is (file_path, parent_output_dir, level).
        self.extraction_queue = deque()
        self.total_extractions = 0 # Counter for successful binwalk extractions

        # Prepare the base output directory for a clean run.
        if os.path.exists(self.output_base_directory):
            print(f"Warning: Output directory '{self.output_base_directory}' already exists.")
            print("It will be cleared before starting a new extraction.")
            # Remove the existing directory and its contents
            shutil.rmtree(self.output_base_directory)
        # Create a fresh, empty directory for all extracted content
        os.makedirs(self.output_base_directory)
        print(f"Extraction output will be saved in: {self.output_base_directory}")

    def _run_binwalk_extract(self, file_path, current_output_dir):
        """
        Executes 'binwalk -e' on a given file.

        Args:
            file_path (str): The path to the file to be extracted.
            current_output_dir (str): The directory where binwalk should perform
                                      its extraction (binwalk will create its
                                      '_<filename>.extracted' directory inside this).

        Returns:
            str or None: The full path to the newly created extracted directory
                         if extraction was successful, otherwise None.
        """
        print(f"Attempting binwalk -e on: {file_path}")
        
        original_cwd = os.getcwd() # Store original working directory
        
        # Create a temporary directory to run binwalk from, ensuring its output
        # is contained within our desired structure.
        temp_binwalk_run_dir = os.path.join(current_output_dir, f"binwalk_temp_{os.path.basename(file_path).replace('.', '_')}")
        os.makedirs(temp_binwalk_run_dir, exist_ok=True)

        # Copy the file to be extracted into the temporary directory
        shutil.copy(file_path, temp_binwalk_run_dir)
        copied_file_name = os.path.basename(file_path)
        
        try:
            # Change to the temporary directory to execute binwalk
            os.chdir(temp_binwalk_run_dir)
            
            # Execute binwalk -e. Using subprocess.run for better control over output
            # and error handling compared to os.system.
            result = subprocess.run(
                ['binwalk', '-e', copied_file_name],
                capture_output=True, # Capture stdout and stderr
                text=True,           # Decode output as text
                check=False          # Do not raise an exception for non-zero exit codes;
                                     # we'll check returncode manually.
            )
            
            # Check if binwalk exited with an error
            if result.returncode != 0:
                print(f"  Binwalk extraction failed for {copied_file_name}:")
                print(f"    Stdout: {result.stdout.strip()}")
                print(f"    Stderr: {result.stderr.strip()}")
                return None

            # Binwalk typically creates a directory named `_<original_filename>.extracted`
            # in the directory where it was run.
            extracted_dir_name = f"_{copied_file_name}.extracted"
            extracted_full_path_in_temp = os.path.join(temp_binwalk_run_dir, extracted_dir_name)

            # Verify if the extracted directory was actually created
            if os.path.isdir(extracted_full_path_in_temp):
                print(f"Successfully extracted {copied_file_name} to: {extracted_full_path_in_temp}")
                self.total_extractions += 1
                return extracted_full_path_in_temp
            else:
                print(f"  Binwalk ran, but no '{extracted_dir_name}' directory found for {copied_file_name}.")
                print(f"  Binwalk stdout: {result.stdout.strip()}")
                print(f"  Binwalk stderr: {result.stderr.strip()}")
                return None
        except FileNotFoundError:
            print("Error: 'binwalk' command not found. Please ensure Binwalk is installed and in your system's PATH.")
            return None
        except Exception as e:
            print(f"An unexpected error occurred during binwalk execution for {copied_file_name}: {e}")
            return None
        finally:
            # Always change back to the original working directory
            os.chdir(original_cwd)

    def run(self):
        """
        Starts the recursive binwalk extraction process.
        It processes files in a queue, extracting them and adding any newly
        found potential archives to the queue for further processing.
        The process continues until the queue is empty, meaning no more
        extractable files were found.
        """
        print("\n--- Starting Recursive Binwalk Extraction ---")
        
        # Ensure the initial file exists before starting
        if not os.path.exists(self.initial_file):
            print(f"Error: Initial file '{self.initial_file}' not found at '{os.path.abspath(self.initial_file)}'.")
            return

        # Add the initial file to the queue for processing.
        # We store (file_path, parent_output_directory, current_level)
        self.extraction_queue.append((self.initial_file, self.output_base_directory, 0))

        while self.extraction_queue:
            # Get the next file to process from the front of the queue
            current_file_path, parent_output_dir, level = self.extraction_queue.popleft()
            
            # Create a dedicated output directory for this specific extraction level.
            # This helps organize the deeply nested extracted content.
            level_output_dir = os.path.join(parent_output_dir, f"level_{level}_extracted_from_{os.path.basename(current_file_path).replace('.', '_')}")
            os.makedirs(level_output_dir, exist_ok=True)

            # Skip if this file has already been processed to prevent redundant work or loops
            if current_file_path in self.processed_files:
                print(f"Skipping already processed file: {current_file_path}")
                continue

            # Mark the current file as processed
            self.processed_files.add(current_file_path)
            
            # Attempt to extract the current file using binwalk
            extracted_path = self._run_binwalk_extract(current_file_path, level_output_dir)

            if extracted_path:
                # If binwalk successfully extracted content, traverse the newly created directory
                print(f"Exploring new extraction at level {level}: {extracted_path}")
                # os.walk iterates through directories and files within a given path
                for root, dirs, files in os.walk(extracted_path):
                    for file_name in files:
                        potential_nested_file_path = os.path.join(root, file_name)
                        
                        # Add any newly found file (that hasn't been processed yet)
                        # to the queue for further binwalk extraction.
                        # This is an aggressive approach, assuming any file might contain
                        # further embedded data. For more specific scenarios, you might
                        # add heuristics (e.g., check file headers/extensions).
                        if potential_nested_file_path not in self.processed_files:
                            self.extraction_queue.append((potential_nested_file_path, level_output_dir, level + 1))
                            print(f"  Added potential nested file to queue: {potential_nested_file_path}")
                    # Note: os.walk automatically traverses into subdirectories (`dirs`),
                    # so we don't need to explicitly add directories to the queue.
                    # We only care about the *files* within them.

        print("\n--- Recursive Binwalk Extraction Finished ---")
        print(f"Total successful binwalk extractions: {self.total_extractions}")
        print(f"All extracted content is organized within the '{self.output_base_directory}' directory.")
        print("The process terminated because no more new extractable files were found in the queue.")
        print("\nNow, manually explore the output directory for the flag.")
        print(f"You can use `ls -R {self.output_base_directory}` (on Linux/macOS) or your file explorer")
        print("     to see the complete directory structure and contents.")
        print("Common next steps: Use `grep -r 'flag{'` or `strings` on suspicious files in the output directory.")

if __name__ == "__main__":
    # --- Configuration ---
    # The initial file to start the recursive extraction from.
    # Based on our previous conversation, this is likely 'combined_quartet.zip'.
    # If your initial file is named '5B.zlib' as in your example, please change this.
    initial_file_to_extract = '5B.zlib'
    
    # The base directory where all extracted content will be placed.
    output_directory = 'recursive_binwalk_output'

    # Create an instance of the extractor and run it.
    extractor = RecursiveBinwalkExtractor(initial_file_to_extract, output_directory)
    extractor.run()