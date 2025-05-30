import subprocess
import sys
import os

def run_crackme(input_string):
    try:
        # Assuming crackme-rust-fun.exe is in the same directory
        # IMPORTANT: Remove .encode() when text=True
        process = subprocess.run(
            ['crackme-rust-fun.exe'],
            input=input_string,  # Pass the string directly
            capture_output=True,
            text=True,           # This handles encoding/decoding
            check=True,
            timeout=5            # Optional: Add a timeout to prevent hanging
        )
        if str("not") not in str(process.stdout): 
            print("STDOUT:", process.stdout)
            print("STDERR:", process.stderr)
        return process.stdout, process.stderr
    except subprocess.CalledProcessError as e:
        print(f"Error running crackme (exit code {e.returncode}): {e}")
        print("STDOUT (Error):", e.stdout)
        print("STDERR (Error):", e.stderr)
        return None, None
    except subprocess.TimeoutExpired as e:
        print(f"Crackme process timed out: {e}")
        print("STDOUT (Timeout):", e.stdout)
        print("STDERR (Timeout):", e.stderr)
        # You might want to terminate the process here if it's still running
        e.process.kill()
        return None, None
    except FileNotFoundError:
        print("Error: 'crackme-rust-fun.exe' not found. Make sure it's in the same directory or specified with a full path.")
        return None, None

# Example usage:
# Make sure to include a newline character if the program expects it for input submission

if __name__ == "__main__":
    argV = sys.argv[1:]
    if len(argV) == 0:
        print("Usage: python runCrackMe.py passwordList");exit(1)
    if not os.path.isfile(str(argV[0])):
        print(f"Failed To Find File: {str(argV[0])}");exit(1)
    print("Loading File...")
    fileHandle = open(str(argV[0]),"rb").read().decode("latin-1")
    fileSplit = fileHandle.split("\n")
    print(f"Loaded: {str(len(fileSplit))} Passwords")
    for p in fileSplit: 
        try:
            run_crackme(f"{p}\n")
        except: continue