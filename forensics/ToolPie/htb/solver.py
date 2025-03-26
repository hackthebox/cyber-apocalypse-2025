from scapy.all import rdpcap, TCP, IP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import argparse
import os

# Configure values
ATTACKER_IP = "13.61.7.218"  # Must match the attacker's C2 IP
SEPARATOR = "<SEPARATOR>"  # Must match the malware separator
BUFFER_SIZE = 4096  # Standard buffer size

def extract_aes_key(packets):
    """Extracts the AES key from the initial beacon to the attacker's server."""
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[IP].dst == ATTACKER_IP and packet[TCP].payload:
                payload = bytes(packet[TCP].payload).decode(errors="ignore")
                if SEPARATOR in payload:
                    _, extracted_key = payload.split(SEPARATOR, 1)
                    if len(extracted_key) == 16:
                        print(f"[+] Found AES Key: {extracted_key}")
                        return extracted_key
    return None


def decrypt_message(ciphertext, key):
    """Decrypt AES CBC encrypted messages with padding handling."""
    try:
        cipher = AES.new(key.encode(), AES.MODE_CBC, key.encode())
        return unpad(cipher.decrypt(ciphertext), 16)
    except ValueError:
        return b""  # Ignore padding errors on partial packets
    except Exception as e:
        return f"Decryption failed: {str(e)}".encode()


def process_pcap(pcap_file):
    """Processes the PCAP file, extracts AES key, decrypts messages, and reconstructs exfiltrated files."""
    packets = rdpcap(pcap_file)

    # Extract AES key
    extracted_key = extract_aes_key(packets)
    if not extracted_key:
        print("[-] No AES key found in PCAP. Decryption may not work.")
        return

    decrypted_messages = []
    file_data = b""  # Store file content
    filename = None
    file_size = 0
    collecting_file = False  # Flag to indicate file collection
    get_file_issued = False  # Flag to track if a `get_file` command was issued

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[IP].src == ATTACKER_IP or packet[IP].dst == ATTACKER_IP:
                if packet[TCP].payload:
                    encrypted_payload = bytes(packet[TCP].payload)
                    decrypted_text = decrypt_message(encrypted_payload, extracted_key)

                    try:
                        text = decrypted_text.decode(errors="ignore").strip()

                        # Detect command executions
                        if text:
                            decrypted_messages.append((packet.time, text))
                            print(f"[{packet.time}] {text}")

                        # Detect the `get_file` command
                        if text == "get_file":
                            get_file_issued = True
                            continue

                        # After `get_file` command, expect filename
                        if get_file_issued and "\\" in text:
                            filename = os.path.basename(text)
                            print(f"[+] File transfer detected: {filename}")
                            continue

                        # After filename, expect file size
                        if get_file_issued and text.isdigit():
                            file_size = int(text)
                            print(f"[+] File size: {file_size} bytes")
                            collecting_file = True
                            file_data = b""  # Reset file buffer
                            get_file_issued = False  # Reset flag
                            continue

                    except UnicodeDecodeError:
                        pass  # It's likely binary file data, not a message

                    # If collecting a file, store encrypted chunks
                    if collecting_file and packet[IP].dst == ATTACKER_IP:
                        
                        file_data += encrypted_payload
                        print(f'[+] collecting file data: {len(file_data)}/{file_size}')

                        # Stop collecting when full file size is reached
                        if len(file_data) >= file_size:
                            break

    # Decrypt and save the reconstructed file
    if filename and file_data and len(file_data) >= file_size:
        decrypted_file_data = decrypt_message(file_data[:file_size], extracted_key)  # Decrypt all at once
        save_path = os.path.join(os.getcwd(), f"recovered_{filename}")
        with open(save_path, "wb") as f:
            f.write(decrypted_file_data)
        print(f"[+] Exfiltrated file successfully recovered: {save_path}")
    else:
        print("[-] File transfer was incomplete or missing in PCAP.")

    # Display decrypted messages
    print("\n--- Decrypted Commands & Responses ---")
    for timestamp, message in decrypted_messages[:-1]:
        print(f"[{timestamp}] {message}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt AES-encrypted traffic from a PCAP file and reconstruct exfiltrated files.")
    parser.add_argument("pcap", help="Path to the PCAP file.")
    args = parser.parse_args()

    process_pcap(args.pcap)
