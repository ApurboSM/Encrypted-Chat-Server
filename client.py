import socket
import threading
import sys
import base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

PORT = 5174
DEVICE_NAME = socket.gethostname()
SERVER_IP = socket.gethostbyname(DEVICE_NAME)
SOCKET_ADDR = (SERVER_IP, PORT)
EXCHANGE_FORMAT = "utf-8"
BUFFER_SIZE = 4096

# Global variables
running = True
aes_key = None

def encrypt_message(message, aes_key):
    """Encrypt message using AES-256"""
    try:
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(message.encode(EXCHANGE_FORMAT), AES.block_size))
        return base64.b64encode(iv + encrypted).decode(EXCHANGE_FORMAT)
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return None

def decrypt_message(encrypted_data, aes_key):
    """Decrypt message using AES-256"""
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode(EXCHANGE_FORMAT)
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return None

def perform_handshake(client_socket):
    """
    Perform SSL-like handshake with server:
    1. Receive server's RSA public key
    2. Generate AES-256 key
    3. Encrypt AES key with server's public key
    4. Send encrypted AES key to server
    5. Receive encrypted confirmation
    """
    try:
        print("\n" + "="*70)
        print("INITIATING SECURE HANDSHAKE".center(70))
        print("="*70)
        
        # Step 1: Receive server's RSA public key
        print("[1/5] Receiving server's RSA public key...")
        key_length = int(client_socket.recv(10).decode())
        public_key_pem = client_socket.recv(key_length)
        server_public_key = RSA.import_key(public_key_pem)
        print(f"      ✓ Received RSA-2048 public key ({key_length} bytes)")
        
        # Step 2: Generate AES-256 key (32 bytes for AES-256)
        print("[2/5] Generating AES-256 symmetric key...")
        aes_key = get_random_bytes(32)
        print(f"      ✓ Generated AES-256 key: {base64.b64encode(aes_key).decode()[:32]}...")
        
        # Step 3: Encrypt AES key with server's public RSA key
        print("[3/5] Encrypting AES key with server's RSA public key...")
        rsa_cipher = PKCS1_OAEP.new(server_public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        print(f"      ✓ Encrypted AES key ({len(encrypted_aes_key)} bytes)")
        
        # Step 4: Send encrypted AES key to server
        print("[4/5] Sending encrypted AES key to server...")
        client_socket.send(f"{len(encrypted_aes_key)}".zfill(10).encode())
        client_socket.send(encrypted_aes_key)
        print(f"      ✓ Sent encrypted key")
        
        # Step 5: Receive and verify encrypted confirmation
        print("[5/5] Receiving encrypted confirmation from server...")
        conf_length = int(client_socket.recv(10).decode())
        encrypted_confirmation = client_socket.recv(conf_length).decode(EXCHANGE_FORMAT)
        confirmation = decrypt_message(encrypted_confirmation, aes_key)
        
        if confirmation == "HANDSHAKE_OK":
            print(f"      ✓ Handshake confirmed: {confirmation}")
            print("\n" + "="*70)
            print("✓ SECURE CHANNEL ESTABLISHED".center(70))
            print("All communication will be encrypted with AES-256".center(70))
            print("="*70 + "\n")
            return aes_key
        else:
            print(f"      ✗ Handshake failed: Invalid confirmation")
            return None
            
    except Exception as e:
        print(f"\n[ERROR] Handshake failed: {e}")
        return None

def receive_messages(client_socket, aes_key):
    """Continuously receive and decrypt messages from server"""
    global running
    while running:
        try:
            msg_len = client_socket.recv(10).decode()
            if not msg_len:
                print("\n[SYSTEM] Server closed connection")
                running = False
                break
            
            encrypted_msg = client_socket.recv(int(msg_len)).decode(EXCHANGE_FORMAT)
            message = decrypt_message(encrypted_msg, aes_key)
            
            if message:
                if message.startswith("ERROR:"):
                    print(f"\n{message}")
                    running = False
                    break
                else:
                    print(f"\n{message}")
                    print("You: ", end="", flush=True)
            else:
                print("\n[ERROR] Failed to decrypt message")
                
        except Exception as e:
            if running:
                print(f"\n[ERROR] Connection error: {e}")
            running = False
            break

def send_messages(client_socket, username, aes_key):
    """Handle sending encrypted messages to server"""
    global running
    
    print("\nCommands:")
    print("  /pm <username> <message>  - Send encrypted private message")
    print("  /list                     - Show online users")
    print("  /quit                     - Leave chat")
    print("\nAll messages are encrypted end-to-end with AES-256")
    print("="*70 + "\n")
    
    while running:
        try:
            print("You: ", end="", flush=True)
            message = input()
            
            if not running:
                break
            
            if message.strip():
                # Encrypt and send message
                encrypted = encrypt_message(message.strip(), aes_key)
                if encrypted:
                    client_socket.send(f"{len(encrypted)}".zfill(10).encode())
                    client_socket.send(encrypted.encode(EXCHANGE_FORMAT))
                    
                    if message.strip() == '/quit':
                        print("\n[SYSTEM] Disconnecting from secure channel...")
                        running = False
                        break
                else:
                    print("[ERROR] Failed to encrypt message")
                    
        except (EOFError, KeyboardInterrupt):
            print("\n\n[SYSTEM] Disconnecting...")
            running = False
            break
        except Exception as e:
            if running:
                print(f"\n[ERROR] Failed to send: {e}")
            break

def main():
    """Main client function"""
    global running, aes_key
    
    print("="*70)
    print("ENCRYPTED CHAT CLIENT (SSL-LIKE HANDSHAKE)".center(70))
    print("="*70)
    print(f"Server: {SERVER_IP}:{PORT}")
    print(f"Security: RSA-2048 + AES-256 encryption")
    print("="*70 + "\n")
    
    # Get username
    username = input("Enter your username: ").strip()
    
    if not username:
        print("[ERROR] Username cannot be empty!")
        return
    
    if ' ' in username:
        print("[ERROR] Username cannot contain spaces!")
        return
    
    try:
        # Connect to server
        print(f"\nConnecting to server at {SERVER_IP}:{PORT}...")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(SOCKET_ADDR)
        print("✓ TCP connection established")
        
        # Perform secure handshake
        aes_key = perform_handshake(client)
        
        if not aes_key:
            print("[ERROR] Secure handshake failed!")
            client.close()
            return
        
        # Send encrypted username
        encrypted_username = encrypt_message(username, aes_key)
        client.send(f"{len(encrypted_username)}".zfill(10).encode())
        client.send(encrypted_username.encode(EXCHANGE_FORMAT))
        
        # Start receiving thread
        receive_thread = threading.Thread(target=receive_messages, args=(client, aes_key))
        receive_thread.daemon = True
        receive_thread.start()
        
        # Small delay for welcome message
        import time
        time.sleep(0.5)
        
        # Handle sending messages
        send_messages(client, username, aes_key)
        
        # Cleanup
        running = False
        client.close()
        print("\n[SYSTEM] Secure connection closed. Goodbye!\n")
        
    except ConnectionRefusedError:
        print(f"\n[ERROR] Could not connect to server at {SERVER_IP}:{PORT}")
        print("Make sure the server is running!")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
    finally:
        running = False

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[SYSTEM] Client terminated. Goodbye!")
        sys.exit(0)
