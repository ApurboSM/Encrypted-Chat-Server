import socket
import threading
import os
import base64
import hashlib
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

# Dictionary to store connected clients: {username: (conn, addr, aes_key)}
clients = {}
clients_lock = threading.Lock()

# Generate RSA key pair for server (2048-bit)
print("Generating RSA key pair for server...")
server_rsa_key = RSA.generate(2048)
server_public_key = server_rsa_key.publickey()
print("✓ RSA keys generated")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(SOCKET_ADDR)
server.listen()
print(f"\n{'='*70}")
print(f"{'ENCRYPTED CHAT SERVER (SSL-LIKE HANDSHAKE)':^70}")
print(f"{'='*70}")
print(f"Server IP: {SERVER_IP}")
print(f"Port: {PORT}")
print(f"Encryption: AES-256 + RSA-2048")
print(f"Status: Listening for secure connections...")
print(f"{'='*70}\n")

def get_timestamp():
    """Get current timestamp"""
    return datetime.now().strftime("%H:%M:%S")

def encrypt_message(message, aes_key):
    """Encrypt message using AES-256"""
    try:
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(message.encode(EXCHANGE_FORMAT), AES.block_size))
        # Return IV + encrypted message, base64 encoded
        return base64.b64encode(iv + encrypted).decode(EXCHANGE_FORMAT)
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")
        return None

def decrypt_message(encrypted_data, aes_key):
    """Decrypt message using AES-256"""
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        iv = encrypted_bytes[:16]  # First 16 bytes are IV
        ciphertext = encrypted_bytes[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode(EXCHANGE_FORMAT)
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return None

def perform_handshake(conn, addr):
    """
    Perform SSL-like handshake with client:
    1. Send server's RSA public key
    2. Receive client's encrypted AES key
    3. Decrypt AES key with server's RSA private key
    4. Send encrypted confirmation
    """
    try:
        timestamp = get_timestamp()
        print(f"[{timestamp}] [HANDSHAKE] Starting with {addr}")
        
        # Step 1: Send server's public RSA key to client
        public_key_pem = server_public_key.export_key()
        conn.send(f"{len(public_key_pem)}".zfill(10).encode())
        conn.send(public_key_pem)
        print(f"[{timestamp}] [HANDSHAKE] Sent RSA public key ({len(public_key_pem)} bytes)")
        
        # Step 2: Receive encrypted AES key from client
        key_length = int(conn.recv(10).decode())
        encrypted_aes_key = conn.recv(key_length)
        print(f"[{timestamp}] [HANDSHAKE] Received encrypted AES key ({key_length} bytes)")
        
        # Step 3: Decrypt AES key using server's private RSA key
        rsa_cipher = PKCS1_OAEP.new(server_rsa_key)
        aes_key = rsa_cipher.decrypt(encrypted_aes_key)
        print(f"[{timestamp}] [HANDSHAKE] Decrypted AES-256 key: {base64.b64encode(aes_key).decode()[:32]}...")
        
        # Step 4: Send encrypted confirmation (encrypt "HANDSHAKE_OK" with AES key)
        confirmation = encrypt_message("HANDSHAKE_OK", aes_key)
        conn.send(f"{len(confirmation)}".zfill(10).encode())
        conn.send(confirmation.encode(EXCHANGE_FORMAT))
        print(f"[{timestamp}] [HANDSHAKE] Sent encrypted confirmation")
        
        # Step 5: Receive username (encrypted)
        username_len = int(conn.recv(10).decode())
        encrypted_username = conn.recv(username_len).decode(EXCHANGE_FORMAT)
        username = decrypt_message(encrypted_username, aes_key)
        
        if not username:
            print(f"[{timestamp}] [HANDSHAKE] Failed to decrypt username")
            return None, None
        
        print(f"[{timestamp}] [HANDSHAKE] ✓ Secure channel established with user: {username}")
        print(f"[{timestamp}] [HANDSHAKE] All messages will be encrypted with AES-256\n")
        
        return aes_key, username
        
    except Exception as e:
        print(f"[ERROR] Handshake failed with {addr}: {e}")
        return None, None

def broadcast_encrypted_message(message, sender_username=None, exclude_username=None):
    """Broadcast encrypted message to all clients"""
    with clients_lock:
        disconnected_clients = []
        for username, (conn, addr, aes_key) in clients.items():
            if username == exclude_username:
                continue
            
            try:
                encrypted = encrypt_message(message, aes_key)
                if encrypted:
                    conn.send(f"{len(encrypted)}".zfill(10).encode())
                    conn.send(encrypted.encode(EXCHANGE_FORMAT))
            except Exception as e:
                print(f"[ERROR] Failed to send to {username}: {e}")
                disconnected_clients.append(username)
        
        # Remove disconnected clients
        for username in disconnected_clients:
            remove_client(username)

def send_encrypted_private_message(sender_username, recipient_username, message):
    """Send encrypted private message"""
    with clients_lock:
        if recipient_username in clients:
            try:
                # Send to recipient
                recipient_conn, _, recipient_key = clients[recipient_username]
                timestamp = get_timestamp()
                pm_msg = f"[{timestamp}] [PM from {sender_username}] {message}"
                encrypted = encrypt_message(pm_msg, recipient_key)
                if encrypted:
                    recipient_conn.send(f"{len(encrypted)}".zfill(10).encode())
                    recipient_conn.send(encrypted.encode(EXCHANGE_FORMAT))
                
                # Send confirmation to sender
                sender_conn, _, sender_key = clients[sender_username]
                confirm_msg = f"[{timestamp}] [PM to {recipient_username}] {message}"
                encrypted_confirm = encrypt_message(confirm_msg, sender_key)
                if encrypted_confirm:
                    sender_conn.send(f"{len(encrypted_confirm)}".zfill(10).encode())
                    sender_conn.send(encrypted_confirm.encode(EXCHANGE_FORMAT))
                
                print(f"[{timestamp}] [PM ENCRYPTED] {sender_username} -> {recipient_username}")
                return True
            except Exception as e:
                print(f"[ERROR] Failed to send encrypted PM: {e}")
                return False
        else:
            return False

def send_encrypted_message(conn, message, aes_key):
    """Send single encrypted message to specific client"""
    try:
        encrypted = encrypt_message(message, aes_key)
        if encrypted:
            conn.send(f"{len(encrypted)}".zfill(10).encode())
            conn.send(encrypted.encode(EXCHANGE_FORMAT))
            return True
        return False
    except Exception as e:
        print(f"[ERROR] Failed to send encrypted message: {e}")
        return False

def remove_client(username):
    """Remove client from dictionary (must be called with lock)"""
    if username in clients:
        try:
            conn, addr, _ = clients[username]
            conn.close()
        except:
            pass
        del clients[username]

def handle_client(conn, addr):
    """Handle encrypted client connection"""
    username = None
    aes_key = None
    
    try:
        # Perform SSL-like handshake
        aes_key, username = perform_handshake(conn, addr)
        
        if not aes_key or not username:
            print(f"[{addr}] Handshake failed, closing connection")
            conn.close()
            return
        
        # Check if username already exists
        with clients_lock:
            if username in clients:
                error_msg = "ERROR: Username already taken"
                send_encrypted_message(conn, error_msg, aes_key)
                conn.close()
                print(f"[{addr}] Username '{username}' already taken")
                return
            
            # Add client to dictionary with AES key
            clients[username] = (conn, addr, aes_key)
        
        # Send encrypted welcome message
        timestamp = get_timestamp()
        welcome_msg = f"\n{'='*50}\n✓ Secure connection established!\nWelcome {username}!\nAll messages are encrypted with AES-256\n{'='*50}"
        send_encrypted_message(conn, welcome_msg, aes_key)
        
        # Broadcast join notification (encrypted)
        print(f"[{timestamp}] [JOIN] {username} joined from {addr}")
        join_notification = f"[{timestamp}] [SYSTEM] {username} joined (secure channel)"
        broadcast_encrypted_message(join_notification, exclude_username=username)
        
        # Main message loop
        while True:
            try:
                # Receive encrypted message
                msg_len = conn.recv(10).decode()
                if not msg_len:
                    break
                
                encrypted_msg = conn.recv(int(msg_len)).decode(EXCHANGE_FORMAT)
                message = decrypt_message(encrypted_msg, aes_key)
                
                if not message:
                    print(f"[{timestamp}] [ERROR] Failed to decrypt message from {username}")
                    continue
                
                message = message.strip()
                timestamp = get_timestamp()
                
                # Handle commands
                if message.startswith('/pm '):
                    parts = message.split(' ', 2)
                    if len(parts) >= 3:
                        recipient = parts[1]
                        pm_content = parts[2]
                        success = send_encrypted_private_message(username, recipient, pm_content)
                        if not success:
                            error_msg = f"[{timestamp}] [ERROR] User '{recipient}' not found"
                            send_encrypted_message(conn, error_msg, aes_key)
                    else:
                        error_msg = f"[{timestamp}] [ERROR] Usage: /pm <username> <message>"
                        send_encrypted_message(conn, error_msg, aes_key)
                
                elif message == '/list':
                    with clients_lock:
                        user_list = ", ".join(clients.keys())
                        list_msg = f"\n{'='*50}\nOnline Users ({len(clients)}): {user_list}\n{'='*50}"
                        send_encrypted_message(conn, list_msg, aes_key)
                
                elif message == '/quit':
                    break
                
                else:
                    # Broadcast message (encrypted to all)
                    broadcast_msg = f"[{timestamp}] {username}: {message}"
                    print(f"[{timestamp}] [ENCRYPTED BROADCAST] {username}: {message}")
                    broadcast_encrypted_message(broadcast_msg, sender_username=username)
                    
            except Exception as e:
                print(f"[ERROR] Error in message loop for {username}: {e}")
                break
    
    except Exception as e:
        print(f"[ERROR] Error handling client {addr}: {e}")
    
    finally:
        # Cleanup
        if username:
            with clients_lock:
                remove_client(username)
            
            timestamp = get_timestamp()
            print(f"[{timestamp}] [LEAVE] {username} disconnected")
            leave_msg = f"[{timestamp}] [SYSTEM] {username} left the chat"
            broadcast_encrypted_message(leave_msg)

def main():
    """Main server loop"""
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
            
            with clients_lock:
                active = len(clients)
            print(f"[INFO] New connection from {addr} (Active: {active})")
    
    except KeyboardInterrupt:
        print("\n\n[SERVER] Shutting down...")
        with clients_lock:
            for username, (conn, addr, aes_key) in list(clients.items()):
                try:
                    send_encrypted_message(conn, "[SYSTEM] Server shutting down", aes_key)
                    conn.close()
                except:
                    pass
        server.close()
        print("[SERVER] Server closed")
    
    except Exception as e:
        print(f"[ERROR] Server error: {e}")
        server.close()

if __name__ == "__main__":
    main()
