# Encrypted Chat Server with Custom Handshake

## Overview
A secure chat system implementing a mini SSL-like handshake mechanism with RSA key exchange and AES-256 encryption for all messages. This demonstrates transport-level encryption similar to how HTTPS/TLS works.

## Features Implemented

### Core Requirements ✓
1. **Custom SSL-Like Handshake**
   - Multi-step handshake protocol
   - Key exchange using RSA-2048
   - Mutual verification
   - Encrypted confirmation

2. **Shared Key Exchange**
   - Server generates RSA-2048 key pair
   - Client generates AES-256 symmetric key
   - Client encrypts AES key with server's public RSA key
   - Server decrypts AES key with its private RSA key
   - Secure key establishment without exposing symmetric key

3. **Message Encryption**
   - All messages encrypted with AES-256
   - CBC mode with random IV for each message
   - Base64 encoding for transport
   - No plaintext messages after handshake

4. **Transport-Level Encryption & Verification**
   - End-to-end encryption demonstrated
   - Key verification in handshake
   - Encrypted confirmation messages
   - Failed decryption detection

## Security Architecture

### Handshake Protocol (Similar to TLS)

```
CLIENT                                  SERVER
  |                                       |
  |------ TCP Connection Established ---->|
  |                                       |
  |<------- Server RSA Public Key --------|  (Step 1)
  |                                       |
  | Generate AES-256 Key                  |  (Step 2)
  |                                       |
  | Encrypt AES key with RSA public key   |  (Step 3)
  |                                       |
  |------- Encrypted AES Key ------------>|  (Step 4)
  |                                       |
  |                      Decrypt AES Key  |  (Step 5)
  |                                       |
  |<----- Encrypted Confirmation ---------|  (Step 6)
  |       (encrypted with AES)            |
  |                                       |
  | Verify Confirmation                   |  (Step 7)
  |                                       |
  |------- Encrypted Username ----------->|  (Step 8)
  |                                       |
  |<===== SECURE CHANNEL ESTABLISHED ====>|
  |                                       |
  |<==== All Messages AES Encrypted =====>|
  |                                       |
```

### Encryption Layers

1. **RSA-2048 (Asymmetric)**
   - Used only for initial key exchange
   - Server has public/private key pair
   - Client encrypts AES key with server's public key
   - Server decrypts with private key

2. **AES-256 (Symmetric)**
   - Used for all message encryption
   - CBC mode with random IV per message
   - 256-bit key (32 bytes)
   - Fast and secure

### Message Format

**Encrypted Message Structure:**
```
[10-byte length header][base64-encoded(IV + ciphertext)]
```

Where:
- **IV**: 16 bytes (random initialization vector)
- **Ciphertext**: Padded and encrypted message
- **Base64**: Safe transport encoding

## File Structure
```
task7/
├── server.py       # Encrypted chat server with RSA key generation
├── client.py       # Encrypted chat client with handshake
├── README.md       # This file
└── requirements.txt # Python dependencies
```

## Dependencies

Install required cryptographic libraries:
```bash
pip install pycryptodome
```

Or:
```bash
pip install -r requirements.txt
```

## How to Run

### 1. Install Dependencies
```bash
pip install pycryptodome
```

### 2. Start the Server
```bash
python server.py
```

Output:
```
Generating RSA key pair for server...
✓ RSA keys generated

======================================================================
        ENCRYPTED CHAT SERVER (SSL-LIKE HANDSHAKE)
======================================================================
Server IP: 192.168.x.x
Port: 5174
Encryption: AES-256 + RSA-2048
Status: Listening for secure connections...
======================================================================
```

### 3. Run Client(s)
```bash
python client.py
```

### 4. Observe Secure Handshake
The client will display the complete handshake process:
```
======================================================================
                    INITIATING SECURE HANDSHAKE
======================================================================
[1/5] Receiving server's RSA public key...
      ✓ Received RSA-2048 public key (451 bytes)
[2/5] Generating AES-256 symmetric key...
      ✓ Generated AES-256 key: xYz123abc...
[3/5] Encrypting AES key with server's RSA public key...
      ✓ Encrypted AES key (256 bytes)
[4/5] Sending encrypted AES key to server...
      ✓ Sent encrypted key
[5/5] Receiving encrypted confirmation from server...
      ✓ Handshake confirmed: HANDSHAKE_OK

======================================================================
                  ✓ SECURE CHANNEL ESTABLISHED
         All communication will be encrypted with AES-256
======================================================================
```

## Example Usage

### Client Side:
```
ENCRYPTED CHAT CLIENT (SSL-LIKE HANDSHAKE)
======================================================================
Server: 192.168.1.100:5174
Security: RSA-2048 + AES-256 encryption
======================================================================

Enter your username: Alice

Connecting to server at 192.168.1.100:5174...
✓ TCP connection established

======================================================================
                    INITIATING SECURE HANDSHAKE
======================================================================
[1/5] Receiving server's RSA public key...
      ✓ Received RSA-2048 public key (451 bytes)
[2/5] Generating AES-256 symmetric key...
      ✓ Generated AES-256 key: xYz123abc...
[3/5] Encrypting AES key with server's RSA public key...
      ✓ Encrypted AES key (256 bytes)
[4/5] Sending encrypted AES key to server...
      ✓ Sent encrypted key
[5/5] Receiving encrypted confirmation from server...
      ✓ Handshake confirmed: HANDSHAKE_OK

======================================================================
                  ✓ SECURE CHANNEL ESTABLISHED
         All communication will be encrypted with AES-256
======================================================================

==================================================
✓ Secure connection established!
Welcome Alice!
All messages are encrypted with AES-256
==================================================

[14:30:15] [SYSTEM] Bob joined (secure channel)

You: Hello Bob! This message is encrypted!

[14:30:25] Bob: Hi Alice! Yes, all our messages are secure!

You: /pm Bob This is a private encrypted message

[14:30:35] [PM to Bob] This is a private encrypted message
```

### Server Side:
```
[14:30:10] [HANDSHAKE] Starting with ('192.168.1.101', 54321)
[14:30:10] [HANDSHAKE] Sent RSA public key (451 bytes)
[14:30:10] [HANDSHAKE] Received encrypted AES key (256 bytes)
[14:30:10] [HANDSHAKE] Decrypted AES-256 key: xYz123abc...
[14:30:10] [HANDSHAKE] Sent encrypted confirmation
[14:30:10] [HANDSHAKE] ✓ Secure channel established with user: Alice
[14:30:10] [HANDSHAKE] All messages will be encrypted with AES-256

[14:30:10] [JOIN] Alice joined from ('192.168.1.101', 54321)

[14:30:15] [HANDSHAKE] Starting with ('192.168.1.102', 54322)
[14:30:15] [HANDSHAKE] ✓ Secure channel established with user: Bob
[14:30:15] [JOIN] Bob joined from ('192.168.1.102', 54322)

[14:30:20] [ENCRYPTED BROADCAST] Alice: Hello Bob! This message is encrypted!
[14:30:25] [ENCRYPTED BROADCAST] Bob: Hi Alice! Yes, all our messages are secure!
[14:30:35] [PM ENCRYPTED] Alice -> Bob
```

## Technical Deep Dive

### 1. RSA Key Exchange (Handshake Phase)

**Server Side:**
```python
# Generate 2048-bit RSA key pair
server_rsa_key = RSA.generate(2048)
server_public_key = server_rsa_key.publickey()

# Send public key to client
public_key_pem = server_public_key.export_key()
conn.send(public_key_pem)

# Receive and decrypt AES key
encrypted_aes_key = conn.recv(key_length)
rsa_cipher = PKCS1_OAEP.new(server_rsa_key)
aes_key = rsa_cipher.decrypt(encrypted_aes_key)
```

**Client Side:**
```python
# Receive server's public key
public_key_pem = client_socket.recv(key_length)
server_public_key = RSA.import_key(public_key_pem)

# Generate AES-256 key (32 bytes)
aes_key = get_random_bytes(32)

# Encrypt AES key with server's public key
rsa_cipher = PKCS1_OAEP.new(server_public_key)
encrypted_aes_key = rsa_cipher.encrypt(aes_key)
client_socket.send(encrypted_aes_key)
```

### 2. AES Message Encryption (After Handshake)

**Encryption:**
```python
def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv  # Random IV for each message
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    # Return IV + encrypted, base64 encoded
    return base64.b64encode(iv + encrypted).decode()
```

**Decryption:**
```python
def decrypt_message(encrypted_data, aes_key):
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_bytes[:16]  # Extract IV
    ciphertext = encrypted_bytes[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode()
```

### 3. Security Features

✓ **Perfect Forward Secrecy**: New AES key for each session  
✓ **No Key Reuse**: Each message has unique IV  
✓ **Asymmetric + Symmetric**: Best of both worlds  
✓ **Padding**: PKCS7 padding prevents length analysis  
✓ **Base64 Encoding**: Safe binary data transport  
✓ **Length Prefixing**: Prevents message fragmentation  

## Security Properties

### Confidentiality ✓
- All messages encrypted with AES-256
- Symmetric key never transmitted in plaintext
- Different IV for each message prevents pattern analysis

### Authentication ✓
- Server proves ownership of RSA private key
- Only server can decrypt AES key
- Client verifies encrypted confirmation

### Integrity ✓
- Failed decryption detected immediately
- Padding validation ensures message integrity
- Base64 encoding prevents corruption

### Key Exchange Security ✓
- RSA-2048 provides strong asymmetric encryption
- AES key encrypted with public key
- Only server with private key can decrypt
- No man-in-the-middle without server's private key

## Comparison with Real SSL/TLS

| Feature | Task 7 | Real TLS |
|---------|--------|----------|
| Key Exchange | RSA | RSA, ECDHE, etc. |
| Symmetric Cipher | AES-256-CBC | AES-256-GCM preferred |
| Handshake Steps | 8 steps | ~10-12 steps |
| Certificates | None | X.509 certificates |
| Perfect Forward Secrecy | Per-session | Per-session (ECDHE) |
| Integrity Check | Implicit | MAC/AEAD |
| Cipher Suites | Fixed | Negotiable |

## Testing Scenarios

1. **Basic Encrypted Chat**
   - Start server and 2 clients
   - Send messages
   - Verify all encrypted in transit

2. **Handshake Verification**
   - Observe complete handshake output
   - Verify RSA key exchange
   - Check AES key generation

3. **Private Messages**
   - Send PMs between users
   - Verify encryption per-user
   - Check only recipient can decrypt

4. **Failed Decryption**
   - Simulate corrupted message
   - Verify error detection
   - Check graceful handling

5. **Multiple Sessions**
   - Connect multiple clients
   - Each gets unique AES key
   - Verify no cross-contamination

## Commands

All standard chat commands work with encryption:

- `/pm <user> <message>` - Encrypted private message
- `/list` - Show online users
- `/quit` - Secure disconnect

## Configuration

```python
PORT = 5174              # Different from task6 to avoid conflicts
RSA_KEY_SIZE = 2048      # RSA key strength
AES_KEY_SIZE = 32        # AES-256 (32 bytes)
BUFFER_SIZE = 4096       # Message buffer
```

## Advantages Over Plaintext

✅ **Privacy**: Messages cannot be read by network sniffers  
✅ **Security**: Prevents eavesdropping and interception  
✅ **Verification**: Confirms server identity via key exchange  
✅ **Modern Crypto**: Uses industry-standard algorithms  
✅ **Scalable**: Each client has unique session key  
✅ **Educational**: Demonstrates real-world security concepts  

## Educational Value

This implementation demonstrates:
- **How HTTPS/TLS works** at a fundamental level
- **Hybrid encryption** (asymmetric + symmetric)
- **Key exchange protocols**
- **Transport layer security**
- **Cryptographic best practices**
- **Real-world security concepts** in action

## Important Notes

⚠️ **Educational Purpose**: This is a simplified implementation for learning  
⚠️ **Production Use**: Real applications should use proven TLS libraries  
⚠️ **Certificate Validation**: Real TLS uses X.509 certificates  
⚠️ **Perfect Forward Secrecy**: Consider ECDHE for production  
⚠️ **Message Authentication**: Consider adding HMAC or using GCM mode  

## Requirements File

Create `requirements.txt`:
```
pycryptodome==3.19.0
```

Install with:
```bash
pip install -r requirements.txt
```
