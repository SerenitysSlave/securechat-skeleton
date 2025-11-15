#!/usr/bin/env python3
"""
Secure Chat Client
Connects to server, authenticates, and exchanges encrypted messages
"""

import socket
import sys
import os
import threading
import time

# Add app directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.pki import CertificateValidator, load_private_key, load_certificate
from crypto.dh import DHKeyExchange
from crypto.aes import AESCipher
from crypto.sign import SignatureManager
from storage.transcript import TranscriptManager
from storage.db import UserManager
from common.protocol import ProtocolHandler
from common.utils import send_message, receive_message, generate_nonce, format_cert_fingerprint, print_banner


class SecureChatClient:
    """Secure chat client implementation"""
    
    def __init__(self, server_host='127.0.0.1', server_port=5000):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        
        # Load client certificate and private key
        print("[*] Loading client credentials...")
        self.private_key = load_private_key("certs/client_private_key.pem")
        self.certificate = load_certificate("certs/client_cert.pem")
        
        # Initialize certificate validator
        self.cert_validator = CertificateValidator("certs/ca_cert.pem")
        
        # Server certificate
        self.server_cert = None
        self.server_public_key = None
        self.server_cert_fingerprint = None
        
        # Session state
        self.authenticated = False
        self.username = None
        self.email = None
        
        # Cryptographic state
        self.temp_aes_key = None  # For control plane (registration/login)
        self.session_aes_key = None  # For data plane (chat messages)
        
        # Message tracking
        self.last_seqno = 0
        self.my_seqno = 0
        
        # Transcript
        self.transcript = None
        
        # Signature manager
        self.signer = SignatureManager(
            private_key=self.private_key,
            public_key=self.certificate.public_key()
        )
        
        print("[+] Client initialized")
    
    def connect(self):
        """Connect to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"[+] Connected to server {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def certificate_exchange(self):
        """Phase 1: Mutual certificate exchange and validation"""
        print("\n[*] Starting certificate exchange...")
        
        try:
            # Step 1: Send client hello
            with open("certs/client_cert.pem", "rb") as f:
                client_cert_pem = f.read()
            
            client_nonce = generate_nonce()
            hello_msg = ProtocolHandler.create_hello(client_cert_pem, client_nonce)
            send_message(self.socket, hello_msg)
            
            print("[+] Sent client certificate")
            
            # Step 2: Receive server hello
            msg = receive_message(self.socket)
            if not msg:
                print("[-] Failed to receive server hello")
                return False
            
            data = ProtocolHandler.parse_message(msg)
            
            # Check for errors
            if data['type'] == ProtocolHandler.ERROR:
                print(f"[-] Server error: {data['code']} - {data['message']}")
                return False
            
            if data['type'] != ProtocolHandler.SERVER_HELLO:
                print("[-] Expected SERVER_HELLO message")
                return False
            
            # Step 3: Validate server certificate
            server_cert_pem = data['server_cert']
            is_valid, cert, error_msg = self.cert_validator.validate_certificate(
                server_cert_pem,
                expected_cn="SecureChat Server"
            )
            
            if not is_valid:
                print(f"[-] Server certificate validation failed: {error_msg}")
                return False
            
            self.server_cert = cert
            self.server_public_key = cert.public_key()
            self.server_cert_fingerprint = format_cert_fingerprint(cert)
            
            print(f"[+] Server certificate validated")
            print(f"    CN: {self.cert_validator.get_common_name(cert)}")
            print(f"    Fingerprint: {self.server_cert_fingerprint[:16]}...")
            
            print("[+] Certificate exchange completed")
            return True
            
        except Exception as e:
            print(f"[-] Certificate exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def authenticate(self):
        """Phase 2: Authenticate with server (register or login)"""
        print("\n[*] Starting authentication...")
        
        try:
            # Step 1: Perform temporary DH exchange for control plane encryption
            if not self.temp_dh_exchange():
                print("[-] Temporary DH exchange failed")
                return False
            
            # Step 2: Choose registration or login
            print("\n" + "="*60)
            print("1. Register new account")
            print("2. Login to existing account")
            print("="*60)
            
            choice = input("Choose option (1 or 2): ").strip()
            
            if choice == '1':
                return self.register()
            elif choice == '2':
                return self.login()
            else:
                print("[-] Invalid choice")
                return False
                
        except Exception as e:
            print(f"[-] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def temp_dh_exchange(self):
        """Temporary DH exchange for control plane encryption"""
        print("[*] Performing temporary DH exchange...")
        
        try:
            # Generate DH keypair
            dh = DHKeyExchange()
            client_A = dh.generate_keypair()
            
            # Send DH parameters
            params = dh.get_public_params()
            dh_msg = ProtocolHandler.create_dh_client(params['g'], params['p'], params['A'])
            send_message(self.socket, dh_msg)
            
            # Receive server DH response
            msg = receive_message(self.socket)
            if not msg:
                return False
            
            data = ProtocolHandler.parse_message(msg)
            if data['type'] != ProtocolHandler.DH_SERVER:
                return False
            
            server_B = data['B']
            
            # Compute shared secret
            self.temp_aes_key = dh.compute_shared_secret(server_B)
            
            print(f"[+] Temp session key derived: {self.temp_aes_key.hex()[:32]}...")
            
            return True
            
        except Exception as e:
            print(f"[-] Temp DH exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def register(self):
        """Handle user registration"""
        print("\n" + "="*60)
        print("REGISTRATION")
        print("="*60)
        
        try:
            # Get user input
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password (min 8 chars): ").strip()
            
            # Validate locally
            if not UserManager.validate_email(email):
                print("[-] Invalid email format")
                return False
            
            if not UserManager.validate_username(username):
                print("[-] Invalid username (3-50 alphanumeric characters)")
                return False
            
            if not UserManager.validate_password(password):
                print("[-] Password must be at least 8 characters")
                return False
            
            # Generate salt and hash password
            salt = UserManager.generate_salt()
            pwd_hash = UserManager.hash_password(salt, password)
            
            # Create registration message
            reg_msg = ProtocolHandler.create_register(email, username, pwd_hash, salt)
            
            # Encrypt with temp key
            temp_cipher = AESCipher(self.temp_aes_key)
            encrypted_payload = temp_cipher.encrypt(reg_msg)
            
            # Send encrypted registration
            encrypted_msg = f'{{"type":"encrypted","payload":"{encrypted_payload}"}}'
            send_message(self.socket, encrypted_msg)
            
            print("[+] Registration request sent")
            
            # Receive response
            msg = receive_message(self.socket)
            if not msg:
                print("[-] No response from server")
                return False
            
            data = ProtocolHandler.parse_message(msg)
            
            # Decrypt response if encrypted
            if data.get('type') == 'encrypted':
                decrypted_response = temp_cipher.decrypt(data['payload'])
                response = ProtocolHandler.parse_message(decrypted_response)
            else:
                response = data
            
            # Check result
            if response['type'] == ProtocolHandler.AUTH_SUCCESS:
                print(f"[+] {response['message']}")
                self.authenticated = True
                self.username = response.get('username', username)
                self.email = email
                return True
            else:
                print(f"[-] Registration failed: {response['message']}")
                return False
                
        except Exception as e:
            print(f"[-] Registration error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def login(self):
        """Handle user login"""
        print("\n" + "="*60)
        print("LOGIN")
        print("="*60)
        
        try:
            # Get credentials
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            
            # Note: We need to get the salt from server first
            # For now, we'll hash with a temporary approach
            # In a real system, you'd do a two-step login (get salt, then send hash)
            
            # For this implementation, we'll send email and let server verify
            # Create a dummy salt for the hash (client doesn't know real salt yet)
            # Server will re-verify with stored salt
            
            temp_salt = b'\x00' * 16  # Dummy salt
            pwd_hash = UserManager.hash_password(temp_salt, password)
            
            # Actually, let's fix this: send plaintext password (encrypted with temp key)
            # Server will hash it properly
            
            login_nonce = generate_nonce()
            login_msg = ProtocolHandler.create_login(email, password, login_nonce)
            
            # Encrypt with temp key
            temp_cipher = AESCipher(self.temp_aes_key)
            encrypted_payload = temp_cipher.encrypt(login_msg)
            
            # Send encrypted login
            encrypted_msg = f'{{"type":"encrypted","payload":"{encrypted_payload}"}}'
            send_message(self.socket, encrypted_msg)
            
            print("[+] Login request sent")
            
            # Receive response
            msg = receive_message(self.socket)
            if not msg:
                print("[-] No response from server")
                return False
            
            data = ProtocolHandler.parse_message(msg)
            
            # Decrypt response if encrypted
            if data.get('type') == 'encrypted':
                decrypted_response = temp_cipher.decrypt(data['payload'])
                response = ProtocolHandler.parse_message(decrypted_response)
            else:
                response = data
            
            # Check result
            if response['type'] == ProtocolHandler.AUTH_SUCCESS:
                print(f"[+] {response['message']}")
                self.authenticated = True
                self.username = response.get('username')
                self.email = email
                return True
            else:
                print(f"[-] Login failed: {response['message']}")
                return False
                
        except Exception as e:
            print(f"[-] Login error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def establish_session_key(self):
        """Phase 3: Establish session key via DH for chat encryption"""
        print("\n[*] Establishing session key...")
        
        try:
            # Generate DH keypair
            dh = DHKeyExchange()
            client_A = dh.generate_keypair()
            
            # Send DH parameters
            params = dh.get_public_params()
            dh_msg = ProtocolHandler.create_dh_client(params['g'], params['p'], params['A'])
            send_message(self.socket, dh_msg)
            
            # Receive server DH response
            msg = receive_message(self.socket)
            if not msg:
                return False
            
            data = ProtocolHandler.parse_message(msg)
            if data['type'] != ProtocolHandler.DH_SERVER:
                return False
            
            server_B = data['B']
            
            # Compute shared session key
            self.session_aes_key = dh.compute_shared_secret(server_B)
            
            print(f"[+] Session key established: {self.session_aes_key.hex()[:32]}...")
            
            # Initialize transcript
            self.transcript = TranscriptManager(
                role="client",
                peer_name="server",
                session_id=f"{self.username}_{int(time.time())}"
            )
            
            return True
            
        except Exception as e:
            print(f"[-] Session key establishment error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def chat_loop(self):
        """Phase 4: Encrypted chat message exchange"""
        print("\n" + "="*60)
        print(f"SECURE CHAT SESSION - {self.username}")
        print("="*60)
        print("[*] Type your messages (type 'quit' to exit)")
        print()
        
        # Create cipher
        cipher = AESCipher(self.session_aes_key)
        
        # Start receiver thread
        self.running = True
        receiver_thread = threading.Thread(target=self.receive_messages, args=(cipher,))
        receiver_thread.daemon = True
        receiver_thread.start()
        
        # Send messages
        try:
            while self.running:
                # Read from console
                plaintext = input(f"[{self.username}]: ")
                
                if plaintext.lower() == 'quit':
                    self.running = False
                    # Send disconnect message
                    disconnect_msg = ProtocolHandler.create_disconnect()
                    send_message(self.socket, disconnect_msg)
                    break
                
                if not plaintext.strip():
                    continue
                
                # Encrypt message
                ciphertext = cipher.encrypt(plaintext)
                
                # Increment sequence number
                self.my_seqno += 1
                
                # Sign message
                timestamp = int(time.time() * 1000)
                signature = self.signer.sign_message(self.my_seqno, timestamp, ciphertext)
                
                # Create and send message
                msg = ProtocolHandler.create_message(self.my_seqno, ciphertext, signature)
                send_message(self.socket, msg)
                
                # Log to transcript
                self.transcript.append_message(
                    self.my_seqno, timestamp, ciphertext, signature,
                    self.server_cert_fingerprint
                )
                
        except KeyboardInterrupt:
            print("\n[*] Client initiated disconnect")
            self.running = False
        except Exception as e:
            print(f"\n[-] Chat error: {e}")
            import traceback
            traceback.print_exc()
            self.running = False
    
    def receive_messages(self, cipher):
        """Receive and decrypt messages from server"""
        server_signer = SignatureManager(public_key=self.server_public_key)
        
        while self.running:
            try:
                msg = receive_message(self.socket)
                if not msg:
                    print("\n[*] Connection closed by server")
                    self.running = False
                    break
                
                data = ProtocolHandler.parse_message(msg)
                
                if data['type'] == ProtocolHandler.MSG:
                    seqno = data['seqno']
                    timestamp = data['ts']
                    ciphertext = data['ct']
                    signature = data['sig']
                    
                    # Check sequence number (replay protection)
                    if seqno <= self.last_seqno:
                        print(f"\n[!] REPLAY detected: seqno {seqno}")
                        continue
                    
                    # Verify signature
                    if not server_signer.verify_message(seqno, timestamp, ciphertext, signature):
                        print(f"\n[!] SIG_FAIL: Invalid signature on message {seqno}")
                        continue
                    
                    # Decrypt message
                    plaintext = cipher.decrypt(ciphertext)
                    
                    # Update sequence number
                    self.last_seqno = seqno
                    
                    # Log to transcript
                    self.transcript.append_message(
                        seqno, timestamp, ciphertext, signature,
                        self.server_cert_fingerprint
                    )
                    
                    # Display message
                    print(f"\n[Server]: {plaintext}")
                    print(f"[{self.username}]: ", end='', flush=True)
                
                elif data['type'] == ProtocolHandler.DISCONNECT:
                    print("\n[*] Server disconnected")
                    self.running = False
                    break
                    
            except Exception as e:
                if self.running:
                    print(f"\n[-] Receive error: {e}")
                break
    
    def teardown(self):
        """Phase 5: Generate and exchange session receipts"""
        print("\n[*] Generating session receipt...")
        
        try:
            if self.transcript and len(self.transcript.entries) > 0:
                # Compute transcript hash
                transcript_hash = self.transcript.compute_transcript_hash()
                
                # Get sequence range
                first_seq, last_seq = self.transcript.get_sequence_range()
                
                # Sign transcript hash
                signature = self.signer.sign_data(transcript_hash.encode('utf-8'))
                
                # Create receipt
                receipt = ProtocolHandler.create_receipt(
                    "client", first_seq, last_seq, transcript_hash, signature
                )
                
                # Save receipt
                self.transcript.save_receipt(receipt)
                
                # Finalize transcript
                self.transcript.finalize()
                
                print(f"[+] Session receipt generated")
                print(f"    Transcript: {self.transcript.filename}")
                print(f"    Transcript hash: {transcript_hash[:32]}...")
                
        except Exception as e:
            print(f"[-] Teardown error: {e}")
            import traceback
            traceback.print_exc()
    
    def start(self):
        """Main client workflow"""
        print_banner("SECURE CHAT CLIENT")
        
        try:
            # Phase 1: Connect and exchange certificates
            if not self.connect():
                return
            
            if not self.certificate_exchange():
                print("[-] Certificate exchange failed")
                return
            
            # Phase 2: Authenticate
            if not self.authenticate():
                print("[-] Authentication failed")
                return
            
            # Phase 3: Establish session key
            if not self.establish_session_key():
                print("[-] Session key establishment failed")
                return
            
            # Phase 4: Chat
            self.chat_loop()
            
            # Phase 5: Teardown
            self.teardown()
            
        except KeyboardInterrupt:
            print("\n[*] Client shutting down...")
        except Exception as e:
            print(f"[-] Client error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.socket:
                self.socket.close()
            print("[+] Client stopped")


if __name__ == "__main__":
    # Parse command line arguments (optional)
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    
    args = parser.parse_args()
    
    # Start client
    client = SecureChatClient(server_host=args.host, server_port=args.port)
    client.start()