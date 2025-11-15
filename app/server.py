"""
Secure Chat Server (No TLS/SSL)
Handles client authentication, DH key exchange, encrypted chat,
message signing, replay protection, and transcript receipts.
"""

import socket
import sys
import os
import json
import threading
import argparse
from contextlib import suppress


APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
sys.path.insert(0, APP_DIR)

from crypto.pki import CertificateValidator, load_private_key, load_certificate
from crypto.dh import DHKeyExchange
from crypto.aes import AESCipher
from crypto.sign import SignatureManager
from storage.db import DatabaseManager
from storage.transcript import TranscriptManager
from common.protocol import ProtocolHandler
from common.utils import (
    send_message,
    receive_message,
    generate_nonce,
    format_cert_fingerprint,
    print_banner,
)


def _json(obj) -> str:
    """Compact JSON encoder."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _wrap_encrypted(payload_b64: str) -> str:
    """Return protocol envelope for encrypted payload."""
    return _json({"type": "encrypted", "payload": payload_b64})


# ---------------------------------------------------------------------
#                           CLIENT HANDLER
# ---------------------------------------------------------------------
class ClientHandler:
    """Handles one client connection + all security states."""

    def __init__(self, sock: socket.socket, address, server):
        self.socket = sock
        self.address = address
        self.server = server

        # Certificate details
        self.client_cert = None
        self.client_public_key = None
        self.client_cert_fingerprint = None

        # Authentication state
        self.authenticated = False
        self.username = None
        self.email = None

        # Keys
        self.temp_aes_key = None   # control-plane encryption
        self.session_aes_key = None  # chat encryption

        # Sequence numbers
        self.last_seqno = 0
        self.my_seqno = 0

        # Transcript recorder
        self.transcript: TranscriptManager | None = None

        self.signer = SignatureManager(
            private_key=server.private_key,
            public_key=server.certificate.public_key(),
        )

        self._receiver_thread: threading.Thread | None = None

    # -----------------------------------------------------------------
    #                      MAIN CONNECTION FLOW
    # -----------------------------------------------------------------
    def handle(self):
        print(f"[+] Connection from {self.address}")

        try:
            self.socket.settimeout(20.0)

            if not self.certificate_exchange():
                return

            if not self.authenticate_client():
                return

            if not self.establish_session_key():
                return

            self.socket.settimeout(None)

            self.chat_loop()
            self.teardown()

        except Exception as e:
            print(f"[-] Handler error ({self.address}): {e}")
            import traceback
            traceback.print_exc()

        finally:
            with suppress(Exception):
                self.socket.shutdown(socket.SHUT_RDWR)
            with suppress(Exception):
                self.socket.close()

            print(f"[+] Disconnected: {self.address}")

    # -----------------------------------------------------------------
    #                    CERTIFICATE EXCHANGE
    # -----------------------------------------------------------------
    def certificate_exchange(self) -> bool:
        print("\n[*] Certificate exchange...")

        try:
            msg = receive_message(self.socket)
            if not msg:
                return False

            data = ProtocolHandler.parse_message(msg)
            if data.get("type") != ProtocolHandler.HELLO:
                send_message(
                    self.socket,
                    ProtocolHandler.create_error("PROTOCOL_ERROR", "Expected HELLO"),
                )
                return False

            # Validate client certificate
            client_cert_pem = data.get("client_cert")
            ok, cert, err = self.server.cert_validator.validate_certificate(client_cert_pem)
            if not ok:
                print(f"[-] Bad client certificate: {err}")
                send_message(self.socket, ProtocolHandler.create_error("BAD_CERT", err))
                return False

            self.client_cert = cert
            self.client_public_key = cert.public_key()
            self.client_cert_fingerprint = format_cert_fingerprint(cert)

            print("[+] Certificate OK")
            print(f"    CN: {self.server.cert_validator.get_common_name(cert)}")
            print(f"    FP: {self.client_cert_fingerprint[:18]}...")

            # Send server hello
            with open(self.server.paths["server_cert"], "rb") as f:
                server_cert_pem = f.read()

            server_nonce = generate_nonce()
            send_message(self.socket, ProtocolHandler.create_server_hello(server_cert_pem, server_nonce))

            return True

        except Exception as e:
            print(f"[-] Cert exchange error: {e}")
            return False

    # -----------------------------------------------------------------
    #                     AUTHENTICATION PHASE
    # -----------------------------------------------------------------
    def authenticate_client(self) -> bool:
        print("\n[*] Authentication phase...")

        try:
            if not self._dh_exchange(is_temp=True):
                return False

            msg = receive_message(self.socket)
            if not msg:
                return False

            data = ProtocolHandler.parse_message(msg)
            cipher = AESCipher(self.temp_aes_key)

            if data.get("type") == "encrypted":
                auth_raw = cipher.decrypt(data["payload"])
                auth = ProtocolHandler.parse_message(auth_raw)
            else:
                auth = data

            if auth.get("type") == ProtocolHandler.REGISTER:
                return self.handle_registration(auth)

            if auth.get("type") == ProtocolHandler.LOGIN:
                return self.handle_login(auth)

            send_message(self.socket, ProtocolHandler.create_auth_response(False, "Bad auth message"))
            return False

        except Exception as e:
            print(f"[-] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return False

    # -----------------------------------------------------------------
    #                     DIFFIE–HELLMAN EXCHANGE
    # -----------------------------------------------------------------
    def _dh_exchange(self, is_temp: bool) -> bool:
        phase = "temp" if is_temp else "session"
        print(f"[*] DH ({phase})...")

        try:
            msg = receive_message(self.socket)
            if not msg:
                return False

            data = ProtocolHandler.parse_message(msg)
            if data.get("type") != ProtocolHandler.DH_CLIENT:
                send_message(
                    self.socket,
                    ProtocolHandler.create_error("PROTOCOL_ERROR", "Expected DH_CLIENT"),
                )
                return False

            p, g, client_A = data["p"], data["g"], data["A"]

            dh = DHKeyExchange(p=p, g=g)
            server_B = dh.generate_keypair()
            shared = dh.compute_shared_secret(client_A)

            if is_temp:
                self.temp_aes_key = shared
                print("[+] Temp AES key set")
            else:
                self.session_aes_key = shared
                print("[+] Session AES key set")

            send_message(self.socket, ProtocolHandler.create_dh_server(server_B))
            return True

        except Exception as e:
            print(f"[-] DH ({phase}) error: {e}")
            return False

    # -----------------------------------------------------------------
    #                         REGISTRATION
    # -----------------------------------------------------------------
    def handle_registration(self, data: dict) -> bool:
        print("[*] Registration...")

        try:
            email = data.get("email")
            username = data.get("username")
            pwd_hash = data.get("pwd")
            salt_b64 = data.get("salt")

            if not all([email, username, pwd_hash, salt_b64]):
                raise ValueError("Missing fields")

            import base64
            salt = base64.b64decode(salt_b64)

            ok, msg = self.server.db.register_user(email, username, salt, pwd_hash)

            if ok:
                self.authenticated = True
                self.username = username
                self.email = email
                print(f"[+] Registered user: {username}")

            response = ProtocolHandler.create_auth_response(ok, msg, username if ok else None)

            cipher = AESCipher(self.temp_aes_key)
            send_message(self.socket, _wrap_encrypted(cipher.encrypt(response)))
            return ok

        except Exception as e:
            print(f"[-] Registration error: {e}")
            return False

    # -----------------------------------------------------------------
    #                           LOGIN
    # -----------------------------------------------------------------
    def handle_login(self, data: dict) -> bool:
        print("[*] Login...")

        try:
            email = data.get("email")
            pwd_hash = data.get("pwd")

            stored_salt, stored_hash, username = self.server.db.get_user_credentials(email)

            cipher = AESCipher(self.temp_aes_key)

            if stored_salt is None:
                resp = ProtocolHandler.create_auth_response(False, "User not found")
                send_message(self.socket, _wrap_encrypted(cipher.encrypt(resp)))
                return False

            if pwd_hash == stored_hash:
                self.authenticated = True
                self.email = email
                self.username = username
                self.server.db.update_last_login(email)
                resp = ProtocolHandler.create_auth_response(True, "OK", username)
                print(f"[+] Login OK: {username}")
            else:
                resp = ProtocolHandler.create_auth_response(False, "Invalid password")
                print(f"[-] Wrong password for {email}")

            send_message(self.socket, _wrap_encrypted(cipher.encrypt(resp)))
            return self.authenticated

        except Exception as e:
            print(f"[-] Login error: {e}")
            return False

    # -----------------------------------------------------------------
    #                     SESSION KEY SETUP
    # -----------------------------------------------------------------
    def establish_session_key(self) -> bool:
        print("\n[*] Establishing session key...")

        if not self._dh_exchange(is_temp=False):
            return False

        self.transcript = TranscriptManager(
            role="server",
            peer_name=self.username or "unknown",
            session_id=f"{self.username}_{self.address[0]}_{self.address[1]}",
        )

        return True

    # -----------------------------------------------------------------
    #                              CHAT
    # -----------------------------------------------------------------
    def chat_loop(self):
        print(f"\n[*] Chat started with {self.username}")
        print("[*] Type 'quit' to exit")

        cipher = AESCipher(self.session_aes_key)

        self._receiver_thread = threading.Thread(
            target=self.receive_messages, args=(cipher,), daemon=True
        )
        self._receiver_thread.start()

        try:
            while True:
                text = input(f"[Server -> {self.username}]: ").strip()
                if text.lower() == "quit":
                    break
                if not text:
                    continue

                ct = cipher.encrypt(text)
                self.my_seqno += 1

                import time
                ts = int(time.time() * 1000)
                sig = self.signer.sign_message(self.my_seqno, ts, ct)

                msg = ProtocolHandler.create_message(self.my_seqno, ct, sig, timestamp=ts)
                send_message(self.socket, msg)

                if self.transcript:
                    self.transcript.append_message(self.my_seqno, ts, ct, sig, self.client_cert_fingerprint)

        except (EOFError, KeyboardInterrupt):
            print("\n[*] Ending chat")

        finally:
            with suppress(Exception):
                send_message(self.socket, ProtocolHandler.create_disconnect())
            if self._receiver_thread.is_alive():
                self._receiver_thread.join(1)

    # -----------------------------------------------------------------
    #                       RECEIVE LOOP
    # -----------------------------------------------------------------
    def receive_messages(self, cipher: AESCipher):
        client_sig = SignatureManager(public_key=self.client_public_key)

        while True:
            try:
                msg = receive_message(self.socket)
                if not msg:
                    break

                data = ProtocolHandler.parse_message(msg)

                if data.get("type") == ProtocolHandler.MSG:
                    seqno = data["seqno"]
                    ts = data["ts"]
                    ct = data["ct"]
                    sig = data["sig"]

                    # Replay protection
                    if seqno <= self.last_seqno:
                        print(f"\n[!] Replay blocked: {seqno}")
                        continue

                    # Signature verification
                    if not client_sig.verify_message(seqno, ts, ct, sig):
                        print(f"\n[!] Bad signature (seq {seqno})")
                        continue

                    pt = cipher.decrypt(ct)
                    self.last_seqno = seqno

                    if self.transcript:
                        self.transcript.append_message(seqno, ts, ct, sig, self.client_cert_fingerprint)

                    print(f"\n[{self.username}]: {pt}")
                    print(f"[Server -> {self.username}]: ", end="")

                elif data.get("type") == ProtocolHandler.DISCONNECT:
                    print(f"\n[*] Client left: {self.username}")
                    break

            except Exception:
                break

    # -----------------------------------------------------------------
    #                        TEARDOWN
    # -----------------------------------------------------------------
    def teardown(self):
        print("\n[*] Creating session receipt...")

        try:
            if not self.transcript or not self.transcript.entries:
                return

            h = self.transcript.compute_transcript_hash()
            first, last = self.transcript.get_sequence_range()
            sig = self.signer.sign_data(h.encode("utf-8"))

            receipt = ProtocolHandler.create_receipt(
                "server", first, last, h, sig
            )

            self.transcript.save_receipt(receipt)
            with suppress(Exception):
                send_message(self.socket, ProtocolHandler.create_receipt_envelope(receipt))

            self.transcript.finalize()

            print("[+] Session receipt stored")
            print(f"    Hash: {h[:40]}...")

        except Exception as e:
            print(f"[-] Teardown error: {e}")


# ---------------------------------------------------------------------
#                          SERVER CLASS
# ---------------------------------------------------------------------
class SecureChatServer:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None

        certs_dir = os.path.join(PROJECT_ROOT, "certs")
        self.paths = {
            "server_key": os.path.join(certs_dir, "server_private_key.pem"),
            "server_cert": os.path.join(certs_dir, "server_cert.pem"),
            "ca_cert": os.path.join(certs_dir, "ca_cert.pem"),
        }

        print("[*] Loading server keys...")
        self.private_key = load_private_key(self.paths["server_key"])
        self.certificate = load_certificate(self.paths["server_cert"])

        self.cert_validator = CertificateValidator(self.paths["ca_cert"])

        print("[*] Connecting DB...")
        self.db = DatabaseManager()
        if not self.db.connect():
            raise RuntimeError("Database connection failed")

        print("[+] Server ready")

    def start(self):
        print_banner("SECURE CHAT SERVER")

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(50)

            print(f"[+] Listening at {self.host}:{self.port}\n")

            while True:
                sock, addr = self.socket.accept()
                threading.Thread(
                    target=ClientHandler(sock, addr, self).handle,
                    daemon=True
                ).start()

        except KeyboardInterrupt:
            print("\n[*] Shutdown requested")
        finally:
            with suppress(Exception):
                if self.socket:
                    self.socket.close()
            self.db.disconnect()
            print("[+] Server stopped")


# ---------------------------------------------------------------------
#                              MAIN
# ---------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("SECURECHAT_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SECURECHAT_PORT", "5000")))
    args = parser.parse_args(argv)

    SecureChatServer(args.host, args.port).start()


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Secure Chat Server (No TLS/SSL)
Handles client authentication, DH key exchange, encrypted chat,
message signing, replay protection, and transcript receipts.
"""

import socket
import sys
import os
import json
import threading
import argparse
from contextlib import suppress

# Add 'app' directory to path
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
sys.path.insert(0, APP_DIR)

from crypto.pki import CertificateValidator, load_private_key, load_certificate
from crypto.dh import DHKeyExchange
from crypto.aes import AESCipher
from crypto.sign import SignatureManager
from storage.db import DatabaseManager
from storage.transcript import TranscriptManager
from common.protocol import ProtocolHandler
from common.utils import (
    send_message,
    receive_message,
    generate_nonce,
    format_cert_fingerprint,
    print_banner,
)


def _json(obj) -> str:
    """Compact JSON encoder."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _wrap_encrypted(payload_b64: str) -> str:
    """Return protocol envelope for encrypted payload."""
    return _json({"type": "encrypted", "payload": payload_b64})


# ---------------------------------------------------------------------
#                           CLIENT HANDLER
# ---------------------------------------------------------------------
class ClientHandler:
    """Handles one client connection + all security states."""

    def __init__(self, sock: socket.socket, address, server):
        self.socket = sock
        self.address = address
        self.server = server

        # Certificate details
        self.client_cert = None
        self.client_public_key = None
        self.client_cert_fingerprint = None

        # Authentication state
        self.authenticated = False
        self.username = None
        self.email = None

        # Keys
        self.temp_aes_key = None   # control-plane encryption
        self.session_aes_key = None  # chat encryption

        # Sequence numbers
        self.last_seqno = 0
        self.my_seqno = 0

        # Transcript recorder
        self.transcript: TranscriptManager | None = None

        self.signer = SignatureManager(
            private_key=server.private_key,
            public_key=server.certificate.public_key(),
        )

        self._receiver_thread: threading.Thread | None = None

    # -----------------------------------------------------------------
    #                      MAIN CONNECTION FLOW
    # -----------------------------------------------------------------
    def handle(self):
        print(f"[+] Connection from {self.address}")

        try:
            self.socket.settimeout(20.0)

            if not self.certificate_exchange():
                return

            if not self.authenticate_client():
                return

            if not self.establish_session_key():
                return

            self.socket.settimeout(None)

            self.chat_loop()
            self.teardown()

        except Exception as e:
            print(f"[-] Handler error ({self.address}): {e}")
            import traceback
            traceback.print_exc()

        finally:
            with suppress(Exception):
                self.socket.shutdown(socket.SHUT_RDWR)
            with suppress(Exception):
                self.socket.close()

            print(f"[+] Disconnected: {self.address}")

    # -----------------------------------------------------------------
    #                    CERTIFICATE EXCHANGE
    # -----------------------------------------------------------------
    def certificate_exchange(self) -> bool:
        print("\n[*] Certificate exchange...")

        try:
            msg = receive_message(self.socket)
            if not msg:
                return False

            data = ProtocolHandler.parse_message(msg)
            if data.get("type") != ProtocolHandler.HELLO:
                send_message(
                    self.socket,
                    ProtocolHandler.create_error("PROTOCOL_ERROR", "Expected HELLO"),
                )
                return False

            # Validate client certificate
            client_cert_pem = data.get("client_cert")
            ok, cert, err = self.server.cert_validator.validate_certificate(client_cert_pem)
            if not ok:
                print(f"[-] Bad client certificate: {err}")
                send_message(self.socket, ProtocolHandler.create_error("BAD_CERT", err))
                return False

            self.client_cert = cert
            self.client_public_key = cert.public_key()
            self.client_cert_fingerprint = format_cert_fingerprint(cert)

            print("[+] Certificate OK")
            print(f"    CN: {self.server.cert_validator.get_common_name(cert)}")
            print(f"    FP: {self.client_cert_fingerprint[:18]}...")

            # Send server hello
            with open(self.server.paths["server_cert"], "rb") as f:
                server_cert_pem = f.read()

            server_nonce = generate_nonce()
            send_message(self.socket, ProtocolHandler.create_server_hello(server_cert_pem, server_nonce))

            return True

        except Exception as e:
            print(f"[-] Cert exchange error: {e}")
            return False

    # -----------------------------------------------------------------
    #                     AUTHENTICATION PHASE
    # -----------------------------------------------------------------
    def authenticate_client(self) -> bool:
        print("\n[*] Authentication phase...")

        try:
            if not self._dh_exchange(is_temp=True):
                return False

            msg = receive_message(self.socket)
            if not msg:
                return False

            data = ProtocolHandler.parse_message(msg)
            cipher = AESCipher(self.temp_aes_key)

            if data.get("type") == "encrypted":
                auth_raw = cipher.decrypt(data["payload"])
                auth = ProtocolHandler.parse_message(auth_raw)
            else:
                auth = data

            if auth.get("type") == ProtocolHandler.REGISTER:
                return self.handle_registration(auth)

            if auth.get("type") == ProtocolHandler.LOGIN:
                return self.handle_login(auth)

            send_message(self.socket, ProtocolHandler.create_auth_response(False, "Bad auth message"))
            return False

        except Exception as e:
            print(f"[-] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return False

    # -----------------------------------------------------------------
    #                     DIFFIE–HELLMAN EXCHANGE
    # -----------------------------------------------------------------
    def _dh_exchange(self, is_temp: bool) -> bool:
        phase = "temp" if is_temp else "session"
        print(f"[*] DH ({phase})...")

        try:
            msg = receive_message(self.socket)
            if not msg:
                return False

            data = ProtocolHandler.parse_message(msg)
            if data.get("type") != ProtocolHandler.DH_CLIENT:
                send_message(
                    self.socket,
                    ProtocolHandler.create_error("PROTOCOL_ERROR", "Expected DH_CLIENT"),
                )
                return False

            p, g, client_A = data["p"], data["g"], data["A"]

            dh = DHKeyExchange(p=p, g=g)
            server_B = dh.generate_keypair()
            shared = dh.compute_shared_secret(client_A)

            if is_temp:
                self.temp_aes_key = shared
                print("[+] Temp AES key set")
            else:
                self.session_aes_key = shared
                print("[+] Session AES key set")

            send_message(self.socket, ProtocolHandler.create_dh_server(server_B))
            return True

        except Exception as e:
            print(f"[-] DH ({phase}) error: {e}")
            return False

    # -----------------------------------------------------------------
    #                         REGISTRATION
    # -----------------------------------------------------------------
    def handle_registration(self, data: dict) -> bool:
        print("[*] Registration...")

        try:
            email = data.get("email")
            username = data.get("username")
            pwd_hash = data.get("pwd")
            salt_b64 = data.get("salt")

            if not all([email, username, pwd_hash, salt_b64]):
                raise ValueError("Missing fields")

            import base64
            salt = base64.b64decode(salt_b64)

            ok, msg = self.server.db.register_user(email, username, salt, pwd_hash)

            if ok:
                self.authenticated = True
                self.username = username
                self.email = email
                print(f"[+] Registered user: {username}")

            response = ProtocolHandler.create_auth_response(ok, msg, username if ok else None)

            cipher = AESCipher(self.temp_aes_key)
            send_message(self.socket, _wrap_encrypted(cipher.encrypt(response)))
            return ok

        except Exception as e:
            print(f"[-] Registration error: {e}")
            return False

    # -----------------------------------------------------------------
    #                           LOGIN
    # -----------------------------------------------------------------
    def handle_login(self, data: dict) -> bool:
        print("[*] Login...")

        try:
            email = data.get("email")
            pwd_hash = data.get("pwd")

            stored_salt, stored_hash, username = self.server.db.get_user_credentials(email)

            cipher = AESCipher(self.temp_aes_key)

            if stored_salt is None:
                resp = ProtocolHandler.create_auth_response(False, "User not found")
                send_message(self.socket, _wrap_encrypted(cipher.encrypt(resp)))
                return False

            if pwd_hash == stored_hash:
                self.authenticated = True
                self.email = email
                self.username = username
                self.server.db.update_last_login(email)
                resp = ProtocolHandler.create_auth_response(True, "OK", username)
                print(f"[+] Login OK: {username}")
            else:
                resp = ProtocolHandler.create_auth_response(False, "Invalid password")
                print(f"[-] Wrong password for {email}")

            send_message(self.socket, _wrap_encrypted(cipher.encrypt(resp)))
            return self.authenticated

        except Exception as e:
            print(f"[-] Login error: {e}")
            return False

    # -----------------------------------------------------------------
    #                     SESSION KEY SETUP
    # -----------------------------------------------------------------
    def establish_session_key(self) -> bool:
        print("\n[*] Establishing session key...")

        if not self._dh_exchange(is_temp=False):
            return False

        self.transcript = TranscriptManager(
            role="server",
            peer_name=self.username or "unknown",
            session_id=f"{self.username}_{self.address[0]}_{self.address[1]}",
        )

        return True

    # -----------------------------------------------------------------
    #                              CHAT
    # -----------------------------------------------------------------
    def chat_loop(self):
        print(f"\n[*] Chat started with {self.username}")
        print("[*] Type 'quit' to exit")

        cipher = AESCipher(self.session_aes_key)

        self._receiver_thread = threading.Thread(
            target=self.receive_messages, args=(cipher,), daemon=True
        )
        self._receiver_thread.start()

        try:
            while True:
                text = input(f"[Server -> {self.username}]: ").strip()
                if text.lower() == "quit":
                    break
                if not text:
                    continue

                ct = cipher.encrypt(text)
                self.my_seqno += 1

                import time
                ts = int(time.time() * 1000)
                sig = self.signer.sign_message(self.my_seqno, ts, ct)

                msg = ProtocolHandler.create_message(self.my_seqno, ct, sig, timestamp=ts)
                send_message(self.socket, msg)

                if self.transcript:
                    self.transcript.append_message(self.my_seqno, ts, ct, sig, self.client_cert_fingerprint)

        except (EOFError, KeyboardInterrupt):
            print("\n[*] Ending chat")

        finally:
            with suppress(Exception):
                send_message(self.socket, ProtocolHandler.create_disconnect())
            if self._receiver_thread.is_alive():
                self._receiver_thread.join(1)

    # -----------------------------------------------------------------
    #                       RECEIVE LOOP
    # -----------------------------------------------------------------
    def receive_messages(self, cipher: AESCipher):
        client_sig = SignatureManager(public_key=self.client_public_key)

        while True:
            try:
                msg = receive_message(self.socket)
                if not msg:
                    break

                data = ProtocolHandler.parse_message(msg)

                if data.get("type") == ProtocolHandler.MSG:
                    seqno = data["seqno"]
                    ts = data["ts"]
                    ct = data["ct"]
                    sig = data["sig"]

                    # Replay protection
                    if seqno <= self.last_seqno:
                        print(f"\n[!] Replay blocked: {seqno}")
                        continue

                    # Signature verification
                    if not client_sig.verify_message(seqno, ts, ct, sig):
                        print(f"\n[!] Bad signature (seq {seqno})")
                        continue

                    pt = cipher.decrypt(ct)
                    self.last_seqno = seqno

                    if self.transcript:
                        self.transcript.append_message(seqno, ts, ct, sig, self.client_cert_fingerprint)

                    print(f"\n[{self.username}]: {pt}")
                    print(f"[Server -> {self.username}]: ", end="")

                elif data.get("type") == ProtocolHandler.DISCONNECT:
                    print(f"\n[*] Client left: {self.username}")
                    break

            except Exception:
                break

    # -----------------------------------------------------------------
    #                        TEARDOWN
    # -----------------------------------------------------------------
    def teardown(self):
        print("\n[*] Creating session receipt...")

        try:
            if not self.transcript or not self.transcript.entries:
                return

            h = self.transcript.compute_transcript_hash()
            first, last = self.transcript.get_sequence_range()
            sig = self.signer.sign_data(h.encode("utf-8"))

            receipt = ProtocolHandler.create_receipt(
                "server", first, last, h, sig
            )

            self.transcript.save_receipt(receipt)
            with suppress(Exception):
                send_message(self.socket, ProtocolHandler.create_receipt_envelope(receipt))

            self.transcript.finalize()

            print("[+] Session receipt stored")
            print(f"    Hash: {h[:40]}...")

        except Exception as e:
            print(f"[-] Teardown error: {e}")


# ---------------------------------------------------------------------
#                          SERVER CLASS
# ---------------------------------------------------------------------
class SecureChatServer:
    def __init__(self, host="127.0.0.1", port=5000):
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None

        certs_dir = os.path.join(PROJECT_ROOT, "certs")
        self.paths = {
            "server_key": os.path.join(certs_dir, "server_private_key.pem"),
            "server_cert": os.path.join(certs_dir, "server_cert.pem"),
            "ca_cert": os.path.join(certs_dir, "ca_cert.pem"),
        }

        print("[*] Loading server keys...")
        self.private_key = load_private_key(self.paths["server_key"])
        self.certificate = load_certificate(self.paths["server_cert"])

        self.cert_validator = CertificateValidator(self.paths["ca_cert"])

        print("[*] Connecting DB...")
        self.db = DatabaseManager()
        if not self.db.connect():
            raise RuntimeError("Database connection failed")

        print("[+] Server ready")

    def start(self):
        print_banner("SECURE CHAT SERVER")

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(50)

            print(f"[+] Listening at {self.host}:{self.port}\n")

            while True:
                sock, addr = self.socket.accept()
                threading.Thread(
                    target=ClientHandler(sock, addr, self).handle,
                    daemon=True
                ).start()

        except KeyboardInterrupt:
            print("\n[*] Shutdown requested")
        finally:
            with suppress(Exception):
                if self.socket:
                    self.socket.close()
            self.db.disconnect()
            print("[+] Server stopped")


# ---------------------------------------------------------------------
#                              MAIN
# ---------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("SECURECHAT_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SECURECHAT_PORT", "5000")))
    args = parser.parse_args(argv)

    SecureChatServer(args.host, args.port).start()


if __name__ == "__main__":
    main()
