import importlib.util
import pathlib
import types


def load_server_module():
    """Dynamically load `app/server.py` as a module for testing."""
    root = pathlib.Path(__file__).resolve().parents[1]
    server_path = root / "app" / "server.py"

    spec = importlib.util.spec_from_file_location(
        "app_server_under_test", str(server_path)
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def test_server_accepts_and_invokes_handler(monkeypatch):
    server_mod = load_server_module()

    # ============================================================
    # Recording handler calls
    # ============================================================
    calls = []

    # ============================================================
    # Fake components to replace SSL/DB/network
    # ============================================================
    class FakeCert:
        def public_key(self):
            return object()

    class FakeCertValidator:
        def __init__(self, ca_path):
            self.ca_path = ca_path

        def validate_certificate(self, pem):
            return True, FakeCert(), ""

        def get_common_name(self, cert):
            return "Test Client"

    class FakeDB:
        def __init__(self):
            self.connected = False
            self.disconnected = False

        def connect(self):
            self.connected = True
            return True

        def disconnect(self):
            self.disconnected = True

        # Minimal stubs for code paths
        def register_user(self, *args, **kwargs):
            return True, "OK"

        def get_user_credentials(self, *args, **kwargs):
            return b"", "hash", "user"

        def update_last_login(self, *args, **kwargs):
            return None

    class FakeClientSocket:
        def setsockopt(self, *a, **k): pass
        def settimeout(self, *a, **k): pass
        def shutdown(self, *a, **k): pass
        def close(self): pass

    class FakeServerSocket:
        def __init__(self, *args, **kwargs):
            self.accept_count = 0
            self.closed = False

        def setsockopt(self, *a, **k): pass
        def bind(self, addr): self.addr = addr
        def listen(self, backlog): self.backlog = backlog

        def accept(self):
            if self.accept_count == 0:
                self.accept_count += 1
                return FakeClientSocket(), ("127.0.0.1", 60000)
            raise KeyboardInterrupt()  # Stop server loop

        def close(self):
            self.closed = True

    # ============================================================
    # Fake ClientHandler class generator (captures calls)
    # ============================================================
    def make_handler(recorder):
        class _FakeClientHandler:
            def __init__(self, sock, addr, server):
                self.sock = sock
                self.addr = addr
                self.server = server

            def handle(self):
                recorder.append(("handle_called", self.addr))

        return _FakeClientHandler

    # ============================================================
    # Monkeypatch everything the server depends on
    # ============================================================
    monkeypatch.setattr(server_mod, "load_private_key", lambda *_: object())
    monkeypatch.setattr(server_mod, "load_certificate", lambda *_: FakeCert())
    monkeypatch.setattr(server_mod, "CertificateValidator", FakeCertValidator)
    monkeypatch.setattr(server_mod, "DatabaseManager", FakeDB)

    # Silence banner
    monkeypatch.setattr(server_mod, "print_banner", lambda *_: None)

    # Fake socket factory
    monkeypatch.setattr(
        server_mod.socket, "socket", lambda *a, **k: FakeServerSocket()
    )

    # Replace real handler with fake one
    monkeypatch.setattr(server_mod, "ClientHandler", make_handler(calls))

    # ============================================================
    # Run the server: it should accept once, call handler, then exit
    # ============================================================
    srv = server_mod.SecureChatServer(host="127.0.0.1", port=0)
    srv.start()

    # ============================================================
    # Assertions
    # ============================================================
    assert calls == [
        ("handle_called", ("127.0.0.1", 60000))
    ], "Handler should be invoked exactly once with correct address"

if __name__ == "__main__":
    test_server_accepts_and_invokes_handler(monkeypatch=None)
    print("[✓] Server test complete")

