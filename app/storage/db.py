"""
Database Module - User management and authentication
"""

from __future__ import annotations
import os
from typing import Optional, Tuple
from contextlib import contextmanager

import mysql.connector
from mysql.connector import Error

import hashlib
import hmac
import re


class DatabaseManager:
    """Manages MySQL database connections and user-related operations."""

    def __init__(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
        port: Optional[int] = None,
        ssl_ca: Optional[str] = None,
        connect_immediately: bool = True,
    ):
        """
        Initialize database connection parameters.
        Environment variables are used as defaults if parameters are not provided:
          SECURECHAT_DB_HOST, SECURECHAT_DB_USER, SECURECHAT_DB_PASSWORD,
          SECURECHAT_DB_NAME, SECURECHAT_DB_PORT, SECURECHAT_DB_SSL_CA
        """
        self.host = host or os.getenv("SECURECHAT_DB_HOST", "localhost")
        self.user = user or os.getenv("SECURECHAT_DB_USER", "securechat_user")
        self.password = password or os.getenv("SECURECHAT_DB_PASSWORD", "")
        self.database = database or os.getenv("SECURECHAT_DB_NAME", "securechat")
        self.port = int(port or os.getenv("SECURECHAT_DB_PORT", "3306"))
        self.ssl_ca = ssl_ca or os.getenv("SECURECHAT_DB_SSL_CA")

        self.connection: Optional[mysql.connector.MySQLConnection] = None
        if connect_immediately:
            self.connect()

    def connect(self) -> bool:
        """Establish database connection."""
        try:
            conn_params = {
                "host": self.host,
                "user": self.user,
                "password": self.password,
                "database": self.database,
                "port": self.port,
                "connection_timeout": 5,
            }
            if self.ssl_ca:
                conn_params.update(
                    {
                        "ssl_ca": self.ssl_ca,
                        "ssl_verify_cert": True,
                    }
                )
            self.connection = mysql.connector.connect(**conn_params)
            if self.connection.is_connected():
                print("[+] Database connected successfully")
                return True
            return False
        except Error as e:
            print(f"[-] Database connection error: {e}")
            self.connection = None
            return False

    def _ensure_connection(self) -> None:
        """Ensure the connection is alive; reconnect if needed."""
        if self.connection is None:
            self.connect()
            return
        try:
            self.connection.ping(reconnect=True, attempts=1, delay=0)
        except Error:
            self.connect()

    def disconnect(self) -> None:
        """Close the database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            self.connection = None
            print("[+] Database disconnected")

    @contextmanager
    def _cursor(self):
        """Context manager to yield a buffered cursor and close it after use."""
        self._ensure_connection()
        if not self.connection or not self.connection.is_connected():
            raise RuntimeError("Database not connected")
        cursor = self.connection.cursor(buffered=True)
        try:
            yield cursor
        finally:
            cursor.close()

    def user_exists(self, email: Optional[str] = None, username: Optional[str] = None) -> bool:
        """Check if a user exists by email or username."""
        if not email and not username:
            return False
        try:
            with self._cursor() as cursor:
                if email:
                    query = "SELECT id FROM users WHERE email = %s LIMIT 1"
                    cursor.execute(query, (email.lower(),))
                else:
                    query = "SELECT id FROM users WHERE username = %s LIMIT 1"
                    cursor.execute(query, (username,))
                return cursor.fetchone() is not None
        except Error as e:
            print(f"[-] Error checking user existence: {e}")
            return False

    def register_user(self, email: str, username: str, salt: bytes, pwd_hash: str) -> Tuple[bool, str]:
        """
        Register a new user.

        Args:
            email: User email
            username: Username
            salt: 16-byte salt (bytes)
            pwd_hash: SHA-256 password hash (hex string)

        Returns:
            Tuple(success: bool, message: str)
        """
        try:
            email_norm = email.lower().strip()
            username_norm = username.strip()

            if not email_norm or not username_norm:
                return False, "Email and username are required"
            if not isinstance(salt, (bytes, bytearray)):
                return False, "Salt must be bytes"

            if self.user_exists(email=email_norm):
                return False, "Email already registered"
            if self.user_exists(username=username_norm):
                return False, "Username already taken"

            with self._cursor() as cursor:
                query = """
                    INSERT INTO users (email, username, salt, pwd_hash)
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(query, (email_norm, username_norm, salt, pwd_hash))
            self.connection.commit()
            print(f"[+] User registered: {username_norm}")
            return True, "Registration successful"
        except Error as e:
            try:
                if self.connection and self.connection.in_transaction:
                    self.connection.rollback()
            except Exception:
                pass
            print(f"[-] Registration error: {e}")
            return False, f"Registration failed: {e}"

    def get_user_credentials(self, email: str) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Retrieve the salt and password hash for a user by email.

        Returns:
            Tuple(salt: bytes or None, pwd_hash: str or None)
        """
        try:
            with self._cursor() as cursor:
                query = "SELECT salt, pwd_hash FROM users WHERE email = %s LIMIT 1"
                cursor.execute(query, (email.lower(),))
                row = cursor.fetchone()
                if row:
                    return row[0], row[1]
                return None, None
        except Error as e:
            print(f"[-] Error fetching credentials: {e}")
            return None, None

    def update_last_login(self, email: str) -> bool:
        """
        Update the last_login timestamp for a user.

        Returns:
            True if a row was updated, else False.
        """
        try:
            with self._cursor() as cursor:
                query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = %s"
                cursor.execute(query, (email.lower(),))
            self.connection.commit()
            return cursor.rowcount > 0
        except Error as e:
            print(f"[-] Error updating last login: {e}")
            try:
                if self.connection and self.connection.in_transaction:
                    self.connection.rollback()
            except Exception:
                pass
            return False

"""
User Manager Module
Handles user registration and authentication
"""

class UserManager:
    """Manages user authentication operations"""

    # KDF parameters
    SALT_BYTES = 16
    PBKDF2_ALG = "sha256"
    PBKDF2_ITERATIONS = 260_000
    PBKDF2_DKLEN = 32  # 256-bit
    PBKDF2_PREFIX = "pbkdf2"  # marker added to stored hash for algorithm/versioning

    EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,50}$")

    def __init__(self, db_manager, pepper: Optional[bytes] = None):
        """
        Initialize UserManager

        Args:
            db_manager: DatabaseManager instance
            pepper: Optional application-level secret added to password (bytes).
                    If not provided, reads SECURECHAT_PWD_PEPPER from env (UTF-8).
        """
        self.db = db_manager
        if pepper is not None:
            self.pepper = pepper
        else:
            env_pepper = os.environ.get("SECURECHAT_PWD_PEPPER")
            self.pepper = env_pepper.encode("utf-8") if env_pepper else None

    @staticmethod
    def generate_salt(length: int = SALT_BYTES) -> bytes:
        """Generate cryptographically secure random salt."""
        return os.urandom(length)

    def _derive_pbkdf2(self, salt: bytes, password: str, iterations: int | None = None, dklen: int | None = None) -> bytes:
        """Derive a key using PBKDF2-HMAC-SHA256 with optional pepper."""
        iterations = iterations or self.PBKDF2_ITERATIONS
        dklen = dklen or self.PBKDF2_DKLEN
        pwd_bytes = password.encode("utf-8")
        if self.pepper:
            pwd_bytes += self.pepper
        return hashlib.pbkdf2_hmac(self.PBKDF2_ALG, pwd_bytes, salt, iterations, dklen=dklen)

    def hash_password(self, salt: bytes, password: str) -> str:
        """
        Hash password using PBKDF2-HMAC-SHA256.
        Returns a versioned string: pbkdf2$sha256$<iterations>$<dklen>$<hex>
        """
        dk = self._derive_pbkdf2(salt, password)
        return f"{self.PBKDF2_PREFIX}${self.PBKDF2_ALG}${self.PBKDF2_ITERATIONS}${self.PBKDF2_DKLEN}${dk.hex()}"

    def _verify_pbkdf2_string(self, salt: bytes, stored_hash: str, password: str) -> bool:
        """Verify password against a versioned PBKDF2 stored hash."""
        try:
            prefix, alg, iters_s, dklen_s, hex_digest = stored_hash.split("$", 4)
            if prefix != self.PBKDF2_PREFIX or alg != self.PBKDF2_ALG:
                return False
            iters = int(iters_s)
            dklen = int(dklen_s)
        except Exception:
            return False

        dk = self._derive_pbkdf2(salt, password, iterations=iters, dklen=dklen)
        return hmac.compare_digest(dk.hex(), hex_digest)

    @staticmethod
    def _legacy_sha256(salt: bytes, password: str) -> str:
        """Legacy hash: hex(sha256(salt || password_utf8))"""
        return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()

    def verify_password(self, stored_salt: bytes, stored_hash: str, provided_password: str) -> bool:
        """
        Verify password using constant-time comparison.
        Supports both PBKDF2 (new) and legacy SHA-256(salt+password).
        """
        if isinstance(stored_hash, bytes):
            try:
                stored_hash = stored_hash.decode("utf-8")
            except Exception:
                return False

        if stored_hash.startswith(f"{self.PBKDF2_PREFIX}$"):
            return self._verify_pbkdf2_string(stored_salt, stored_hash, provided_password)

        # Fallback: legacy scheme
        legacy = self._legacy_sha256(stored_salt, provided_password)
        return hmac.compare_digest(legacy, stored_hash)

    @classmethod
    def validate_email(cls, email: str) -> bool:
        """Basic email validation."""
        return bool(cls.EMAIL_RE.match(email))

    @classmethod
    def validate_username(cls, username: str) -> bool:
        """Username validation (alphanumeric + underscore, 3-50 chars)."""
        return bool(cls.USERNAME_RE.match(username))

    @staticmethod
    def validate_password(password: str) -> bool:
        """Password strength (min 8 chars)."""
        return len(password) >= 8

    def register(self, email: str, username: str, password: str) -> Tuple[bool, str, Optional[bytes]]:
        """
        Register a new user.

        Returns:
            (success, message, salt or None)
        """
        # Validate inputs
        if not self.validate_email(email):
            return False, "Invalid email format", None
        if not self.validate_username(username):
            return False, "Invalid username (3-50 alphanumeric characters)", None
        if not self.validate_password(password):
            return False, "Password must be at least 8 characters", None

        # Generate salt and hash
        salt = self.generate_salt()
        pwd_hash = self.hash_password(salt, password)

        # Store in database
        success, message = self.db.register_user(email, username, salt, pwd_hash)
        if success:
            return True, message, salt
        return False, message, None

    def authenticate(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Authenticate user login.

        Returns:
            (success, message)
        """
        if not self.validate_email(email):
            return False, "Invalid email format"

        stored_salt, stored_hash = self.db.get_user_credentials(email)
        if stored_salt is None or stored_hash is None:
            return False, "User not found"

        if self.verify_password(stored_salt, stored_hash, password):
            self.db.update_last_login(email)
            return True, "Authentication successful"
        return False, "Invalid password"