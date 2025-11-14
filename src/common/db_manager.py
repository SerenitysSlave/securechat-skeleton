"""
Database Manager Module
Handles all MySQL operations for user management
"""

import os
from typing import Optional, Tuple
from contextlib import contextmanager

import mysql.connector
from mysql.connector import Error


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
