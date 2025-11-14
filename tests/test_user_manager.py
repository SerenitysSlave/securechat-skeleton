#!/usr/bin/env python3
"""Test user management functionality"""

import sys
import uuid

sys.path.insert(0, '.')

# Try loading .env so SECURECHAT_DB_* are available
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

from app.storage.db import UserManager, DatabaseManager  # noqa: E402


def test_password_hashing():
    """Test PBKDF2 password hashing and verification"""

    print("=" * 60)
    print("[TEST 1] Password Hashing and Verification (PBKDF2-HMAC-SHA256)")
    print("=" * 60)

    um = UserManager(db_manager=None)  # db not needed for hashing tests

    # Generate salt
    salt = um.generate_salt()
    print(f"[+] Generated salt (16 bytes): {salt.hex()}")
    print(f"    Salt length: {len(salt)} bytes")

    # Hash password
    password = "MySecurePassword123!"
    pwd_hash = um.hash_password(salt, password)
    print(f"\n[+] Original password: {password}")
    print(f"[+] Stored hash: {pwd_hash}")

    # Check format prefix and properties
    assert pwd_hash.startswith("pbkdf2$sha256$"), "Hash should be versioned PBKDF2"
    parts = pwd_hash.split("$")
    assert len(parts) == 5, "Hash should have 5 parts: prefix, alg, iters, dklen, hex"
    _, _, iters_s, dklen_s, hex_digest = parts
    assert int(iters_s) >= 200_000, "PBKDF2 iterations should be strong"
    assert int(dklen_s) == 32, "PBKDF2 dklen should be 32 bytes"
    assert len(hex_digest) == 64, "Derived key hex should be 64 chars"

    # Verify correct password
    print("\n[*] Testing correct password verification...")
    is_valid = um.verify_password(salt, pwd_hash, password)
    print(f"[+] Verification result: {is_valid}")
    assert is_valid is True, "Correct password should verify"

    # Verify incorrect password
    print("\n[*] Testing incorrect password verification...")
    wrong_password = "WrongPassword123!"
    is_valid = um.verify_password(salt, pwd_hash, wrong_password)
    print(f"[+] Verification result: {is_valid}")
    assert is_valid is False, "Incorrect password should not verify"

    # Determinism with same salt+password
    print("\n[*] Hashing same password multiple times with same salt...")
    hashes = [um.hash_password(salt, password) for _ in range(3)]
    print("\n".join(f"    Hash {i+1}: {h}" for i, h in enumerate(hashes)))
    assert len(set(hashes)) == 1, "Same salt+password should produce same PBKDF2 string"

    # Different salt -> different hash
    different_salt = um.generate_salt()
    different_hash = um.hash_password(different_salt, password)
    assert different_hash != pwd_hash, "Different salt should produce different hash"

    print("\n[✓] Password hashing tests passed!\n")


def test_validation():
    """Test input validation functions"""

    print("=" * 60)
    print("[TEST 2] Input Validation")
    print("=" * 60)

    # Email validation tests
    print("\n[*] Email Validation Tests:")
    valid_emails = [
        "user@example.com",
        "john.doe@university.edu",
        "test_user+tag@domain.co.uk",
    ]
    invalid_emails = [
        "invalid.email",
        "@example.com",
        "user@",
        "user @example.com",
    ]

    for email in valid_emails:
        result = UserManager.validate_email(email)
        print(f"    {email:35} -> {'VALID' if result else 'INVALID'}")
        assert result is True, f"Should be valid: {email}"

    for email in invalid_emails:
        result = UserManager.validate_email(email)
        print(f"    {email:35} -> {'VALID' if result else 'INVALID'}")
        assert result is False, f"Should be invalid: {email}"

    # Username validation tests
    print("\n[*] Username Validation Tests:")
    valid_usernames = ["john_doe", "user123", "test_user_2024"]
    invalid_usernames = ["ab", "us", "user@name", "user name", "a" * 51]

    for username in valid_usernames:
        result = UserManager.validate_username(username)
        print(f"    {username:35} -> {'VALID' if result else 'INVALID'}")
        assert result is True, f"Should be valid: {username}"

    for username in invalid_usernames:
        result = UserManager.validate_username(username)
        print(f"    {username[:35]:35} -> INVALID")
        assert result is False, f"Should be invalid: {username}"

    # Password validation tests
    print("\n[*] Password Validation Tests:")
    valid_passwords = ["password123", "MySecurePass!", "12345678"]
    invalid_passwords = ["short", "1234567", ""]

    for password in valid_passwords:
        result = UserManager.validate_password(password)
        print(f"    {password:35} -> {'VALID' if result else 'INVALID'}")
        assert result is True, f"Should be valid: {password}"

    for password in invalid_passwords:
        result = UserManager.validate_password(password)
        print(f"    {password:35} -> INVALID (min 8 chars)")
        assert result is False, f"Should be invalid: {password}"

    print("\n[✓] Validation tests passed!\n")


def test_registration_and_login():
    """Test user registration and authentication with database"""

    print("=" * 60)
    print("[TEST 3] User Registration and Authentication")
    print("=" * 60)

    # Initialize database
    print("\n[*] Connecting to database...")
    db = DatabaseManager()
    if not db.connect():
        print("[-] Failed to connect to database. Skipping DB-backed test.")
        return False

    um = UserManager(db)

    # Unique user to avoid collisions between runs
    uniq = uuid.uuid4().hex[:8]
    test_email = f"testuser+{uniq}@example.com"
    test_username = f"testuser_{uniq}"
    test_password = "SecurePass123!"

    # Register
    print("\n[*] Testing user registration...")
    success, message, salt = um.register(test_email, test_username, test_password)
    print(f"[+] Registration result: {message}")
    assert success is True, f"Registration failed unexpectedly: {message}"
    assert salt and isinstance(salt, (bytes, bytearray)), "Salt not returned"

    # Duplicate registration (same email) should fail
    print("\n[*] Testing duplicate registration (same email, should fail)...")
    success_dup, message_dup, _ = um.register(test_email, test_username + "_alt", test_password)
    print(f"[+] Result: {message_dup}")
    assert success_dup is False, "Duplicate email should be rejected"

    # Successful login
    print("\n[*] Testing successful login...")
    ok, msg = um.authenticate(test_email, test_password)
    print(f"[+] Login result: {msg}")
    assert ok is True, "Valid credentials should authenticate"

    # Wrong password
    print("\n[*] Testing failed login (wrong password)...")
    ok, msg = um.authenticate(test_email, "WrongPassword123!")
    print(f"[+] Login result: {msg}")
    assert ok is False, "Invalid password should be rejected"

    # Non-existent user
    print("\n[*] Testing failed login (non-existent user)...")
    ok, msg = um.authenticate(f"nonexistent+{uniq}@example.com", test_password)
    print(f"[+] Login result: {msg}")
    assert ok is False, "Non-existent user should be rejected"

    db.disconnect()
    print("\n[✓] Registration and authentication tests passed!\n")
    return True

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("USER MANAGER TEST SUITE")
    print("=" * 60 + "\n")

    try:
        # Basic tests (no database required)
        test_password_hashing()
        test_validation()

        # Database tests (requires running MySQL and .env configured)
        ran_db_tests = test_registration_and_login()

        print("=" * 60)
        if ran_db_tests:
            print("ALL TESTS PASSED! ✓")
        else:
            print("CORE TESTS PASSED (DB tests skipped) ✓")
            print("=" * 60 + "\n")

    except AssertionError as e:
        print(f"\n[✗] TEST FAILED: {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[✗] ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()