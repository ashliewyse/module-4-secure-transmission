"""Module 4: demonstrate SHA-256 hashing and AES-GCM encryption of a message."""

import argparse
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 fingerprint of the exact input bytes."""
    return hashlib.sha256(data).hexdigest()


def encrypt_message(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Return a fresh nonce and authenticated ciphertext (including its tag)."""
    # A nonce is public, but must never repeat with the same AES-GCM key.
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ciphertext


def decrypt_message(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Recover the message, or raise InvalidTag if authentication fails."""
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def verify_integrity(data: bytes, expected_hash: str) -> bool:
    """Compare the received data's hash with the trusted original hash."""
    return hmac.compare_digest(sha256_hex(data), expected_hash)


def run_demo(message: str, tamper: bool = False) -> int:
    """Simulate the sender and receiver locally; no network transfer occurs."""
    original = message.encode("utf-8")
    original_hash = sha256_hex(original)

    # The same secret key is used for encryption and decryption (symmetric AES).
    # Generate a new key each run. It is never printed or saved to a file.
    key = AESGCM.generate_key(bit_length=256)
    nonce, ciphertext = encrypt_message(original, key)

    print("\nModule 4 - Secure Message Demonstration")
    print("1. Original message:", message)
    print("2. Original SHA-256:", original_hash)
    print("3. Encryption: AES-256-GCM; a new random secret key was generated.")
    print("   Nonce (Base64):", base64.b64encode(nonce).decode("ascii"))
    print("   Ciphertext + tag (Base64):", base64.b64encode(ciphertext).decode("ascii"))

    if tamper:
        # Changing one byte simulates corruption or tampering during transfer.
        ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        print("   Demonstration: changed one byte of the encrypted content.")

    try:
        recovered = decrypt_message(nonce, ciphertext, key)
    except InvalidTag:
        print("4. Decryption rejected: authentication failed; no plaintext released.")
        print("   The content, key, or nonce may have changed.")
        if tamper:
            print("PASS: the deliberate tampering was detected.")
            return 0
        return 1

    print("4. Decrypted message:", recovered.decode("utf-8"))
    print("5. Decrypted SHA-256:", sha256_hex(recovered))
    if verify_integrity(recovered, original_hash):
        print("PASS: hashes match. The recovered message matches the original.")
        return 0
    print("FAIL: hashes do not match.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true", help="use a sample message")
    parser.add_argument("--tamper", action="store_true", help="show tampering detection")
    args = parser.parse_args()
    if args.demo:
        message = "My Module 4 message stays confidential and unchanged."
    else:
        try:
            message = input("Enter a sample message: ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 1
    return run_demo(message, tamper=args.tamper)


if __name__ == "__main__":
    raise SystemExit(main())
