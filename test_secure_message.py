"""Check recovery, known SHA-256 output, and rejection of altered data."""

import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_message import decrypt_message, encrypt_message, sha256_hex, verify_integrity


class SecureMessageTests(unittest.TestCase):
    def test_sha256_known_value(self):
        self.assertEqual(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_round_trip_and_hash(self):
        for message in (b"", b"hello", "Hello, caf\u00e9! \U0001f512".encode("utf-8"), b"x" * 10000):
            with self.subTest(length=len(message)):
                key = AESGCM.generate_key(bit_length=256)
                nonce, ciphertext = encrypt_message(message, key)
                recovered = decrypt_message(nonce, ciphertext, key)
                self.assertEqual(recovered, message)
                self.assertTrue(verify_integrity(recovered, sha256_hex(message)))

    def test_changed_plaintext_fails_hash_check(self):
        self.assertFalse(verify_integrity(b"changed", sha256_hex(b"original")))

    def test_changed_ciphertext_is_rejected(self):
        key = AESGCM.generate_key(bit_length=256)
        nonce, ciphertext = encrypt_message(b"message", key)
        altered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        with self.assertRaises(InvalidTag):
            decrypt_message(nonce, altered, key)

    def test_wrong_key_is_rejected(self):
        key = AESGCM.generate_key(bit_length=256)
        nonce, ciphertext = encrypt_message(b"message", key)
        wrong_key = AESGCM.generate_key(bit_length=256)
        with self.assertRaises(InvalidTag):
            decrypt_message(nonce, ciphertext, wrong_key)

    def test_changed_nonce_is_rejected(self):
        key = AESGCM.generate_key(bit_length=256)
        nonce, ciphertext = encrypt_message(b"message", key)
        altered_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
        with self.assertRaises(InvalidTag):
            decrypt_message(altered_nonce, ciphertext, key)


if __name__ == "__main__":
    unittest.main()
