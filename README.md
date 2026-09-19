# Module 4 Midterm: Secure Data Transmission

A small Python application that accepts a message, hashes it with SHA-256,
encrypts it with AES-256-GCM, decrypts it, and compares the recovered message's
hash with the original. The sender and receiver are simulated in one local run.

## Start here

Open a terminal in this project folder. Python 3.11 or newer is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe secure_message.py
```

Enter a sample message when prompted. The program displays the original hash,
encrypted content, decrypted message, recovered hash, and a PASS result.
Base64 is used only to display the binary nonce and ciphertext; it is not the
encryption algorithm. Use a practice message because plaintext appears onscreen.

On macOS or Linux, use `.venv/bin/python` in place of
`.\.venv\Scripts\python.exe` after creating the environment.

### Quick demonstrations and tests

```powershell
.\.venv\Scripts\python.exe secure_message.py --demo
.\.venv\Scripts\python.exe secure_message.py --demo --tamper
.\.venv\Scripts\python.exe -m unittest -v
```

The first command completes the normal process. The second deliberately changes
one byte of ciphertext and shows that decryption rejects it. The tests also
cover a known SHA-256 value, empty and Unicode messages, a longer message,
a changed plaintext hash, the wrong key, and a changed nonce.

## How the code meets the detailed instructions

| Requirement | Implementation |
| --- | --- |
| Accept user input | `main()` prompts for a message |
| SHA-256 hashing | `sha256_hex()` hashes the UTF-8 message bytes |
| Symmetric encryption | `encrypt_message()` uses AES-256-GCM |
| Decryption | `decrypt_message()` uses the same secret key |
| Compare hashes | `verify_integrity()` compares the recovered hash with the original |
| Explain CIA and randomness | Sections below |
| One-minute screen recording | Separate demonstration of input, encryption, decryption, and hash comparison |

## Confidentiality, integrity, and availability

**Confidentiality:** AES encrypts the message with a secret key. The key stays in
memory and is neither printed nor written to disk. The visible ciphertext cannot
be decrypted without the correct key. This demo intentionally shows the input
and recovered text so the process can be explained.

**Integrity:** SHA-256 fingerprints are calculated before encryption and after
decryption, then compared. A matching result checks that the recovered bytes
match the original. The original hash is trusted because it remains in the same
local process. An ordinary hash alone cannot authenticate a sender: an attacker
who can replace both a message and its hash can calculate a new hash. AES-GCM's
authentication tag provides the additional check against ciphertext tampering.

**Availability:** The script runs locally after its dependency is installed, so
the demonstration does not require an online service. Setup instructions and
tests make it easier to reproduce and recover the application. Encryption itself
does not guarantee availability. This demo keeps its key only for the current
run; closing the program loses it. A real application would need protected key
storage, backups, recovery procedures, and reliable infrastructure.

## Entropy and key generation

Entropy describes unpredictability. Each run calls
`AESGCM.generate_key(bit_length=256)` to produce a random 256-bit key using the
library's secure random generation. Predictable keys, such as keys derived
directly from a name or timestamp, would be easier to guess.

Each encryption also uses `os.urandom(12)` to create a 96-bit nonce. The nonce
does not need to be secret, but it must not repeat with the same AES-GCM key.
This program generates a new key for each run and encrypts one message with it.
The key and nonce are generated using cryptographically secure randomness,
not Python's general-purpose `random` module.

## Scope

This application demonstrates the encryption and hashing workflow locally.
It does not perform a network transfer, persist messages, exchange keys, or
implement user accounts.

## Reference

[Cryptography: AES-GCM documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
