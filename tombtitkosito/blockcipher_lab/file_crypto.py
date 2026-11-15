"""Fájlszintű titkosítás és visszafejtés, eredeti hossz tárolásával.

A fejléc: 4 byte 'BCM1' + 8 byte eredeti bájthossz (big endian) + titkosított blokkok.
A fejléc nem hitelesített; a projekt oktatási célú.
"""

from .ciphers import make_cipher
from .modes import process_blocks
from .padding import add_padding, remove_padding

MAGIC = b"BCM1"
HEADER_SIZE = 12


def encrypt_bytes(plaintext: bytes, config) -> bytes:
    if len(plaintext) >= 1 << 64:
        raise ValueError("Túl nagy bemenet.")
    cipher = make_cipher(config)
    padded = add_padding(plaintext, config.blocksize, config.padding)
    encrypted = process_blocks(padded, cipher, config.mode, config.iv, encrypt=True)
    return MAGIC + len(plaintext).to_bytes(8, "big") + encrypted


def decrypt_bytes(data: bytes, config) -> bytes:
    if len(data) < HEADER_SIZE or data[:4] != MAGIC:
        raise ValueError("Érvénytelen fájlformátum (BCM1 fejléc hiányzik).")
    original_size = int.from_bytes(data[4:12], "big")
    ciphertext = data[HEADER_SIZE:]
    cipher = make_cipher(config)
    padded = process_blocks(ciphertext, cipher, config.mode, config.iv, encrypt=False)
    return remove_padding(padded, config.blocksize, config.padding, original_size)
