"""Egyetlen blokkot titkosító és visszafejtő algoritmusok."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class BinaryVigenere:
    """Saját implementáció: byte-onként modulo 256 összeadás/kivonás.

    c[i] = (p[i] + k[i mod kulcshossz]) mod 256.
    Az index minden blokk elején 0-ra áll vissza. Oktatási célú, nem biztonságos.
    """

    def __init__(self, key: bytes, blocksize: int):
        self.blocksize = blocksize
        self._shifts = bytes(key[i % len(key)] for i in range(blocksize))

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.blocksize:
            raise ValueError("Helytelen blokk hossz.")
        return bytes((x + k) % 256 for x, k in zip(block, self._shifts))

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.blocksize:
            raise ValueError("Helytelen blokk hossz.")
        return bytes((x - k) % 256 for x, k in zip(block, self._shifts))


class AESBlocks:
    """A szabványos AES primitív a cryptography könyvtárból (ECB csak belül)."""

    blocksize = 16

    def __init__(self, key: bytes):
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        self._encryptor = cipher.encryptor()
        self._decryptor = cipher.decryptor()

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Az AES blokk pontosan 16 byte.")
        return self._encryptor.update(block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Az AES blokk pontosan 16 byte.")
        return self._decryptor.update(block)


def make_cipher(config):
    if config.cipher == "VIGENERE-BIN":
        return BinaryVigenere(config.key, config.blocksize)
    if config.cipher in {"AES-128", "AES-192", "AES-256"}:
        return AESBlocks(config.key)
    raise NotImplementedError(f"Nem implementált algoritmus: {config.cipher}")
