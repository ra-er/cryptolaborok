"""Oktatási célú, konfigurálható bájtsorozat-tömbtitkosító."""

from .config import CipherConfig, load_config
from .file_crypto import encrypt_bytes, decrypt_bytes

__all__ = ["CipherConfig", "load_config", "encrypt_bytes", "decrypt_bytes"]
