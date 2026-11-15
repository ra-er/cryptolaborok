"""JSON-konfiguráció beolvasása és ellenőrzése."""

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path

CIPHER_NAMES = {
    "AES-128", "AES-192", "AES-256", "DES", "3DES",
    "VIGENERE-BIN", "CUSTOM(student_id)",
}
MODES = {"ECB", "CBC", "CFB", "OFB", "CTR"}
PADDINGS = {"ZERO", "DES", "SF"}
FIELDS = {"blocksize", "cipher", "key", "mode", "iv", "padding"}


def _decode64(field: str, value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"A(z) '{field}' Base64-kódolt szöveg kell legyen.")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Érvénytelen Base64: {field}") from exc


@dataclass(frozen=True)
class CipherConfig:
    blocksize: int
    cipher: str
    key: bytes
    mode: str
    padding: str
    iv: bytes | None = None

    @classmethod
    def from_dict(cls, obj: dict) -> "CipherConfig":
        if not isinstance(obj, dict):
            raise ValueError("A JSON gyökere objektum kell legyen.")
        missing = {"blocksize", "cipher", "key", "mode", "padding"} - obj.keys()
        unexpected = obj.keys() - FIELDS
        if missing or unexpected:
            raise ValueError(f"Hiányzó mezők: {sorted(missing)}; ismeretlenek: {sorted(unexpected)}")
        blocksize = obj["blocksize"]
        if type(blocksize) is not int or not 1 <= blocksize <= 64:
            raise ValueError("A blocksize egész szám legyen 1 és 64 között.")
        cipher = obj["cipher"]
        mode = obj["mode"]
        padding = obj["padding"]
        if not isinstance(cipher, str) or cipher not in CIPHER_NAMES:
            raise ValueError(f"Ismeretlen cipher: {cipher}")
        if not isinstance(mode, str) or mode not in MODES:
            raise ValueError(f"Ismeretlen mode: {mode}")
        if not isinstance(padding, str) or padding not in PADDINGS:
            raise ValueError(f"Ismeretlen padding: {padding}")
        key = _decode64("key", obj["key"])
        if not key:
            raise ValueError("A kulcs nem lehet üres.")

        if cipher.startswith("AES-"):
            expected_key_length = int(cipher.split("-")[1]) // 8
            if len(key) != expected_key_length or blocksize != 16:
                raise ValueError(f"A(z) {cipher} kulcsa {expected_key_length} byte, blocksize=16.")
        elif cipher not in {"VIGENERE-BIN"}:
            raise NotImplementedError(
                "Ebben a megoldásban AES-128/192/256 és VIGENERE-BIN támogatott."
            )

        if mode == "ECB":
            if "iv" in obj:
                raise ValueError("ECB módban nem adható meg IV.")
            iv = None
        else:
            if "iv" not in obj:
                raise ValueError(f"A(z) {mode} módhoz IV szükséges.")
            iv = _decode64("iv", obj["iv"])
            if len(iv) != blocksize:
                raise ValueError(f"Az IV hossza pontosan {blocksize} byte kell legyen.")
        return cls(blocksize, cipher, key, mode, padding, iv)


def load_config(path: str | Path) -> CipherConfig:
    with open(path, "r", encoding="utf-8") as f:
        return CipherConfig.from_dict(json.load(f))
