"""10 integrációs eset: 2 algoritmus × 5 mód; valódi, >=1 MiB bináris adat."""

import hashlib
from pathlib import Path
import pytest
from blockcipher_lab.config import load_config
from blockcipher_lab.file_crypto import encrypt_bytes, decrypt_bytes

CONFIGS = sorted(Path("configs").glob("*.json"))


@pytest.fixture(scope="module")
def large_binary():
    # Nem szükséges bináris tesztfájlt verziókezelésben tárolni.
    # Oszthatatlan méret, különféle byte-ok és NULL bájtok a végén.
    return (bytes(range(256)) * 4096) + b"\x00\xff\x00\x00\x01\x00\x00"


@pytest.mark.parametrize("config_file", CONFIGS, ids=lambda x: x.stem)
def test_1mib_binary_roundtrip(config_file, large_binary, tmp_path):
    assert len(large_binary) >= 1024 * 1024
    config = load_config(config_file)
    encrypted = encrypt_bytes(large_binary, config)
    original_file = tmp_path / "original.bin"
    cipher_file = tmp_path / "encrypted.bin"
    recovered_file = tmp_path / "recovered.bin"
    original_file.write_bytes(large_binary)
    cipher_file.write_bytes(encrypted)
    recovered_file.write_bytes(decrypt_bytes(cipher_file.read_bytes(), config))
    assert hashlib.sha256(original_file.read_bytes()).digest() == hashlib.sha256(recovered_file.read_bytes()).digest()
    assert recovered_file.read_bytes() == large_binary
    assert cipher_file.read_bytes() != large_binary


def test_exactly_ten_configurations():
    assert len(CONFIGS) == 10
    expected = {f"{c}_{m}" for c in ["aes128", "vigenere"] for m in ["ecb", "cbc", "cfb", "ofb", "ctr"]}
    assert {p.stem for p in CONFIGS} == expected
