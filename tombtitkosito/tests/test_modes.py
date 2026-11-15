import base64
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from blockcipher_lab.ciphers import AESBlocks, BinaryVigenere
from blockcipher_lab.modes import process_blocks
from blockcipher_lab.config import CipherConfig
from blockcipher_lab.file_crypto import encrypt_bytes, decrypt_bytes

KEY = bytes(range(16))
IV = bytes(range(16, 32))
ALL_MODES = ["ECB", "CBC", "CFB", "OFB", "CTR"]


def mk_config(cipher, mode, pad="SF", blocksize=16):
    key = KEY if cipher == "AES-128" else b"k0d123"
    obj = {
        "blocksize": blocksize,
        "cipher": cipher,
        "key": base64.b64encode(key).decode("ascii"),
        "mode": mode,
        "padding": pad,
    }
    if mode != "ECB":
        obj["iv"] = base64.b64encode(bytes((16 + i) % 256 for i in range(blocksize))).decode("ascii")
    return CipherConfig.from_dict(obj)


@pytest.mark.parametrize("cipher", ["VIGENERE-BIN", "AES-128"])
@pytest.mark.parametrize("mode", ALL_MODES)
@pytest.mark.parametrize("padding", ["ZERO", "DES", "SF"])
def test_small_roundtrip(cipher, mode, padding):
    config = mk_config(cipher, mode, padding)
    for original in [b"", b"Hello", bytes(range(16)), b"ABC\x00\x00"]:
        assert decrypt_bytes(encrypt_bytes(original, config), config) == original


def test_aes_fips_197_known_vector():
    aes = AESBlocks(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes.encrypt_block(plaintext) == expected
    assert aes.decrypt_block(expected) == plaintext


def test_binary_vigenere_mod_256():
    vig = BinaryVigenere(b"\x01\x02", 4)
    assert vig.encrypt_block(b"\xff\xfe\x01\x02") == b"\x00\x00\x02\x04"
    assert vig.decrypt_block(b"\x00\x00\x02\x04") == b"\xff\xfe\x01\x02"


@pytest.mark.parametrize("mode", ALL_MODES)
def test_aes_modes_match_library_reference(mode):
    data = bytes(range(48))
    primitives = AESBlocks(KEY)
    actual = process_blocks(data, primitives, mode, None if mode == "ECB" else IV, True)
    if mode == "ECB":
        reference_mode = modes.ECB()
    elif mode == "CBC":
        reference_mode = modes.CBC(IV)
    elif mode == "CFB":
        reference_mode = modes.CFB(IV)  # CFB128 (nem CFB8)
    elif mode == "OFB":
        reference_mode = modes.OFB(IV)
    else:
        reference_mode = modes.CTR(IV)
    expected = Cipher(algorithms.AES(KEY), reference_mode).encryptor().update(data)
    assert actual == expected
    assert process_blocks(actual, AESBlocks(KEY), mode, None if mode == "ECB" else IV, False) == data


def test_cbc_repeated_plaintext_different_ciphertext():
    block = b"a" * 16
    out = process_blocks(block * 2, AESBlocks(KEY), "CBC", IV, True)
    assert out[:16] != out[16:]


def test_ctr_counter_overflow_refused():
    with pytest.raises(ValueError, match="túlcsordulna"):
        process_blocks(b"z" * 32, AESBlocks(KEY), "CTR", b"\xff" * 16, True)


@pytest.mark.parametrize("cipher_name,key_len", [("AES-192", 24), ("AES-256", 32)])
def test_aes_other_key_sizes(cipher_name, key_len):
    obj = {
        "blocksize": 16, "cipher": cipher_name,
        "key": base64.b64encode(bytes(range(key_len))).decode(),
        "mode": "CBC", "iv": base64.b64encode(IV).decode(), "padding": "DES",
    }
    config = CipherConfig.from_dict(obj)
    original = b"different AES key lengths\x00\x00"
    assert decrypt_bytes(encrypt_bytes(original, config), config) == original


@pytest.mark.parametrize("blocksize", [1, 8, 16, 64])
@pytest.mark.parametrize("mode", ALL_MODES)
def test_custom_block_sizes_vigenere(blocksize, mode):
    config = mk_config("VIGENERE-BIN", mode, "SF", blocksize)
    data = bytes(range(111)) + b"\x00\x00"
    assert decrypt_bytes(encrypt_bytes(data, config), config) == data
