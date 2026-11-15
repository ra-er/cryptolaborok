import pytest
from blockcipher_lab.padding import add_padding, remove_padding


@pytest.mark.parametrize("method", ["ZERO", "DES", "SF"])
@pytest.mark.parametrize("n", [0, 1, 7, 8, 15, 16, 17])
def test_padding_roundtrip(method, n):
    blocksize = 8
    original = bytes([i % 256 for i in range(n)]) + b"\x00\x00"
    padded = add_padding(original, blocksize, method)
    assert len(padded) % blocksize == 0
    assert remove_padding(padded, blocksize, method, len(original)) == original


def test_des_padding_has_one_one_bit_then_zero_bits():
    assert add_padding(b"abc", 8, "DES") == b"abc\x80\x00\x00\x00\x00"


def test_sf_padding_full_block():
    assert add_padding(b"12345678", 8, "SF") == b"12345678" + b"\x08" * 8


def test_zero_padding_ambiguous_without_original_size():
    original = b"hello\x00\x00"
    padded = add_padding(original, 8, "ZERO")
    assert remove_padding(padded, 8, "ZERO", len(original)) == original
