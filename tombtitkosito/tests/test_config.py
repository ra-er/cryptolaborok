import base64
import json
from pathlib import Path
import pytest
from blockcipher_lab.config import CipherConfig, load_config


def example():
    return {
        "blocksize": 16,
        "cipher": "AES-128",
        "key": base64.b64encode(b"A" * 16).decode(),
        "mode": "CBC",
        "iv": base64.b64encode(b"B" * 16).decode(),
        "padding": "SF",
    }


def test_example_config_file():
    assert load_config(Path("configs") / "aes128_cbc.json").mode == "CBC"


@pytest.mark.parametrize("field,value", [
    ("blocksize", 0), ("blocksize", 65), ("blocksize", True),
    ("cipher", "ROTOR"), ("mode", "NO_MODE"),
    ("padding", "PKCS9"), ("key", "!!!"),
    ("iv", "!!!"),
])
def test_reject_invalid_fields(field, value):
    e = example()
    e[field] = value
    with pytest.raises((ValueError, TypeError)):
        CipherConfig.from_dict(e)


def test_iv_required():
    e = example()
    del e["iv"]
    with pytest.raises(ValueError, match="IV"):
        CipherConfig.from_dict(e)


def test_no_iv_for_ecb():
    e = example()
    e["mode"] = "ECB"
    with pytest.raises(ValueError, match="ECB"):
        CipherConfig.from_dict(e)


def test_no_extra_properties():
    e = example()
    e["unexpected"] = 3
    with pytest.raises(ValueError, match="ismeretlenek"):
        CipherConfig.from_dict(e)


def test_aes_length():
    e = example()
    e["key"] = base64.b64encode(b"short").decode()
    with pytest.raises(ValueError, match="kulcsa"):
        CipherConfig.from_dict(e)


@pytest.mark.parametrize("field", ["cipher", "mode", "padding"])
def test_reject_wrong_json_type(field):
    e = example()
    e[field] = []
    with pytest.raises(ValueError):
        CipherConfig.from_dict(e)
