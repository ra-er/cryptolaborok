"""ZERO, DES (ISO/IEC 7816-4), SF (PKCS#7) kitöltés."""


def add_padding(data: bytes, blocksize: int, method: str) -> bytes:
    missing = (-len(data)) % blocksize
    if method == "ZERO":
        return data + b"\x00" * missing
    # DES és SF esetén még egy teljes blokkot is hozzáadunk, ha már osztható.
    n = missing if missing else blocksize
    if method == "DES":
        return data + b"\x80" + b"\x00" * (n - 1)
    if method == "SF":
        return data + bytes([n]) * n
    raise ValueError(f"Ismeretlen padding: {method}")


def remove_padding(data: bytes, blocksize: int, method: str, original_size: int) -> bytes:
    if len(data) % blocksize != 0 or original_size < 0 or original_size > len(data):
        raise ValueError("Hibás blokk-/eredeti méret.")
    if method == "ZERO":
        if any(data[original_size:]):
            raise ValueError("Hibás ZERO kitöltés.")
        return data[:original_size]  # Nullbájtos fájlvég is megőrizhető.
    if not data:
        raise ValueError("Hiányzó kitöltés.")
    if method == "DES":
        last = data.rfind(b"\x80")
        if last < 0 or not 1 <= len(data) - last <= blocksize or any(data[last + 1:]):
            raise ValueError("Hibás DES kitöltés.")
        result = data[:last]
    elif method == "SF":
        n = data[-1]
        if n < 1 or n > blocksize or data[-n:] != bytes([n]) * n:
            raise ValueError("Hibás SF kitöltés.")
        result = data[:-n]
    else:
        raise ValueError(f"Ismeretlen padding: {method}")
    if len(result) != original_size:
        raise ValueError("Az eredeti méret és a kitöltés nem egyezik.")
    return result
