"""Öt működési mód általános encrypt_block/decrypt_block primitívvel."""


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def process_blocks(data: bytes, cipher, mode: str, iv: bytes | None, encrypt: bool) -> bytes:
    if mode not in {"ECB", "CBC", "CFB", "OFB", "CTR"}:
        raise ValueError(f"Ismeretlen működési mód: {mode}")
    bs = cipher.blocksize
    if len(data) % bs:
        raise ValueError("Az adat hossza nem a blokk méretének többszöröse.")
    if mode != "ECB" and (iv is None or len(iv) != bs):
        raise ValueError("Hiányzó vagy hibás IV.")

    blocks = (data[i:i + bs] for i in range(0, len(data), bs))
    result = bytearray()
    prev = iv

    if mode == "CTR":
        counter = int.from_bytes(iv, "big")
        if counter + len(data) // bs > (1 << (8 * bs)):
            raise ValueError("A CTR számláló túlcsordulna: veszélyes kulcsáram-ismétlés.")

    for block in blocks:
        if mode == "ECB":
            out = cipher.encrypt_block(block) if encrypt else cipher.decrypt_block(block)
        elif mode == "CBC":
            if encrypt:
                out = cipher.encrypt_block(xor_bytes(block, prev))
                prev = out
            else:
                out = xor_bytes(cipher.decrypt_block(block), prev)
                prev = block
        elif mode == "CFB":  # Teljes blokkos CFB, AES-nél CFB128.
            out = xor_bytes(block, cipher.encrypt_block(prev))
            prev = out if encrypt else block
        elif mode == "OFB":
            prev = cipher.encrypt_block(prev)
            out = xor_bytes(block, prev)
        elif mode == "CTR":
            stream = cipher.encrypt_block(counter.to_bytes(bs, "big"))
            out = xor_bytes(block, stream)
            counter += 1
        else:
            raise ValueError(f"Ismeretlen működési mód: {mode}")
        result.extend(out)
    return bytes(result)
