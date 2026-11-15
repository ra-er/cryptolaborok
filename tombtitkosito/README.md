# Általános tömbtitkosító — kriptográfia labor

.Az öt működési módot **saját Python-kóddal** implementáljuk. Az algoritmus egy cserélhető
`encrypt_block()` / `decrypt_block()` objektum: választható a **saját bináris Vigenère**
és a **cryptography** könyvtár szabványos **AES-128/192/256** megvalósítása. A csomag
10 kész JSON konfigurációt és pytest-teszteket tartalmaz.

A tesztcsomag 10 kombinációban titkosít és visszafejt egy **1 MB-nál nagyobb**
bináris adatot, majd byte-ról byte-ra és SHA-256-tal összehasonlítja.
További tesztek ellenőrzik a paddingot, a hibás konfigurációkat,
az AES hivatalos blokk tesztvektorát, valamint mind az öt saját mód eredményét
független könyvtári referenciával.

## Titkosítás / dekódolás

A `configs/` mappában `aes128_ecb.json` ... `aes128_ctr.json` és
`vigenere_ecb.json` ... `vigenere_ctr.json` minták vannak. Például:

```bash
python -m blockcipher_lab encrypt -c configs/aes128_cbc.json -i kep.png -o kep.enc
python -m blockcipher_lab decrypt -c configs/aes128_cbc.json -i kep.enc -o kep-vissza.png
```

Próba tetszőleges fájl helyett 1 MiB bináris adattal:

```bash
python -c "from pathlib import Path; Path('teszt.bin').write_bytes(bytes(range(256)) * 4096 + b'\\x00\\x00')"
python -m blockcipher_lab encrypt -c configs/vigenere_ctr.json -i teszt.bin -o teszt.enc
python -m blockcipher_lab decrypt -c configs/vigenere_ctr.json -i teszt.enc -o teszt-vissza.bin
```

Windows alatt `python` helyett szükség esetén `py` használható.

## Architektúra

- `config.py`: JSON betöltése, mezők, Base64, AES-kulcshossz és IV ellenőrzése.
- `ciphers.py`: a saját `BinaryVigenere`, valamint AES blokkprimitív.
- `padding.py`: `ZERO`, `DES` (`0x80` és utána nullák), `SF` (PKCS#7).
- `modes.py`: saját `ECB`, `CBC`, `CFB` (teljes blokkos CFB), `OFB`, `CTR` (big-endian).
- `file_crypto.py`: tetszőleges `bytes` titkosítása / visszafejtése.
- `__main__.py`: fájlokat kezelő CLI.
- `tests/`: automatikus pytest unit és integrációs tesztek.
- `.github/workflows/tests.yml`: push és pull request esetén GitHub Actions CI.

### Bináris Vigenère

Egy blokk minden `i` bájtjánál (a kulcs ciklikusan ismétlődik):

`C[i] = (P[i] + K[i mod len(K)]) mod 256`

`P[i] = (C[i] - K[i mod len(K)]) mod 256`

Ez **oktatási**, gyenge titkosító, nem biztonságos valódi titkokhoz.

### Padding és fájlformátum

Az egyszerűség és egységesség kedvéért minden módban a bemenet teljes blokkra
van kitöltve — még CFB/OFB/CTR esetén is, ahol technikailag a padding elhagyható.

- `ZERO`: nullbájtok a következő blokkhatárig (ha eleve teljes blokk, nincs plusz bájt).
- `DES`: `0x80`, majd nullabájtok; teljes blokknyi padding is lehet.
- `SF`: `n` darab `n` értékű byte (PKCS#7 / Schneier–Ferguson); teljes blokknyi padding is lehet.

A ZERO-padding önmagában **nem távolítható el egyértelműen**, ha az eredeti
fájl valódi `0x00` bájtokkal végződik. Emiatt a fájlformátum fejlécében az
**eredeti hossz** is szerepel:

`b"BCM1" | eredeti hossz 8 byte big-endian | titkosított blokkok`

A visszafejtés ugyanazt a JSON-konfigurációt igényli. A fejléc nem titkosított,
és sem a fejléc, sem az üzenet integritását nem védi a projekt.

### IV kezelés

Az ECB-hez nincs IV, más módoknál `blocksize` hosszúságú IV kötelező.
A példák fix IV-ket használnak **kizárólag a megismételhető tesztekhez**.
**Valódi titkosításnál a fix IV veszélyes**, különösen CTR/OFB módban:
azonos kulccsal nem szabad ugyanazt az IV-t újrahasználni.
Az ECB sem rejti el az ismétlődő blokkmintázatokat.
Valódi alkalmazásban célszerű hitelesített titkosítást (pl. AES-GCM) használni.

### Kódbeli használat

```python
from blockcipher_lab import load_config, encrypt_bytes, decrypt_bytes

config = load_config('configs/aes128_cbc.json')
secret = encrypt_bytes(b'hello\x00', config)
plain = decrypt_bytes(secret, config)
assert plain == b'hello\x00'
```

## GitHub Actions

A `.github/workflows/tests.yml` workflow a GitHubra push után automatikusan:
1. leklónozza a repót;
2. beállítja a Python-környezetet;
3. telepíti a függőségeket;
4. futtatja a `pytest` teljes tesztkészletét.

A GitHubon az **Actions** fülön a sikeres zöld jelzés a bizonyíték.

## Korlátok

A projekt oktatási labor, nem éles kriptográfiai eszköz. A CBC/CFB/OFB/CTR
módok saját implementációk, az AES primitív külső könyvtári. A JSON-séma
felsorol `DES`, `3DES` és `CUSTOM(student_id)` neveket is, de ezek ebben a
projektben **nincsenek implementálva**. Választható algoritmusok:
`VIGENERE-BIN`, `AES-128`, `AES-192`, `AES-256`.
