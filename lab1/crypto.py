#!/usr/bin/env python3
"""
File: crypto.py
Assignment 1: Cryptography

Caesar, Vigenere, Scytale és Rail Fence.
Hibakezelés, bináris fájlok és konzolmenü.
"""

from pathlib import Path


# Bemenetek ellenőrzése

def _ellenoriz_szoveg(szoveg):
    if not isinstance(szoveg, str):
        raise TypeError("Az üzenet szöveg (str) legyen.")


def _ellenoriz_pozitiv_egesz(ertek, nev):
    if isinstance(ertek, bool) or not isinstance(ertek, int):
        raise TypeError(f"A(z) {nev} egész szám legyen.")

    if ertek < 1:
        raise ValueError(f"A(z) {nev} legalább 1 legyen.")


def _ellenoriz_keyword(keyword):
    if not isinstance(keyword, str):
        raise TypeError("A kulcsszó szöveg legyen.")

    if not keyword:
        raise ValueError("A kulcsszó nem lehet üres.")

    if not keyword.isascii() or not keyword.isalpha():
        raise ValueError(
            "A kulcsszó csak az angol ábécé betűit tartalmazhatja."
        )

    return keyword.upper()


# Caesar Cipher

def encrypt_caesar(plaintext):
    _ellenoriz_szoveg(plaintext)
    eredmeny = []

    for char in plaintext:
        szam = ord(char) - ord('A')

        if szam < 0 or szam > 25:
            eredmeny.append(char)
        else:
            szam = (szam + 3) % 26
            eredmeny.append(chr(szam + ord('A')))

    return "".join(eredmeny)


def decrypt_caesar(ciphertext):
    _ellenoriz_szoveg(ciphertext)
    eredmeny = []

    for char in ciphertext:
        szam = ord(char) - ord('A')

        if szam < 0 or szam > 25:
            eredmeny.append(char)
        else:
            szam = (szam - 3) % 26
            eredmeny.append(chr(szam + ord('A')))

    return "".join(eredmeny)


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    _ellenoriz_szoveg(plaintext)
    keyword = _ellenoriz_keyword(keyword)

    eredmeny = []
    count = 0

    for char in plaintext:
        keyword_count = count % len(keyword)
        szam = ord(char) - ord('A')

        if szam < 0 or szam > 25:
            eredmeny.append(char)
        else:
            szam += ord(keyword[keyword_count]) - ord('A')
            eredmeny.append(chr(szam % 26 + ord('A')))

        # A te változatodhoz igazodva minden karakternél lépünk.
        count += 1

    return "".join(eredmeny)


def decrypt_vigenere(ciphertext, keyword):
    _ellenoriz_szoveg(ciphertext)
    keyword = _ellenoriz_keyword(keyword)

    eredmeny = []
    count = 0

    for char in ciphertext:
        keyword_count = count % len(keyword)
        szam = ord(char) - ord('A')

        if szam < 0 or szam > 25:
            eredmeny.append(char)
        else:
            szam -= ord(keyword[keyword_count]) - ord('A')
            eredmeny.append(chr(szam % 26 + ord('A')))

        count += 1

    return "".join(eredmeny)


# Scytale
# Szöveggel (str) és bináris adattal (bytes) is működik.

def _ellenoriz_scytale(adat, circumference):
    if not isinstance(adat, (str, bytes)):
        raise TypeError("A Scytale bemenete str vagy bytes legyen.")

    _ellenoriz_pozitiv_egesz(circumference, "kerület")


def encrypt_scytale(plaintext, circumference):
    _ellenoriz_scytale(plaintext, circumference)

    if circumference == 1 or circumference >= len(plaintext):
        return plaintext

    eredmeny = []

    for i in range(circumference):
        k = i

        while k < len(plaintext):
            eredmeny.append(plaintext[k])
            k += circumference

    if isinstance(plaintext, bytes):
        return bytes(eredmeny)

    return "".join(eredmeny)


def decrypt_scytale(ciphertext, circumference):
    _ellenoriz_scytale(ciphertext, circumference)

    if circumference == 1 or circumference >= len(ciphertext):
        return ciphertext

    plaintext = [None] * len(ciphertext)
    j = 0

    for i in range(circumference):
        k = i

        while k < len(ciphertext):
            plaintext[k] = ciphertext[j]
            j += 1
            k += circumference

    if isinstance(ciphertext, bytes):
        return bytes(plaintext)

    return "".join(plaintext)


# Rail Fence

def encrypt_railfence(plaintext, num_rails):
    _ellenoriz_szoveg(plaintext)
    _ellenoriz_pozitiv_egesz(num_rails, "sínek száma")

    if num_rails == 1 or num_rails >= len(plaintext):
        return plaintext

    sorok = [""] * num_rails
    sor = 0
    irany = 1

    for char in plaintext:
        sorok[sor] += char

        if sor == 0:
            irany = 1
        elif sor == num_rails - 1:
            irany = -1

        sor += irany

    return "".join(sorok)


def decrypt_railfence(ciphertext, num_rails):
    _ellenoriz_szoveg(ciphertext)
    _ellenoriz_pozitiv_egesz(num_rails, "sínek száma")

    if num_rails == 1 or num_rails >= len(ciphertext):
        return ciphertext

    poziciok = [[] for _ in range(num_rails)]
    sor = 0
    irany = 1

    for i in range(len(ciphertext)):
        poziciok[sor].append(i)

        if sor == 0:
            irany = 1
        elif sor == num_rails - 1:
            irany = -1

        sor += irany

    plaintext = [""] * len(ciphertext)
    j = 0

    for sor_pozicioi in poziciok:
        for i in sor_pozicioi:
            plaintext[i] = ciphertext[j]
            j += 1

    return "".join(plaintext)


# Bináris fájlok titkosítása és visszafejtése Scytale-lel

def _scytale_file(
    input_filename, output_filename, circumference, transform
):
    _ellenoriz_pozitiv_egesz(circumference, "kerület")

    if Path(input_filename).resolve() == Path(output_filename).resolve():
        raise ValueError("A bemeneti és kimeneti fájl különbözzön.")

    # rb: olvasás bináris módban, szöveggé alakítás nélkül.
    with open(input_filename, "rb") as file:
        adat = file.read()

    eredmeny = transform(adat, circumference)

    # xb: bináris írás új fájlba; meglévő fájlt nem ír felül.
    with open(output_filename, "xb") as file:
        file.write(eredmeny)


def encrypt_binary_file(
    input_filename, output_filename, circumference
):
    _scytale_file(
        input_filename,
        output_filename,
        circumference,
        encrypt_scytale
    )


def decrypt_binary_file(
    input_filename, output_filename, circumference
):
    _scytale_file(
        input_filename,
        output_filename,
        circumference,
        decrypt_scytale
    )


# Konzolmenü

def valasztas(kerdes, lehetosegek):
    while True:
        valasz = input(kerdes).strip().upper()

        if len(valasz) == 1 and valasz in lehetosegek:
            return valasz

        print("Érvénytelen választás: " + ", ".join(lehetosegek))


def console_menu():
    print("Welcome to the Cryptography Suite!")

    while True:
        print("----------------------------------")

        tool = valasztas(
            "(C)aesar, (V)igenere, (S)cytale, "
            "(R)ail Fence, (Q)kilépés? ",
            "CVSRQ"
        )

        if tool == "Q":
            break

        try:
            action = valasztas(
                "(E)ncrypt vagy (D)ecrypt? ",
                "ED"
            )

            mode = "T"

            if tool == "S":
                mode = valasztas(
                    "(T)ext vagy (B)ináris fájl? ",
                    "TB"
                )

            if mode == "B":
                source = input(
                    "Bemeneti fájl: "
                ).strip().strip('"')

                target = input(
                    "Kimeneti fájl: "
                ).strip().strip('"')

                circumference = int(input("Kerület: "))

                if action == "E":
                    transform = encrypt_binary_file
                else:
                    transform = decrypt_binary_file

                transform(source, target, circumference)
                print("Elmentve:", target)

            else:
                source = valasztas(
                    "Bemenet: (F)ájl vagy (S)tring? ",
                    "FS"
                )

                if source == "F":
                    filename = input(
                        "Fájlnév: "
                    ).strip().strip('"')

                    with open(
                        filename, "r", encoding="utf-8", newline=""
                    ) as file:
                        uzenet = file.read()

                else:
                    uzenet = input("Szöveg: ")

                # Ezek az eljárások a nagy A–Z betűket titkosítják.
                if tool in ("C", "V"):
                    uzenet = uzenet.upper()

                if tool == "C":
                    if action == "E":
                        transform = encrypt_caesar
                    else:
                        transform = decrypt_caesar

                    eredmeny = transform(uzenet)

                elif tool == "V":
                    keyword = input("Kulcsszó: ")

                    if action == "E":
                        transform = encrypt_vigenere
                    else:
                        transform = decrypt_vigenere

                    eredmeny = transform(uzenet, keyword)

                elif tool == "S":
                    circumference = int(input("Kerület: "))

                    if action == "E":
                        transform = encrypt_scytale
                    else:
                        transform = decrypt_scytale

                    eredmeny = transform(uzenet, circumference)

                else:
                    num_rails = int(input("Sínek száma: "))

                    if action == "E":
                        transform = encrypt_railfence
                    else:
                        transform = decrypt_railfence

                    eredmeny = transform(uzenet, num_rails)

                target = valasztas(
                    "Kimenet: (F)ájl vagy (S)tring? ",
                    "FS"
                )

                if target == "F":
                    filename = input(
                        "Kimeneti fájl: "
                    ).strip().strip('"')

                    with open(
                        filename, "x", encoding="utf-8", newline=""
                    ) as file:
                        file.write(eredmeny)

                    print("Elmentve:", filename)

                else:
                    print(eredmeny)

        except (TypeError, ValueError, OSError) as error:
            print("Hiba:", error)

        if valasztas("Újra? (Y/N) ", "YN") == "N":
            break

    print("Goodbye!")

if __name__ == "__main__":
    try:
        console_menu()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")