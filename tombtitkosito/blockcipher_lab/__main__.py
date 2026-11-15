"""CLI: python -m blockcipher_lab encrypt|decrypt -c CONFIG -i INPUT -o OUTPUT"""

import argparse
from pathlib import Path

from .config import load_config
from .file_crypto import encrypt_bytes, decrypt_bytes


def main() -> None:

    #strict modon meghatarozza az input alakját.
    parser = argparse.ArgumentParser(description="Általános oktatási tömbtitkosító")
    parser.add_argument("operation", choices=["encrypt", "decrypt"])
    parser.add_argument("-c", "--config", required=True, help="JSON konfiguráció")
    parser.add_argument("-i", "--input", required=True, help="Bemeneti fájl")
    parser.add_argument("-o", "--output", required=True, help="Kimeneti fájl")
    args = parser.parse_args()

    config = load_config(args.config)
    source = Path(args.input).read_bytes()
    if args.operation == "encrypt":
        output = encrypt_bytes(source, config)
    else:
        output = decrypt_bytes(source, config)
    Path(args.output).write_bytes(output)
    print(f"{args.operation}: {len(source)} -> {len(output)} bájt ({config.cipher}/{config.mode})")


if __name__ == "__main__":
    main()
