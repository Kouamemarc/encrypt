#!/usr/bin/env python3
import os
import argparse
import struct
import sys
import gzip
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
ITERATIONS = 100_000
KEY_SIZE = 32  # AES-256


# --------------------------------------------------
# Dérivation de clé
# --------------------------------------------------
def generer_cle(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())


# --------------------------------------------------
# Chiffrement
# --------------------------------------------------
def chiffrer_fichier(fichier_entree, fichier_sortie, passphrase, compress=False):
    start = time.time()

    with open(fichier_entree, "rb") as f:
        data = f.read()

    original_size = len(data)

    if compress:
        data = gzip.compress(data)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = generer_cle(passphrase, salt)
    aesgcm = AESGCM(key)

    encrypted = aesgcm.encrypt(nonce, data, None)

    # encrypted = ciphertext + tag
    ciphertext = encrypted[:-TAG_SIZE]
    tag = encrypted[-TAG_SIZE:]

    with open(fichier_sortie, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    elapsed = time.time() - start

    print("Chiffrement terminé")
    print(f"Taille originale : {original_size} bytes")
    print(f"Taille chiffrée : {os.path.getsize(fichier_sortie)} bytes")
    print(f"Temps : {elapsed:.2f} s")


# --------------------------------------------------
# Déchiffrement
# --------------------------------------------------
def dechiffrer_fichier(fichier_entree, fichier_sortie, passphrase, decompress=False):
    try:
        with open(fichier_entree, "rb") as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            tag = f.read(TAG_SIZE)
            ciphertext = f.read()

        key = generer_cle(passphrase, salt)
        aesgcm = AESGCM(key)

        decrypted = aesgcm.decrypt(nonce, ciphertext + tag, None)

        if decompress:
            decrypted = gzip.decompress(decrypted)

        with open(fichier_sortie, "wb") as f:
            f.write(decrypted)

        print("Déchiffrement réussi")

    except Exception:
        print("Erreur : clé incorrecte ou fichier corrompu")
        sys.exit(1)


# --------------------------------------------------
# CLI
# --------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Outil AES-256-GCM de chiffrement de fichiers")
    sub = parser.add_subparsers(dest="command")

    enc = sub.add_parser("encrypt")
    enc.add_argument("input")
    enc.add_argument("output")
    enc.add_argument("--passphrase", required=True)
    enc.add_argument("--compress", action="store_true")

    dec = sub.add_parser("decrypt")
    dec.add_argument("input")
    dec.add_argument("output")
    dec.add_argument("--passphrase", required=True)
    dec.add_argument("--decompress", action="store_true")

    args = parser.parse_args()

    if args.command == "encrypt":
        chiffrer_fichier(args.input, args.output, args.passphrase, args.compress)
    elif args.command == "decrypt":
        dechiffrer_fichier(args.input, args.output, args.passphrase, args.decompress)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
