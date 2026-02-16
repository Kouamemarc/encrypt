
SecureBank File Encryptor

Outil de chiffrement/déchiffrement de fichiers sécurisé utilisant AES-256-GCM avec dérivation de clé PBKDF2.

Ce projet a été développé dans le cadre du TP cybersécurité SecureBank afin de protéger les sauvegardes sensibles avant leur envoi vers le cloud.

Fonctionnalités

Chiffrement AES-256-GCM (confidentialité + intégrité)

Dérivation de clé PBKDF2 (100 000 itérations)

Détection automatique :

clé incorrecte

fichier corrompu

Compression optionnelle (gzip)

CLI simple avec argparse

Format fichier sécurisé :

[salt 16 bytes][nonce 12 bytes][tag 16 bytes][ciphertext]

Installation
1. Cloner le projet
git clone https://github.com/votre_repo/securebank-encryptor.git
cd securebank-encryptor

2. Installer les dépendances
pip install cryptography


(optionnel)

pip install tqdm

Utilisation
Chiffrement
python file_encryptor.py encrypt test.txt test.enc --passphrase "SuperSecret123!"


Avec compression :

python file_encryptor.py encrypt test.txt test.enc --passphrase "SuperSecret123!" --compress

Déchiffrement
python file_encryptor.py decrypt test.enc test_decrypted.txt --passphrase "SuperSecret123!"


Avec décompression :

python file_encryptor.py decrypt test.enc test_decrypted.txt --passphrase "SuperSecret123!" --decompress

Tests

Créer un fichier test

echo "IBAN: FR76XXXXXXXXXXXX" > test.txt


Chiffrer

python file_encryptor.py encrypt test.txt test.enc --passphrase "SuperSecret123!"


Vérifier qu’il est illisible

cat test.enc


Déchiffrer

python file_encryptor.py decrypt test.enc test_decrypted.txt --passphrase "SuperSecret123!"


Comparer

diff test.txt test_decrypted.txt

Sécurité

AES-GCM assure l’intégrité et empêche la modification des données

PBKDF2 protège contre les attaques bruteforce sur la passphrase

Le salt est stocké dans le fichier (non secret, nécessaire pour dériver la clé)

Structure du projet
securebank-encryptor/
│
├── file_encryptor.py
├── README.md
└── test.txt

Auteur

Projet pédagogique cybersécurité — SecureBank Encryption Tool