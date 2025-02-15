# Poor Man's KeyPass

A lightweight password manager that uses GPG encryption with support for hardware key storage on ESP32.

## Overview

This password manager provides a secure way to store and retrieve passwords using GPG encryption, with two possible setups:

1. **Trusted Machine Setup**
   - Full GPG implementation with both public and private keys
   - Suitable for your primary secure computer
   - Complete password management capabilities

2. **Standard Machine + Hardware Key Setup**
   - Public key operations on your computer
   - Private key stored securely on ESP32 hardware
   - Enhanced security through hardware key storage

## How It Works

1. Passwords are encrypted using GPG's public key encryption
2. Each password is stored in a separate encrypted file
3. Decryption requires:
   - Either full GPG access (Trusted Machine setup)
   - Or ESP32 hardware key (Standard Machine setup)

## Setup Instructions

### 1. Generate GPG Key Pair

```bash
gpg --full-generate-key
```
* choose RSA-2048
* no passphrase

## List keys and note the "long" key-id

```bash
 $ gpg --list-secret-key --keyid-format long

/home/david/.gnupg/pubring.kbx
------------------------------
sec   rsa2048/069ECFEC25327D7B 2025-01-26 [SC]
      E70262371AA68EF6D63D476B069ECFEC25327D7B
uid                 [ultimate] David Cermak (Personal) <xxxxx@xxxxxx.xxx>
ssb   rsa2048/69A16114A29E364C 2025-01-26 [E]
```

the long key-id is the number "069ECFEC25327D7B"
the ssb (subkey) id is "69A16114A29E364C" --> this will be used for converting to plain RSA keys

## Export to plain RSA key

```bash
gpg --export-secret-keys 69A16114A29E364C | openpgp2ssh 69A16114A29E364C > secret.pem

```

# Create the password file

```bash
echo "Super-secret-password" | gpg --compress-level 0 --encrypt --recipient 069ECFEC25327D7B  --output password.pgp
```

# Decrypt the password

## Get the encrypted session key

```bash
cargo run --bin extract-seip-content password.pgp
```
this parses openpgp packets and creates two files (encrypted binaries)
* `pkesk.bin` (asymmetrically encrypted session key)
* `encrypted.bin` (symmetrically encrypted message)

## Decrypt the session key

Lets decrypt the `pkesk.bin` directly with the RSA private key:

```bash
openssl rsautl -decrypt -in pkesk.bin -inkey secret.pem -out session_key.bin
```
check the session key:
```bash
~$ xxd session_key.bin
00000000: 09fa 2672 fd63 269a ab74 6e7d d8b5 f3ce  ..&r.c&..tn}....
00000010: 1e98 4d00 a25d ed0f efc3 0418 9d24 10af  ..M..].......$..
00000020: 850f db                                  ...
```
and compare with gpg extracted session key:
```bash
~$ gpg --show-session-key --decrypt password.pgp 
gpg: encrypted with 2048-bit RSA key, ID 69A16114A29E364C, created 2025-01-26
        .....
gpg: session key: '9:FA2672FD63269AAB746E7DD8B5F3CE1E984D00A25DED0FEFC304189D2410AF85'
```

## Use the session key to decrypt the message

export the session key
```bash
export KEY=FA2672FD63269AAB746E7DD8B5F3CE1E984D00A25DED0FEFC304189D2410AF85
```
and use the openssl command printed from `cargo run --bin extract-seip-content password.pgp`

```bash
~$ openssl enc -aes-256-cfb -d -K $KEY -iv D9218797E27FAD1931CFD8EB9E74EEE5 -in encrypted.bin
�
 ֋0L���=
v* �<�bg���Super-secret-password
�-�"���g
8�����E�~
```
