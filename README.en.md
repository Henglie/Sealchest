# Sealchest

> An Android tool to open VeraCrypt encrypted containers without root. Pure user space, nothing ever hits the disk in plaintext.

[中文版 README](README.md)

Sealchest (Chinese name 匿匣) is an Android app that lets you open VeraCrypt / TrueCrypt encrypted containers on a phone **without root**, and browse the files inside.

## How it works without root

Desktop VeraCrypt relies on a kernel driver to mount the container as a virtual disk. That is impossible on a non-rooted Android device. Sealchest takes a pure user-space path instead:

1. Parse the volume header inside the app — read the salt, derive the header key with PBKDF2, decrypt the header, extract the master key, and build the XTS decryption context;
2. The container holds an ordinary file system; Sealchest reads that file system itself, in user space;
3. Expose the decrypted file system through Android's **SAF (Storage Access Framework) DocumentsProvider** and a built-in browser, so the system file picker and other apps can read it like a normal folder.

Sectors are decrypted on demand — only the sector being read is decrypted. The whole container is never written out or unpacked to disk. That is the core of the no-root approach.

## Current capabilities

- Open containers **read + write** (write-back interoperability with desktop VeraCrypt)
- Inner file system: FAT12 / FAT16 / FAT32 (exFAT and NTFS are on the roadmap)
- Ciphers: AES, Serpent, Twofish, Camellia, Kuznyechik and their cascades (all compiled in)
- Hash / KDF: SHA-256, SHA-512, Whirlpool, Streebog, BLAKE2s, Argon2id
- Built-in file browser: navigate, preview (image / text), export, open-with
- Also exposed to the system through SAF for any SAF-aware app

## Compatibility

- Minimum Android 6.0 (API 23), covering devices from 2015 onward
- ABIs: arm64-v8a, armeabi-v7a, x86_64 (emulator)
- UI languages: Chinese and English (Chinese system locale → Chinese, everything else → English)

## Crypto core and license

Sealchest's crypto core is ported from the open-source [VeraCrypt](https://www.veracrypt.fr/) (the pure-C implementation under `src/Crypto`, `src/Volume`, `src/Common`), under its dual license:

- **Apache License 2.0** (AM Crypto modifications)
- **TrueCrypt License 3.0** (inherited from TrueCrypt 7.1a)

Sealchest is an independent product. It is not affiliated with, and does not impersonate, the VeraCrypt or TrueCrypt projects. All original copyright notices are kept under `third_party/VeraCrypt`.

## Author

Henglie / EternalBlaze — <https://github.com/Henglie/Sealchest>
