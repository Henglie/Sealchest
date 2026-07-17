<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="Sealchest logo" />
</p>

<h1 align="center">Sealchest</h1>

<p align="center">
  An Android tool to open VeraCrypt / TrueCrypt encrypted containers <b>without root</b>. Pure user space, nothing ever hits the disk in plaintext.
</p>

<p align="center">
  <a href="https://github.com/Henglie/Sealchest/stargazers"><img src="https://img.shields.io/github/stars/Henglie/Sealchest?style=flat-square" alt="GitHub stars" /></a>
  <a href="https://github.com/Henglie/Sealchest/network/members"><img src="https://img.shields.io/github/forks/Henglie/Sealchest?style=flat-square" alt="GitHub forks" /></a>
  <a href="https://github.com/Henglie/Sealchest/releases"><img src="https://img.shields.io/github/v/release/Henglie/Sealchest?style=flat-square" alt="GitHub release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Henglie/Sealchest?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <a href="https://github.com/Henglie/Sealchest/issues"><img src="https://img.shields.io/github/issues/Henglie/Sealchest?style=flat-square" alt="GitHub issues" /></a>
  <a href="https://github.com/Henglie/Sealchest/pulls"><img src="https://img.shields.io/github/issues-pr/Henglie/Sealchest?style=flat-square" alt="GitHub pull requests" /></a>
  <img src="https://img.shields.io/badge/Android-6.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white" alt="Android 6.0+" />
</p>

<p align="center">
  <a href="README.md">中文版 README</a>
</p>

> [!WARNING]
> Trust in an encryption tool rests on interoperability — always verify Sealchest-written containers in **desktop VeraCrypt**, and back up important data first. If you hit a bug, compatibility issue, or unexpected behavior, please report it promptly — open an Issue with reproduction steps, logs, screenshots, and your system version.

Sealchest (Chinese name 匿匣) is an Android app that lets you open VeraCrypt / TrueCrypt encrypted containers on a phone **without root**, and browse the files inside.

## How it works without root

Desktop VeraCrypt relies on a kernel driver to mount the container as a virtual disk. That is impossible on a non-rooted Android device. Sealchest takes a pure user-space path instead:

1. Parse the volume header inside the app — read the salt, derive the header key with PBKDF2, decrypt the header, extract the master key, and build the XTS decryption context;
2. The container holds an ordinary file system; Sealchest reads that file system itself, in user space;
3. Expose the decrypted file system through Android's **SAF (Storage Access Framework) DocumentsProvider** and a built-in browser, so the system file picker and other apps can read it like a normal folder.

Sectors are decrypted on demand — only the sector being read is decrypted. The whole container is never written out or unpacked to disk. That is the core of the no-root approach.

## Guiding principle

Sealchest is a strict Android parser for VeraCrypt containers. Its crypto and volume-format behavior must be **byte-for-byte identical** to desktop VeraCrypt, and the only criterion is **interoperability**: containers written by Sealchest open in desktop VeraCrypt, and containers written by desktop VeraCrypt read in Sealchest. The cryptographic implementation uses only upstream VeraCrypt C sources — never self-written, never modified. Only the volume-format spec (keyfile mixing, header layout, file-system structures) is reimplemented in Kotlin, with the upstream source noted in comments.

## Current capabilities

- **Open containers** — read + write (create / overwrite / delete files, changes are encrypted back into the container and open cleanly in desktop VeraCrypt)
- **Inner file systems** — FAT12 / FAT16 / FAT32 · exFAT · NTFS (all self-implemented read/write, no third-party FS library)
- **Ciphers** — AES, Serpent, Twofish, Camellia, Kuznyechik and their cascades (all compiled in)
- **Hash / KDF** — SHA-256, SHA-512, Whirlpool, Streebog, BLAKE2s, Argon2id
- **Volume operations** — create new containers (entropy collection + finger painting + random-pool visualization), change password / PIM / PRF / keyfiles, hidden-volume unlock and creation, header backup & restore (rescue), volume expansion
- **Keyfile unlock** — byte-for-byte reimplementation of VeraCrypt KeyFilesApply
- **Built-in file browser** — directory navigation, image / text preview, encrypted gallery and media playback, export to phone, open-with
- **SAF exposure** — any SAF-aware app can read files inside the container
- **Security hardening** — Argon2id PIN gate, Panic PIN instant wipe, biometric unlock, auto-lock (timeout / screen-off / background), foreground service to stay alive while mounted
- **UI** — Material You dynamic color + optional accent color + dark mode; **16 languages** (Chinese, English, French, German, Spanish, Japanese, Korean, Russian, Italian, Portuguese, Dutch, Arabic, Hindi, Turkish, Polish, Vietnamese — including Arabic RTL)

## Compatibility

- Minimum Android 6.0 (API 23), covering devices from 2015 onward
- ABIs: arm64-v8a, armeabi-v7a, x86_64 (emulator)

## Out of scope (Android form-factor boundary)

- Hidden operating system / pre-boot authentication of the system disk: the Android boot chain is fundamentally different from desktop, so this is excluded.
- Kernel-level mounting (dm-crypt / FUSE kernel module): impossible from a pure app layer.

## Crypto core and license

Sealchest's own code is licensed under **Apache License 2.0** — full text in [`LICENSE`](LICENSE) at the repo root.

The crypto core is ported from the open-source [VeraCrypt](https://www.veracrypt.fr/) (the pure-C implementation under `src/Crypto`, `src/Volume`, `src/Common`), under its original dual license:

- **Apache License 2.0** (AM Crypto modifications)
- **TrueCrypt License 3.0** (inherited from TrueCrypt 7.1a)

Sealchest is an independent product. It is not affiliated with, and does not impersonate, the VeraCrypt or TrueCrypt projects. All original copyright notices are kept under `third_party/VeraCrypt`.

## Author

Henglie / EternalBlaze — <https://github.com/Henglie/Sealchest>

## Keywords

<sub>VeraCrypt Android · TrueCrypt Android · open VeraCrypt on Android · no-root mount · encrypted container · encrypted volume · on-the-fly decryption · userspace filesystem · XTS · PBKDF2 · Argon2id · AES Serpent Twofish Camellia Kuznyechik · SHA-512 Whirlpool Streebog BLAKE2s · FAT exFAT NTFS · hidden volume · plausible deniability · keyfile · SAF DocumentsProvider · no plaintext on disk · Android encryption app · veracrypt mobile · encrypted file manager · privacy</sub>
