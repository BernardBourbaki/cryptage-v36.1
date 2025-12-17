# Cryptage V37.1

**Secure encryption for text files and images**

## 🔐 Security

* **Algorithm**: AES-256-GCM (authenticated encryption)
* **Key derivation**: Argon2id (GPU-resistant)
* **Integrity**: GCM authentication tag
* **Format**: .crypt (proprietary but open specification)

## ⚠️ Important

### Version compatibility

* **V37 / V37.1**: Decrypts **ONLY** .crypt files created with V37+
* **V31-V36**: Use [Cryptage V36.1](https://github.com/BernardBourbaki/Cryptage/releases/tag/v36.1) to decrypt old files

### Limits

* **Maximum size**: 10 MB per file
* **Supported formats**:
  * Text: .txt
  * Images: .jpg, .png, .bmp
  * Encrypted: .crypt
* **Password**: No recovery possible - **use a password manager**

## 🚀 Installation

### Windows (Executable)

1. Download Cryptage_V37.exe from [Releases](https://github.com/BernardBourbaki/Cryptage/releases/latest)
2. Verify SHA256 checksum (see checksums.txt)
3. Run the executable (no installation required)

### Build from sources

**Requirements**:

* GCC (MinGW-w64 for Windows)
* OpenSSL 3.0+

**Command**:
gcc -o Cryptage_V37.exe Cryptage_Main.c Cryptage_Core.c Cryptage_UI_Common.c Cryptage_UI.c -lssl -lcrypto -lgdi32 -lcomctl32 -mwindows


## 📖 Usage

### Intuitive 3-step interface

#### To encrypt a file

1. **Create a strong password** (16+ characters recommended)
   * Use KeePass, Bitwarden or another manager
   * ⚠️ Never send the password with the encrypted file
2. **IMPORT** → **ENCRYPT** → **SAVE**
   * Click "IMPORT" and select your file
   * Click "ENCRYPT"
   * Click "SAVE" to create the .crypt file

#### To decrypt a file

1. **Enter the password** used for encryption
2. **IMPORT** → **DECRYPT** → **EXPORT**
   * Click "IMPORT" and select the .crypt file
   * Click "DECRYPT"
   * Click "EXPORT" (Text or Image depending on content)

### "Quick start" panel

Click the button at the bottom of the window to show/hide detailed instructions (fully visible in V37.1).

## 🔒 Security best practices

✅ **DO**:

* Use passwords of at least 16 characters
* Store passwords in a secure manager
* Test decryption **before** deleting the original
* Keep multiple copies of Cryptage_V37.exe

❌ **DO NOT**:

* Send the password AND encrypted file via the same channel
* Use the same password for all files
* Forget to verify decryption works
* Delete the original before testing

## 🛠️ Technical parameters

### Automatic configuration

The software automatically calculates the optimal memory parameter:

* **Formula**: 25% of available RAM
* **Minimum**: 4 MB (4096 KiB)
* **Maximum**: 1024 MB (1048576 KiB)
* **Default**: 16 MB if calculation fails

### `.crypt` file structure
[AAD - 24 bytes]

Version (4): 370 (decimal)
Reserved (16): future extensions
Argon2id memory (4): in KiB

[SALT - 32 bytes]
[NONCE - 12 bytes]
[CIPHERTEXT - variable]
[TAG - 16 bytes]


## 📊 What's new in V37.1 (December 17, 2025)

### Interface improvements (V37.1)

* ✨ Harmonious spacing between button groups (more airy and readable)
* ✨ "Quick start" panel fully visible with direct link to V36.1
* ✨ Taller window for better visual comfort

### V37 new features (compared to V36.1)

* ✨ Single simplified interface
* ✨ Automatic detection of previous versions
* ✨ Clearer error messages
* ✨ Limit increased to 10 MB (from 2 MB)
* ✨ Integrated help panel
* 🔧 Simplified code architecture

### Incompatibility

⚠️ **V37+ does NOT decrypt V31-V36 files**

To decrypt old files, download [Cryptage V36.1](https://github.com/BernardBourbaki/Cryptage/releases/tag/v36.1)

## 🐛 Known issues

None at the moment.

Report bugs via [Issues](https://github.com/BernardBourbaki/Cryptage/issues).

## 📜 License

This project is under MIT license. See [LICENSE](LICENSE) for details.

## 👤 Author

**Bernard DÉMARET**

* GitHub: [@BernardBourbaki](https://github.com/BernardBourbaki)

## 🙏 Thanks

* OpenSSL for cryptographic algorithms
* GitHub community for feedback and suggestions

## ⚖️ Disclaimer

This software is provided "as is", without warranty of any kind. The author cannot be held responsible for any data loss. **Always keep backups of your original files.**
