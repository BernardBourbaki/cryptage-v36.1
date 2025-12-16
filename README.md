# Cryptage V37

**Chiffrement sécurisé de fichiers texte et images**

[![Version](https://img.shields.io/badge/version-37.0-blue.svg)](https://github.com/BernardBourbaki/cryptage-v37/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0+-red.svg)](https://www.openssl.org/)

## 🔐 Sécurité

- **Algorithme** : AES-256-GCM (chiffrement authentifié)
- **Dérivation de clé** : Argon2id (résistant aux attaques GPU)
- **Intégrité** : Tag d'authentification GCM
- **Format** : `.crypt` (propriétaire mais spécification ouverte)

## ⚠️ Important

### Compatibilité des versions

- **V37** : Déchiffre **UNIQUEMENT** les fichiers `.crypt` créés avec V37
- **V31-V36** : Utilisez [Cryptage V36.1](https://github.com/BernardBourbaki/Cryptage/releases/tag/v36.1) pour déchiffrer les anciens fichiers

### Limites

- **Taille maximale** : 10 Mo par fichier
- **Formats supportés** : 
  - Texte : `.txt`
  - Images : `.jpg`, `.png`, `.bmp`
  - Crypté : `.crypt`
- **Mot de passe** : Aucune récupération possible - **utilisez un gestionnaire de mots de passe**

## 🚀 Installation

### Windows (Exécutable)

1. Téléchargez `Cryptage_V37.exe` depuis [Releases](https://github.com/BernardBourbaki/Cryptage/releases/latest)
2. Vérifiez le checksum SHA256 (voir `checksums.txt`)
3. Lancez l'exécutable (pas d'installation requise)

### Compilation depuis les sources

**Prérequis** :
- GCC (MinGW-w64 pour Windows)
- OpenSSL 3.0+

**Commande** :
```bash
gcc -o Cryptage_V37.exe \
    src/Cryptage_Main.c \
    src/Cryptage_Core.c \
    src/Cryptage_UI_Common.c \
    src/Cryptage_UI.c \
    -lssl -lcrypto -lgdi32 -lcomctl32 -mwindows
```

## 📖 Utilisation

### Interface intuitive en 3 étapes

#### Pour chiffrer un fichier

1. **Créez un mot de passe fort** (16+ caractères recommandés)
   - Utilisez KeePass, Bitwarden ou un autre gestionnaire
   - ⚠️ Ne transmettez **JAMAIS** le mot de passe avec le fichier chiffré

2. **IMPORTER** → **CHIFFRER** → **SAUVEGARDER**
   - Cliquez sur "IMPORTER" et sélectionnez votre fichier
   - Cliquez sur "CHIFFRER"
   - Cliquez sur "SAUVEGARDER" pour créer le fichier `.crypt`

#### Pour déchiffrer un fichier

1. **Entrez le mot de passe** utilisé lors du chiffrement

2. **IMPORTER** → **DÉCHIFFRER** → **EXPORTER**
   - Cliquez sur "IMPORTER" et sélectionnez le fichier `.crypt`
   - Cliquez sur "DÉCHIFFRER"
   - Cliquez sur "EXPORTER" (Texte ou Image selon le contenu)

### Panneau "Prise en main rapide"

Cliquez sur le bouton en bas de la fenêtre pour afficher/masquer les instructions détaillées.

## 🔒 Bonnes pratiques de sécurité

✅ **À FAIRE** :
- Utilisez des mots de passe de 16 caractères minimum
- Conservez vos mots de passe dans un gestionnaire sécurisé
- Testez le déchiffrement **avant** de supprimer l'original
- Gardez plusieurs copies du logiciel Cryptage_V37.exe

❌ **À NE PAS FAIRE** :
- Envoyer le mot de passe ET le fichier chiffré par le même canal
- Utiliser le même mot de passe pour tous vos fichiers
- Oublier de vérifier que le déchiffrement fonctionne
- Supprimer l'original avant d'avoir testé

## 🛠️ Paramètres techniques

### Configuration automatique

Le logiciel calcule automatiquement le paramètre mémoire optimal :
- **Formule** : 25% de la RAM disponible
- **Minimum** : 4 Mo (4096 KiB)
- **Maximum** : 1024 Mo (1048576 KiB)
- **Par défaut** : 16 Mo si le calcul échoue

### Structure du fichier `.crypt`
```
[AAD - 24 octets]
  - Version (4) : 370 (décimal)
  - Réservé (16) : extensibilité future
  - Mémoire Argon2id (4) : en KiB

[SALT - 32 octets]
[NONCE - 12 octets]
[CIPHERTEXT - variable]
[TAG - 16 octets]
```

## 📊 Nouveautés V37

### Par rapport à V36.1

- ✨ Interface unique simplifiée
- ✨ Détection automatique des versions antérieures
- ✨ Messages d'erreur plus clairs
- ✨ Limite portée à 10 Mo (au lieu de 2 Mo)
- ✨ Panneau d'aide intégré
- 🔧 Architecture du code simplifiée (-40% de lignes)

### Incompatibilité

⚠️ **V37 ne déchiffre PAS les fichiers V31-V36**

Pour déchiffrer d'anciens fichiers, téléchargez [Cryptage V36.1](https://github.com/BernardBourbaki/Cryptage/releases/tag/v36.1)

## 🐛 Problèmes connus

Aucun problème connu pour le moment. 

Signalez les bugs via [Issues](https://github.com/BernardBourbaki/cryptage-v37/issues).

## 📜 Licence

Ce projet est sous licence MIT. Voir [LICENSE](LICENSE) pour plus de détails.

## 👤 Auteur

**Bernard DÉMARET**

- GitHub : [@BernardBourbaki](https://github.com/BernardBourbaki)

## 🙏 Remerciements

- OpenSSL pour les algorithmes cryptographiques
- La communauté GitHub pour les retours et suggestions

## ⚖️ Avertissement

Ce logiciel est fourni "tel quel", sans garantie d'aucune sorte. L'auteur ne peut être tenu responsable de toute perte de données. **Conservez toujours des sauvegardes de vos fichiers originaux.**

---


**[English version](README.en.md)** 🇬🇧


