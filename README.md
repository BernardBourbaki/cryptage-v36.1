# Cryptage V36.1

Application Windows portable de chiffrement/déchiffrement utilisant AES-256-GCM et Argon2id.

![Version](https://img.shields.io/badge/version-36.1-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

![Interface Cryptage V36.1](screenshots/interface.png)

## 🔒 Sécurité

- **Chiffrement** : AES-256-GCM (standard militaire)
- **Dérivation de clé** : Argon2id (résistant GPU/ASIC)
- **Authentification** : Tag GCM (intégrité garantie)
- **Formats supportés** : Texte (UTF-8), Images (JPG, PNG, BMP)
- **Taille maximale** : 2 Mo par fichier

## ✨ Fonctionnalités

- ✅ Interface colorée intuitive
- ✅ Détection automatique de format
- ✅ Extraction automatique du paramètre mémoire
- ✅ Nettoyage automatique après export
- ✅ Compatible versions V31-V36
- ✅ 100% portable (aucune installation)

## 📦 Téléchargement

**Dernière version** : [Releases](../../releases)

Téléchargez `cryptage_v36.1.exe` et lancez-le directement.
Aucune installation nécessaire !

## 🚀 Utilisation rapide

### Chiffrer un fichier

1. Créer un mot de passe fort (16+ caractères)
2. Cliquer sur "Importer le fichier source"
3. Sélectionner votre fichier
4. Cliquer "Chiffrer"
5. Sauvegarder en `.crypt`

### Déchiffrer un fichier

1. Cliquer sur "Importer le fichier source"
2. Sélectionner le fichier `.crypt`
3. Le paramètre mémoire est extrait automatiquement
4. Entrer le mot de passe
5. Cliquer "Déchiffrer"
6. Exporter (Texte ou Image)

## 📖 Documentation complète

Pour la documentation détaillée, consultez [README.txt](https://github.com/BernardBourbaki/cryptage-v36.1/blob/docs/README.txt)

## 🔐 Sécurité et Bonnes Pratiques

⚠️ **IMPORTANT** : La sécurité dépend de votre mot de passe !

**Recommandations** :
- Utilisez un gestionnaire de mots de passe (KeePass recommandé)
- Mots de passe de 16+ caractères (idéal : 60 caractères)
- Ne transmettez JAMAIS mot de passe et fichier par le même canal
- Consultez le Guide de Sécurité dans la documentation

## 📊 Spécifications Techniques
```
Algorithmes :
  Chiffrement    : AES-256-GCM
  KDF            : Argon2id
  CSPRNG         : OpenSSL RAND_bytes

Paramètres Argon2id :
  Iterations     : 2
  Memory         : Configurable (défaut: 25% RAM)
  Parallelism    : 1

Structure fichier .crypt :
  Version        : 361 (V36.1)
  En-tête AAD    : 28 octets
  Sel            : 16 octets
  Nonce          : 12 octets
  Tag GCM        : 16 octets
  Données        : Variable (max 2 Mo)
```

## 🏗️ Compilation

### Prérequis
- MinGW-w64
- OpenSSL 1.1.1+

### Commande
```bash
gcc -o cryptage_v36.1.exe Cryptage_UI.c Cryptage_Core.c \
    -I./openssl/include \
    -L./openssl/lib \
    -lssl -lcrypto \
    -lgdi32 -lcomctl32 \
    -mwindows \
    -static \
    -O2
```

## 📜 Changelog

### Version 36.1 (Décembre 2024)

**Nouveautés** :
- Nettoyage automatique après sauvegarde
- Extraction automatique du paramètre mémoire
- Support amélioré fichiers .txt hex
- Validation renforcée des formats

**Corrections** :
- Import fichiers .crypt V36.1
- Déchiffrement fichiers hex
- Gestion mémoire résiduelle

## 📄 Licence

MIT License - © 2024 Bernard DÉMARET

Voir [LICENSE](LICENSE) pour les détails complets.

## ⚠️ Avertissement

Ce logiciel est fourni "tel quel" sans garantie d'aucune sorte.
L'auteur décline toute responsabilité en cas de perte de données.

**Utilisez à vos propres risques.**

## 🙏 Remerciements

- OpenSSL Project pour la bibliothèque cryptographique
- Communauté Argon2 pour le KDF
- Claude (Anthropic) pour l'assistance au développement

## 📞 Support

- **Issues** : [Signaler un bug](../../issues)
- **Discussions** : [Forum](../../discussions)

---

⭐ Si ce projet vous est utile, n'hésitez pas à lui donner une étoile !
```
