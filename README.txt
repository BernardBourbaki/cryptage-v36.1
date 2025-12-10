========================================
CRYPTAGE VERSION 36.1 - APPLICATION DE CHIFFREMENT SÉCURISÉ
========================================

(c) Bernard DÉMARET - Version 36.1 (Portable)
(grandement aidé par Claude.IA (Anthropic))
Dernière mise à jour : Décembre 2024

========================================
NOUVEAUTÉS VERSION 36.1
========================================

✨ AMÉLIORATIONS MAJEURES :

• Nettoyage automatique après sauvegarde
  → Après chaque export (binaire, hex, texte, image), les champs sont 
     automatiquement vidés pour éviter les interférences

• Détection automatique du paramètre mémoire
  → Lors de l'import d'un fichier crypté, le paramètre mémoire est 
     automatiquement extrait et affiché dans l'interface

• Support amélioré des fichiers .txt hex
  → Les fichiers .txt contenant des données hexadécimales sont maintenant 
     correctement traités, avec extraction automatique du paramètre mémoire

• Validation renforcée des formats
  → Meilleure détection des fichiers cryptés (versions 31 à 999)
  → Messages d'erreur plus explicites

🔧 CORRECTIONS DE BUGS :

• Import de fichiers .crypt générés par V36.1 : corrigé
• Déchiffrement de fichiers hex .txt : amélioré
• Gestion de la mémoire résiduelle : corrigée
• Validation de version : étendue pour compatibilité future

📊 COMPATIBILITÉ :

• Compatible avec fichiers chiffrés par versions V31 à V36
• Les anciennes versions peuvent déchiffrer les fichiers V36.1
• Rétrocompatibilité complète assurée

========================================
TABLE DES MATIÈRES
========================================

1. PRÉSENTATION DU PROJET
2. FONCTIONNALITÉS PRINCIPALES
3. GUIDE D'UTILISATION
4. FONCTIONNEMENT TECHNIQUE
5. ALGORITHMES ET SÉCURITÉ
6. COMPILATION
7. LIMITATIONS ET PRÉCAUTIONS
8. DÉPANNAGE
9. LICENCE

========================================
1. PRÉSENTATION DU PROJET
========================================

Cryptage V36.1 est une application Windows portable de chiffrement/déchiffrement
qui offre une sécurité de niveau professionnel avec une interface intuitive
et colorée facilitant l'utilisation quotidienne.

OBJECTIFS :
-----------
• Fournir un chiffrement robuste accessible aux non-experts
• Protéger fichiers texte et images avec cryptographie moderne
• Interface visuelle claire avec code couleur intuitif
• Application portable sans installation requise
• Protection mémoire contre les attaques par canaux auxiliaires

POINTS FORTS :
--------------
✓ Chiffrement AES-256-GCM (standard militaire)
✓ Dérivation de clé Argon2id (résistant GPU/ASIC)
✓ Interface colorée intuitive (5 couleurs principales + 4 pastels)
✓ Support texte et images (JPG, PNG, BMP)
✓ Détection automatique de format à l'import
✓ Extraction automatique du paramètre mémoire
✓ Nettoyage automatique après export
✓ Gestion mémoire sécurisée
✓ 100% portable (aucune installation)

========================================
2. FONCTIONNALITÉS PRINCIPALES
========================================

CHIFFREMENT/DÉCHIFFREMENT :
---------------------------
• Chiffrement symétrique AES-256-GCM
• Mots de passe forts avec validation (8-64 caractères)
• Support fichiers jusqu'à 2 Mo
• Progression visuelle des opérations

FORMATS SUPPORTÉS :
-------------------
• Texte : fichiers .txt en UTF-8
• Images : JPEG/JPG, PNG, BMP
• Fichiers cryptés : .crypt (format propriétaire)
• Export hexadécimal : .txt

INTERFACE UTILISATEUR :
-----------------------
• Code couleur intuitif pour chaque action
• Organisation en 5 groupes fonctionnels distincts
• Détection automatique de format à l'import
• Extraction automatique du paramètre mémoire
• Validation en temps réel des saisies
• Barre de progression pour opérations longues
• Nettoyage automatique après sauvegarde

========================================
3. GUIDE D'UTILISATION
========================================

INTERFACE PRINCIPALE :
----------------------

L'interface est organisée en zones distinctes :

┌───────────────────────────────────────────────────────┐
│ Mot de passe [Afficher]          Mémoire [Mo] : [1024]  │
├─────────────────────────┬─────────────────────────────┤
│                         │ [CYAN] Importer               │
│  Zone Entrée (texte ou  │ [VERT] Chiffrer               │
│  données hexadécimales) │ [BLEU] Déchiffrer             │
│                         │                               │
│                         │ Exporter le fichier chiffré   │
├─────────────────────────┤ [ROSE] Sauvegarder [.crypt]   │
│                         │ [PÊCHE] Exporter hex [.txt]   │
│  Zone Sortie (résultat  │                               │
│  des opérations)        │ Exporter le fichier déchiffré │
│                         │ [LAVANDE] Texte               │
│                         │ [MENTHE] Image                │
│                         │                               │
│                         │ [ROUGE] Effacer               │
├─────────────────────────┴─────────────────────────────┤
│ ████████████████████ Barre de progression               │
└───────────────────────────────────────────────────────┘

CODE COULEUR :
--------------
🔵 CYAN   : Import de fichiers (action d'entrée)
🟢 VERT   : Chiffrement (sécurisation)
🔵 BLEU   : Déchiffrement (déverrouillage)
🌸 ROSE   : Sauvegarde fichier chiffré
🍑 PÊCHE  : Export hexadécimal
💜 LAVANDE: Export texte déchiffré
🌿 MENTHE : Export image déchiffrée
🔴 ROUGE  : Effacement (action destructive)

WORKFLOW CHIFFREMENT :
----------------------

1. Saisir un mot de passe FORT :
   • 8 à 64 caractères
   • Au moins 1 majuscule
   • Au moins 1 minuscule
   • Au moins 1 chiffre
   • Au moins 1 symbole (!@#$%^&*...)

2. Importer ou saisir les données :
   • Clic sur [Importer] (CYAN) pour charger un fichier
   • OU saisir directement OU copier/coller le texte dans "Entrée"
   • Le programme détecte automatiquement le format

3. Vérifier le paramètre mémoire :
   • Valeur par défaut calculée automatiquement
   • Ne modifier QUE si nécessaire
   • ⚠️ IMPORTANT : Cette valeur est maintenant STOCKÉE dans le fichier
     crypté et sera extraite automatiquement au déchiffrement

4. Cliquer sur [Chiffrer] (VERT)
   • La barre de progression s'active
   • Le résultat apparaît en hexadécimal dans "Sortie"

5. Sauvegarder le résultat :
   • [Sauvegarder .crypt] (ROSE) : format binaire compact (RECOMMANDÉ)
   • [Exporter hex .txt] (PÊCHE) : format texte lisible
   
6. ✨ NOUVEAU : Nettoyage automatique
   • Après la sauvegarde, tous les champs sont automatiquement vidés
   • Prêt pour une nouvelle opération

WORKFLOW DÉCHIFFREMENT :
------------------------

1. Importer le fichier chiffré :
   • Clic sur [Importer] (CYAN)
   • Sélectionner le fichier .crypt ou .txt
   • Le format est détecté automatiquement
   
2. ✨ NOUVEAU : Extraction automatique du paramètre mémoire
   • Pour les fichiers .crypt : le paramètre est automatiquement extrait
   • Pour les fichiers .txt hex : le paramètre est extrait lors du déchiffrement
   • Plus besoin de se souvenir manuellement de cette valeur !

3. Saisir le MÊME mot de passe qu'au chiffrement

4. Cliquer sur [Déchiffrer] (BLEU)
   • Si le mot de passe est correct : succès
   • Sinon : message d'erreur explicite

5. Exporter le résultat :
   • Pour texte : [Texte] (LAVANDE) → fichier .txt
   • Pour image : [Image] (MENTHE) → fichier image original

6. ✨ NOUVEAU : Nettoyage automatique
   • Après l'export, tous les champs sont automatiquement vidés

PARAMÈTRE MÉMOIRE :
-------------------

Le paramètre mémoire définit la robustesse de la dérivation de clé :

• Valeur par défaut : 25% de la RAM disponible
• Minimum : 4 Mo (sécurité basique)
• Maximum : 1024 Mo (sécurité maximale)
• Recommandation : conserver la valeur par défaut

✨ NOUVEAUTÉ V36.1 : Extraction automatique
   → Le paramètre mémoire est maintenant STOCKÉ dans le fichier crypté
   → Il est automatiquement extrait et affiché lors de l'import
   → Plus besoin de le noter manuellement - il est stocké dans le fichier !

⚠️ IMPORTANT : Le mot de passe reste OBLIGATOIRE et doit être conservé 
   en lieu sûr. Seul le paramètre mémoire est maintenant géré automatiquement.

Plus la valeur est élevée :
  ✓ Meilleure protection contre attaques par force brute
  ✗ Temps de traitement plus long
  ✗ Consommation mémoire plus importante

CONSEILS D'UTILISATION :
------------------------

✓ Testez TOUJOURS le déchiffrement après un chiffrement important
✓ Conservez plusieurs copies de vos fichiers chiffrés
✓ Utilisez un gestionnaire de mots de passe sécurisé
✓ Ne partagez JAMAIS vos mots de passe
✓ Changez régulièrement vos mots de passe
✓ Pour les images : préférez [Sauvegarder .crypt] à [Exporter hex]

✗ Ne chiffrez pas de données irremplaçables sans backup
✗ N'utilisez pas de mots de passe faibles ou évidents
✗ Ne stockez pas les mots de passe en clair
✗ Ne modifiez pas les fichiers .crypt manuellement

LIMITATIONS DU COPIER/COLLER :
------------------------------

⚠️ IMPORTANT : Le copier/coller de données hexadécimales volumineuses 
   (images) peut être limité par Windows :

• Fichiers texte (<50 Ko) : copier/coller hex fonctionne ✓
• Images (>100 Ko) : copier/coller hex peut échouer ✗

RECOMMANDATION pour les images :
  → Utilisez TOUJOURS [Sauvegarder .crypt] (format binaire)
  → Puis [Importer] pour recharger
  → L'export hex est pour VISUALISATION seulement

========================================
4. FONCTIONNEMENT TECHNIQUE
========================================

ARCHITECTURE LOGICIELLE :
-------------------------

Le programme est structuré en 3 modules :

1. cryptage.h
   • Définitions des structures de données
   • Constantes et macros
   • Déclarations de fonctions

2. cryptage_core.c
   • Cœur cryptographique (AES, Argon2)
   • Gestion mémoire sécurisée
   • Opérations de chiffrement/déchiffrement
   • Validation et conversion de données

3. cryptage_ui.c
   • Interface utilisateur Win32
   • Gestion des événements
   • Import/Export de fichiers
   • Threads pour opérations longues
   • Nettoyage automatique (V36.1)

FLUX DE CHIFFREMENT :
---------------------

1. Validation du mot de passe
   ↓
2. Génération de sel aléatoire (16 octets)
   ↓
3. Dérivation de clé avec Argon2id
   • Entrée : mot de passe + sel
   • Sortie : clé AES-256 (32 octets)
   ↓
4. Génération de nonce aléatoire (12 octets)
   ↓
5. Chiffrement AES-256-GCM
   • Données en entrée
   • Clé dérivée
   • Nonce unique
   • AAD (données additionnelles authentifiées)
   ↓
6. Construction du fichier final
   • En-tête AAD (28 octets)
   • Sel (16 octets)
   • Nonce (12 octets)
   • Tag d'authentification (16 octets)
   • Données chiffrées
   ↓
7. ✨ NOUVEAU : Nettoyage automatique après sauvegarde

FLUX DE DÉCHIFFREMENT :
-----------------------

1. Validation du fichier chiffré
   ↓
2. ✨ NOUVEAU : Extraction automatique du paramètre mémoire
   • Lecture à l'offset 20 (4 octets)
   • Mise à jour automatique de l'interface
   ↓
3. Extraction des composants
   • Lecture de l'en-tête AAD
   • Extraction sel, nonce, tag
   ↓
4. Dérivation de clé avec Argon2id
   • Même mot de passe + sel extrait
   • Paramètre mémoire extrait automatiquement
   ↓
5. Déchiffrement et vérification
   • AES-256-GCM avec clé dérivée
   • Vérification du tag d'authentification
   • Si tag invalide → échec authentification
   ↓
6. Retour des données en clair
   ↓
7. ✨ NOUVEAU : Nettoyage automatique après export

STRUCTURE DU FICHIER .CRYPT :
------------------------------

```
Offset   Taille   Description
------   ------   -----------
0        4        Version du format (361 pour V36.1)
4        4        Taille du sel (16)
8        4        Taille du nonce (12)
12       4        Taille du tag (16)
16       4        Taille des données chiffrées
20       4        Coût mémoire Argon2 (en KiB) ← EXTRACTION AUTO V36.1
24       4        Code d'extension (pour images)
28       16       Sel aléatoire
44       12       Nonce aléatoire
56       16       Tag d'authentification GCM
72       N        Données chiffrées
```

DÉTECTION AUTOMATIQUE DE FORMAT :
----------------------------------

À l'import, le programme analyse dans cet ordre :

1. ✨ NOUVEAU : Vérification format crypté (prioritaire)
   • Lecture version (offset 0)
   • Validation versions 31-999
   • Extraction automatique paramètre mémoire

2. Vérification "magic bytes" images :
   • JPEG : FF D8 FF
   • PNG  : 89 50 4E 47 0D 0A 1A 0A
   • BMP  : 42 4D

3. Vérification format texte :
   • Analyse caractères imprimables
   • Détection UTF-8

GESTION MÉMOIRE SÉCURISÉE :
---------------------------

Toutes les données sensibles (mots de passe, clés, données déchiffrées) 
sont protégées :

1. Allocation sécurisée
   • VirtualAlloc avec VirtualLock (Windows)
   • Empêche le swap sur disque

2. Nettoyage systématique
   • Écrasement avec zéros avant libération
   • secure_clean_and_free() pour toutes les données sensibles
   • ✨ NOUVEAU : Nettoyage automatique après export

3. Registre de mémoire
   • Suivi de toutes les allocations sécurisées
   • Nettoyage automatique à la fermeture

THREADING :
-----------

Les opérations cryptographiques utilisent des threads séparés :

• Thread principal : interface utilisateur
• Thread crypto : chiffrement/déchiffrement
• Communication par messages Windows (WM_USER_PROGRESS, WM_USER_COMPLETE)
• Empêche le gel de l'interface pendant les opérations

========================================
5. ALGORITHMES ET SÉCURITÉ
========================================

AES-256-GCM (ADVANCED ENCRYPTION STANDARD) :
---------------------------------------------

Mode opératoire : Galois/Counter Mode (GCM)
Taille de clé : 256 bits (32 octets)
Taille de bloc : 128 bits (16 octets)

Avantages de GCM :
✓ Chiffrement ET authentification intégrés
✓ Parallélisable (performances optimales)
✓ Détection de toute modification des données
✓ Standard NIST approuvé (SP 800-38D)
✓ Utilisé dans TLS 1.3, IPsec, SSH

Le tag d'authentification (16 octets) garantit :
• Intégrité : les données n'ont pas été modifiées
• Authenticité : les données proviennent de la bonne source
• Protection contre attaques par manipulation

ARGON2ID (KEY DERIVATION FUNCTION) :
-------------------------------------

Type : Argon2id (hybride Argon2i + Argon2d)
Paramètres :
• Iterations (t_cost) : 2
• Memory (m_cost) : configurable (défaut ~16 Mo)
• Parallelism (p_cost) : 1

Pourquoi Argon2id ?
✓ Vainqueur de la Password Hashing Competition (2015)
✓ Résistant aux attaques GPU/ASIC/FPGA
✓ Résistant aux attaques par canaux auxiliaires
✓ Recommandé par l'OWASP et le NIST
✓ Utilisé par Bitwarden, 1Password, KeePassXC

Protection contre :
• Attaques par force brute
• Attaques par dictionnaire
• Rainbow tables
• Attaques parallèles massives

SEL (SALT) :
------------

• Taille : 16 octets (128 bits)
• Génération : RAND_bytes() d'OpenSSL (CSPRNG)
• Unique par fichier

Le sel empêche :
✓ Attaques par rainbow tables
✓ Détection de fichiers identiques
✓ Réutilisation de calculs entre fichiers

NONCE (NUMBER USED ONCE) :
---------------------------

• Taille : 12 octets (96 bits) - optimal pour GCM
• Génération : RAND_bytes() d'OpenSSL
• Unique par opération de chiffrement

Le nonce garantit :
✓ Unicité de chaque chiffrement
✓ Même message chiffré différemment à chaque fois
✓ Protection contre attaques par rejeu

AAD (ADDITIONAL AUTHENTICATED DATA) :
--------------------------------------

L'en-tête de 28 octets est authentifié mais non chiffré :
✓ Empêche modification de la version
✓ Empêche modification des tailles
✓ Empêche modification du coût mémoire
✓ Garantit compatibilité lors du déchiffrement
✓ ✨ NOUVEAU : Permet extraction automatique paramètre mémoire

NIVEAU DE SÉCURITÉ :
--------------------

Configuration actuelle (défaut) :

• AES-256 : ~2^256 combinaisons (inviolable par force brute)
• Argon2id (16 Mo) : ~1 seconde par tentative sur CPU moderne
• Mot de passe fort (12 caractères) : ~95^12 combinaisons

Temps estimé pour casser par force brute :
→ Des millions d'années avec le matériel actuel

Protection contre :
✓ Attaques par force brute
✓ Attaques par dictionnaire
✓ Attaques par rainbow tables
✓ Attaques GPU/ASIC massives
✓ Attaques par canaux auxiliaires (timing, cache)
✓ Attaques par modification de fichier
✓ Attaques par rejeu

CONFORMITÉ AUX STANDARDS :
--------------------------

✓ FIPS 197 (AES)
✓ NIST SP 800-38D (GCM)
✓ RFC 9106 (Argon2)
✓ Recommandations OWASP
✓ Bonnes pratiques ANSSI

========================================
6. COMPILATION
========================================

PRÉREQUIS :
-----------

• Compilateur : GCC (MinGW-w64) ou MSVC
• OpenSSL : version 1.1.1 ou supérieure
• Windows SDK : pour Win32 API
• OS : Windows 7 ou ultérieur

STRUCTURE DES FICHIERS :
------------------------

cryptage_v36.1/
├── cryptage.h          (en-têtes et définitions)
├── cryptage_core.c     (logique cryptographique)
├── cryptage_ui.c       (interface utilisateur)
├── openssl/
│   ├── include/        (headers OpenSSL)
│   └── lib/            (bibliothèques OpenSSL)
└── README.txt          (ce fichier)

COMPILATION AVEC GCC :
----------------------

Option 1 : Liaison dynamique
```bash
gcc -o cryptage_v36.1.exe cryptage_ui.c cryptage_core.c \
    -I./openssl/include \
    -L./openssl/lib \
    -lssl -lcrypto \
    -lgdi32 -lcomctl32 \
    -mwindows \
    -O2
```

Option 2 : Liaison statique (portable)
```bash
gcc -o cryptage_v36.1.exe cryptage_ui.c cryptage_core.c \
    -I./openssl/include \
    -L./openssl/lib \
    -lssl -lcrypto \
    -lgdi32 -lcomctl32 \
    -mwindows \
    -static \
    -O2
```

Option 3 : Version debug
```bash
gcc -o cryptage_v36.1_debug.exe cryptage_ui.c cryptage_core.c \
    -I./openssl/include \
    -L./openssl/lib \
    -lssl -lcrypto \
    -lgdi32 -lcomctl32 \
    -mwindows \
    -g -O0
```

COMPILATION AVEC MSVC :
-----------------------

```cmd
cl /Fe:cryptage_v36.1.exe cryptage_ui.c cryptage_core.c ^
   /I".\openssl\include" ^
   /link /LIBPATH:".\openssl\lib" ^
   libssl.lib libcrypto.lib ^
   gdi32.lib comctl32.lib ^
   /SUBSYSTEM:WINDOWS
```

VÉRIFICATION DE LA COMPILATION :
---------------------------------

Après compilation, vérifier :
1. Taille de l'exécutable : ~500 Ko (statique) ou ~50 Ko (dynamique)
2. Dépendances : `ldd cryptage_v36.1.exe` (ou Dependency Walker)
3. Lancement : double-clic sur l'exécutable
4. Test : chiffrer puis déchiffrer un fichier texte simple
5. ✨ NOUVEAU : Vérifier le nettoyage automatique après export

========================================
7. LIMITATIONS ET PRÉCAUTIONS
========================================

LIMITATIONS TECHNIQUES :
------------------------

• Taille maximale : 2 Mo par fichier
  Raison : équilibre performance/sécurité pour usage courant

• Formats image : uniquement JPG, PNG, BMP
  Raison : détection basée sur magic bytes standardisés

• Copier/coller hex limité pour images volumineuses
  Raison : limite Windows Edit Control (~64 Ko de texte)
  Solution : utiliser [Sauvegarder .crypt] pour les images

• Pas de multi-threading pour le chiffrement
  Raison : OpenSSL non thread-safe pour certaines opérations

• Paramètre mémoire : 4 Mo à 1024 Mo
  Raison : équilibre entre sécurité et compatibilité matérielle

PRÉCAUTIONS ESSENTIELLES :
--------------------------

⚠️ MOTS DE PASSE :
• Utilisez TOUJOURS des mots de passe forts et uniques
• Ne réutilisez JAMAIS les mêmes mots de passe
• Conservez les mots de passe dans un gestionnaire sécurisé
• Ne partagez JAMAIS vos mots de passe

⚠️ PARAMÈTRE MÉMOIRE (V36.1) :
• ✨ NOUVEAU : Stocké automatiquement dans le fichier crypté
• Plus besoin de le noter séparément
• Extraction et utilisation automatiques au déchiffrement
• ⚠️ Le mot de passe reste OBLIGATOIRE et doit être conservé !

⚠️ SAUVEGARDE :
• Conservez TOUJOURS plusieurs copies de vos fichiers chiffrés
• Testez le déchiffrement IMMÉDIATEMENT après chiffrement
• Sauvegardez sur supports multiples (disque, cloud, USB)

⚠️ PERTE DE DONNÉES :
• AUCUNE récupération possible sans le mot de passe correct
• Aucune "porte dérobée" n'existe (par conception)
• ✨ Le paramètre mémoire est maintenant géré automatiquement

CONSIDÉRATIONS SÉCURITAIRES :
------------------------------

L'application protège contre :
✓ Attaques hors ligne (force brute sur fichiers)
✓ Modifications malveillantes de fichiers
✓ Attaques par canaux auxiliaires

L'application NE protège PAS contre :
✗ Keyloggers (enregistreurs de frappe)
✗ Accès physique non autorisé à la machine
✗ Malwares avec privilèges élevés
✗ Attaques pendant que le fichier est déchiffré

Recommandations :
• Utilisez un antivirus à jour
• Maintenez Windows à jour
• Déchiffrez uniquement sur machines de confiance
• Verrouillez votre session quand vous vous absentez
• Chiffrez le disque système (BitLocker/VeraCrypt)

COMPATIBILITÉ :
---------------

Compatibilité ascendante :
✓ V36.1 peut déchiffrer fichiers de V31, V32, V33, V34, V35, V36
✓ Les anciennes versions peuvent déchiffrer fichiers V36.1

Incompatibilité :
✗ Fichiers chiffrés avec d'autres logiciels (incompatible)
✗ Fichiers corrompus ou partiels
✗ Fichiers modifiés manuellement

========================================
8. DÉPANNAGE
========================================

PROBLÈME : "Mot de passe incorrect ou données corrompues"
----------------------------------------------------------
Causes possibles :
• Mot de passe réellement incorrect (typo, casse, espace)
• Fichier corrompu ou incomplet
• Fichier modifié après chiffrement

Solutions :
1. Vérifier la casse du mot de passe (Maj/Min)
2. ✨ NOUVEAU : Le paramètre mémoire est géré automatiquement
3. Essayer une copie de sauvegarde du fichier
4. Vérifier l'intégrité du fichier (taille, checksum)

PROBLÈME : "Échec d'allocation mémoire"
----------------------------------------
Causes :
• RAM insuffisante pour le paramètre mémoire
• Trop d'applications en cours d'exécution
• Fuites mémoire (rare)

Solutions :
1. Fermer d'autres applications
2. Réduire le paramètre mémoire (si au chiffrement)
3. Redémarrer l'ordinateur
4. Augmenter la mémoire virtuelle Windows

PROBLÈME : "Format de fichier non reconnu"
-------------------------------------------
Causes :
• Extension incorrecte
• Fichier corrompu
• Format non supporté

Solutions :
1. Vérifier l'extension du fichier
2. ✨ NOUVEAU : Utiliser [Importer] pour détection automatique
3. Vérifier que le fichier n'est pas vide
4. Essayer une conversion de format

PROBLÈME : Copier/coller ne fonctionne pas pour les images
----------------------------------------------------------
Cause :
• Limite Windows Edit Control pour texte volumineux
• Données hex d'image trop volumineuses (>64 Ko)

Solution :
✓ Pour images : TOUJOURS utiliser [Sauvegarder .crypt]
✓ Puis [Importer] pour recharger
✗ NE PAS utiliser copier/coller hex pour images

PROBLÈME : L'application ne démarre pas
----------------------------------------
Causes :
• DLL OpenSSL manquantes (version dynamique)
• Version Windows incompatible
• Antivirus bloquant l'exécution

Solutions :
1. Vérifier présence de libssl-*.dll et libcrypto-*.dll
2. Vérifier Windows 7 SP1 minimum
3. Ajouter exception dans l'antivirus
4. Exécuter en tant qu'administrateur

PROBLÈME : Interface ne répond plus
------------------------------------
Cause :
• Opération en cours (normal pour gros fichiers)

Solution :
• Patienter (barre de progression indique l'avancement)
• Pour fichiers > 1 Mo, attendre quelques secondes

PROBLÈME : "Algorithme AES-256-GCM non disponible"
---------------------------------------------------
Cause :
• OpenSSL mal installé ou version trop ancienne

Solutions :
1. Réinstaller OpenSSL 1.1.1 ou supérieur
2. Vérifier les chemins des DLL
3. Recompiler avec la bonne version d'OpenSSL

PROBLÈME : Les champs ne se vident pas après export
----------------------------------------------------
✨ CORRECTION V36.1 : Ce problème est résolu
• Les champs sont maintenant automatiquement vidés après :
  → Sauvegarde [.crypt]
  → Exporter hex [.txt]
  → Export texte déchiffré
  → Export image déchiffrée

========================================
9. LICENCE
========================================

© 2024 Bernard DÉMARET - Tous droits réservés

UTILISATION :
-------------
Ce logiciel est destiné à un usage personnel et éducatif.
La redistribution ou modification sans autorisation est interdite.

GARANTIE :
----------
Ce logiciel est fourni "tel quel" sans garantie d'aucune sorte.
L'auteur décline toute responsabilité en cas de :
• Perte de données
• Utilisation inappropriée
• Dommages directs ou indirects

RESPONSABILITÉ DE L'UTILISATEUR :
----------------------------------
L'utilisateur est seul responsable de :
• La conservation de ses mots de passe
• La sauvegarde de ses fichiers
• L'utilisation conforme aux lois locales
• La sécurité de ses données

BIBLIOTHÈQUES TIERCES :
------------------------
Ce logiciel utilise OpenSSL (https://www.openssl.org/)
Licence OpenSSL : Apache License 2.0

========================================
CONTACT ET SUPPORT
========================================

Pour toute question ou problème :

1. Vérifiez d'abord cette documentation
2. Vérifiez les paramètres (mot de passe, mémoire)
3. Testez avec un fichier simple
4. Vérifiez l'intégrité du fichier

Note importante :
-----------------
Aucune récupération de mot de passe n'est possible.
C'est une caractéristique de sécurité, pas un bug.
Si vous perdez votre mot de passe, vos données sont définitivement inaccessibles.

========================================
REMERCIEMENTS
========================================

• OpenSSL Project pour la bibliothèque cryptographique
• NIST pour les standards cryptographiques
• Communauté crypto pour Argon2
• Microsoft pour l'API Win32
• Claude (Anthropic) pour l'assistance au développement de l'interface

========================================
FIN DU DOCUMENT
========================================

Version du document : 36.1
Dernière mise à jour : Décembre 2024