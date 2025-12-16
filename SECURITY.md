# Politique de sécurité

## Versions supportées

| Version |          Support          |
| ------- | ------------------------- |
| 37.x    | ✅ Support actif          |
| 36.1    | ⚠️ Maintenance uniquement |
| < 36.0  | ❌ Non supportée          |

## Signaler une vulnérabilité

### Divulgation responsable

Si vous découvrez une vulnérabilité de sécurité dans Cryptage, merci de **NE PAS** créer une issue publique sur GitHub. Les failles de sécurité doivent rester confidentielles jusqu'à ce qu'un correctif soit disponible.

### Comment signaler

**Méthode privilégiée** : Utilisez la fonctionnalité [Security Advisories](https://github.com/BernardBourbaki/Cryptage/security/advisories/new) de GitHub (privée et sécurisée)

**Alternative** : Envoyez un email à `bourbaki_gos@hotmail.com` avec :
- **Sujet** : `[SECURITY] Cryptage - [Titre court]`
- **Contenu** :
  - Description détaillée de la vulnérabilité
  - Étapes pour reproduire le problème
  - Version(s) affectée(s)
  - Impact potentiel estimé
  - Éventuellement, une preuve de concept (PoC)

### Ce que vous devez inclure

Pour nous aider à traiter rapidement votre rapport, incluez autant d'informations que possible :

1. **Type de vulnérabilité** (injection, contournement du chiffrement, fuite mémoire, etc.)
2. **Composants affectés** (Argon2id, AES-GCM, gestion des fichiers, etc.)
3. **Conditions requises** (fichier malformé, mot de passe spécifique, etc.)
4. **Impact** (perte de confidentialité, corruption de données, déni de service, etc.)
5. **Reproductibilité** (100%, intermittent, dépendant de l'environnement)

### Processus de traitement

1. **Accusé de réception** : Sous 48 heures
2. **Évaluation initiale** : Dans les 7 jours
   - Confirmation de la vulnérabilité
   - Évaluation de la gravité (Critique, Haute, Moyenne, Faible)
3. **Développement du correctif** : Selon la gravité
   - Critique : 7-14 jours
   - Haute : 14-30 jours
   - Moyenne : 30-60 jours
   - Faible : Prochaine version planifiée
4. **Publication coordonnée** :
   - Vous êtes informé avant la publication
   - Publication du correctif
   - Divulgation publique de la CVE (si applicable)
   - Mention dans le CHANGELOG

### Embargos et coordination

- **Embargo par défaut** : 90 jours maximum
- Si vous avez besoin d'un délai spécifique, merci de nous en informer
- Nous vous créditerons publiquement (sauf si vous préférez rester anonyme)

### Ce à quoi vous pouvez vous attendre

✅ **Nous nous engageons à** :
- Traiter votre rapport avec sérieux et professionnalisme
- Vous tenir informé de l'avancement
- Vous créditer pour la découverte (si souhaité)
- Respecter l'embargo convenu

❌ **Nous ne pourrons pas** :
- Offrir de récompense monétaire (bug bounty)
- Garantir un délai de correction fixe pour les vulnérabilités complexes

### Divulgation publique prématurée

Si vous publiez la vulnérabilité avant notre accord :
- Nous publierons immédiatement un avis de sécurité
- Nous ne pourrons pas vous créditer officiellement
- Cela peut mettre les utilisateurs en danger

### Scope (Périmètre)

**Dans le périmètre** :
- Contournement du chiffrement AES-256-GCM
- Faiblesse dans la dérivation de clé Argon2id
- Fuite d'informations sensibles (mots de passe, clés, données)
- Corruption de données lors du chiffrement/déchiffrement
- Vulnérabilités liées au format de fichier `.crypt`
- Déni de service via fichiers malformés

**Hors périmètre** :
- Attaques par force brute sur des mots de passe faibles (comportement attendu)
- Vulnérabilités des dépendances OpenSSL (à signaler à OpenSSL directement)
- Problèmes d'interface utilisateur sans impact sécurité
- Ingénierie sociale

### Sévérité des vulnérabilités

Nous utilisons le système CVSS 3.1 pour évaluer la gravité :

- **Critique (9.0-10.0)** : Contournement complet du chiffrement, fuite de clé
- **Haute (7.0-8.9)** : Fuite partielle de données, affaiblissement cryptographique
- **Moyenne (4.0-6.9)** : Déni de service, corruption de données non critique
- **Faible (0.1-3.9)** : Problèmes mineurs sans impact direct sur la sécurité

### Remerciements

Nous remercions les chercheurs en sécurité suivants pour leurs contributions responsables :

*(À compléter au fur et à mesure)*

---

**Version de cette politique** : 1.0  
**Dernière mise à jour** : Décembre 2025

## Ressources supplémentaires

- [Guide de chiffrement sécurisé](https://github.com/BernardBourbaki/Cryptage/wiki/Secure-Encryption-Guide) *(à créer)*
- [Architecture cryptographique](https://github.com/BernardBourbaki/Cryptage/wiki/Crypto-Architecture) *(à créer)*
- [Format de fichier .crypt](https://github.com/BernardBourbaki/Cryptage/wiki/File-Format-Specification) *(à créer)*
