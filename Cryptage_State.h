/**
 * Cryptage_State.h
 * Structures d'état - Version 37 (Interface unique)
 * (c) Bernard DÉMARET - 2025
 */

#ifndef CRYPTAGE_STATE_H
#define CRYPTAGE_STATE_H

#include <windows.h>
#include <stdbool.h>

/* ========================================
 * ÉNUMÉRATIONS
 * ======================================== */

/**
 * Type de fichier importé
 */
typedef enum {
    FILE_TYPE_NONE,      // Aucun fichier
    FILE_TYPE_TEXT,      // Fichier texte (.txt)
    FILE_TYPE_IMAGE,     // Image (JPG, PNG, BMP)
    FILE_TYPE_CRYPT      // Fichier crypté (.crypt)
} FileType;

/**
 * Type de contenu déchiffré
 */
typedef enum {
    CONTENT_TYPE_NONE,   // Aucun contenu
    CONTENT_TYPE_TEXT,   // Texte déchiffré
    CONTENT_TYPE_IMAGE   // Image déchiffrée
} ContentType;

/* ========================================
 * STRUCTURES D'ÉTAT
 * ======================================== */

/**
 * État partagé de l'application
 */
typedef struct {
    // État du fichier
    BOOL file_imported;              // Un fichier a été importé
    FileType file_type;              // Type du fichier importé
    size_t file_size;                // Taille du fichier en octets
    
    // État des opérations
    BOOL encrypted;                  // Données chiffrées disponibles
    BOOL decrypted;                  // Données déchiffrées disponibles
    ContentType decrypted_type;      // Type du contenu déchiffré
    
    // Données en mémoire
    unsigned char* loaded_data;      // Données brutes chargées
    size_t loaded_len;               // Taille des données chargées
    
    // Extension originale (pour images)
    char* original_extension;        // Extension du fichier d'origine
    size_t original_extension_len;   // Longueur de l'extension
    
    // Configuration crypto
    unsigned int mem_kib;            // Mémoire Argon2id (en KiB)
    unsigned int default_mem_kib;    // Valeur par défaut calculée
    
    // État d'opération
    BOOL operation_in_progress;      // Une opération crypto est en cours
    BOOL decrypt_attempt_failed;     // Échec de déchiffrement
    
} SharedState;

/**
 * Contexte global de l'application
 */
typedef struct {
    // Fenêtre principale
    HWND hwnd;
    
    // Handles des contrôles communs
    HWND hKeyEdit;                   // Champ mot de passe
    HWND hTogglePwdBtn;              // Bouton Afficher/Masquer
    HWND hInputEdit;                 // Zone Entrée
    HWND hOutputEdit;                // Zone Sortie
    HWND hProgressBar;               // Barre de progression
    
    // Handles des boutons
    HWND hImportBtn;
    HWND hEncryptBtn;
    HWND hSaveBtn;
    HWND hDecryptBtn;
    HWND hExportTextBtn;
    HWND hExportImageBtn;
    HWND hClearBtn;
    
    // Panneau d'aide
    HWND hHelpPanel;                 // Panneau "Prise en main rapide"
    BOOL help_expanded;              // Panneau déplié/replié
    
    // Polices
    HFONT hFont;                     // Police Courier New
    HFONT hBoldFont;                 // Police grasse
    
    // État partagé
    SharedState state;
    
    // Visibilité du mot de passe
    BOOL pwdVisible;
    
} AppContext;

/**
 * Structure pour les opérations cryptographiques threadées
 */
typedef struct {
    HWND hwnd;
    AppContext* ctx;
    unsigned char* text;
    size_t text_len;
    char* password;
    unsigned int mem_kib;
    BOOL is_encrypt;
    
    // Résultats
    unsigned char* result;
    size_t result_len;
    int thread_result;
    
    // État
    BOOL completed;
    HANDLE hThread;
} CryptoOperation;

/* ========================================
 * MACROS UTILITAIRES
 * ======================================== */

/**
 * Réinitialise l'état partagé
 */
#define RESET_SHARED_STATE(state) \
    do { \
        (state)->file_imported = FALSE; \
        (state)->file_type = FILE_TYPE_NONE; \
        (state)->file_size = 0; \
        (state)->encrypted = FALSE; \
        (state)->decrypted = FALSE; \
        (state)->decrypted_type = CONTENT_TYPE_NONE; \
        (state)->decrypt_attempt_failed = FALSE; \
    } while(0)

/**
 * Vérifie si une opération est en cours
 */
#define IS_OPERATION_BUSY(ctx) ((ctx)->state.operation_in_progress)

/**
 * Active/Désactive un bouton
 */
#define SET_BUTTON_STATE(hwnd, enabled) \
    EnableWindow((hwnd), (enabled) ? TRUE : FALSE)

/**
 * Met en surbrillance un bouton
 */
#define HIGHLIGHT_BUTTON(hwnd, highlight) \
    InvalidateRect((hwnd), NULL, TRUE)

#endif /* CRYPTAGE_STATE_H */