/**
 * Cryptage.h
 * Header principal - Version 371 
 * (c) Bernard DÉMARET - 2025
 */

#ifndef CRYPTAGE_H
#define CRYPTAGE_H

/* ========================================
 * INCLUDES SYSTÈME
 * ======================================== */

#include <winsock2.h>        // IMPORTANT : avant windows.h
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

/* ========================================
 * CONSTANTES CRYPTOGRAPHIQUES
 * ======================================== */

// Tailles des éléments cryptographiques
#define SALT_LEN                32      // Longueur du sel Argon2id
#define NONCE_LEN               12      // Longueur du nonce AES-GCM
#define TAG_LEN                 16      // Longueur du tag d'authentification
#define KEY_LEN                 32      // Longueur de la clé AES-256

// Paramètres Argon2id
#define DEFAULT_MEMORY_COST_KIB 16384   // 16 Mo par défaut
#define TIME_COST               3       // 3 itérations
#define PARALLELISM             1       // 1 thread

// Compatibilité noms alternatifs (pour Cryptage_Core.c)
#define ARGON2_T_COST           TIME_COST
#define ARGON2_PARALLELISM      PARALLELISM
#define DERIVED_KEY_LEN         KEY_LEN

// Longueur des données additionnelles authentifiées (AAD)
#define AAD_LEN                 24      // Version(4) + Reserved(16) + MemKiB(4)

// Offsets dans l'AAD
#define VERSION_OFFSET          0       // Offset de la version
#define EXTENSION_CODE_OFFSET   4       // Offset du code d'extension (réservé)
#define MEMORY_OFFSET           20      // Offset du paramètre mémoire

// Codes d'extension d'images (dans la zone réservée AAD)
#define EXT_NONE                0
#define EXT_JPG                 1
#define EXT_PNG                 2
#define EXT_BMP                 3

// Formatage hexadécimal
#define HEX_COLUMNS             16      // 16 octets par ligne

// Limites
#define MAX_PASSWORD_LEN        64
#define MAX_TEXT_LEN            (10 * 1024 * 1024)  // 10 Mo

/* ========================================
 * STRUCTURE DES DONNÉES CHIFFRÉES V37
 * ======================================== */

/**
 * Format du fichier crypté :
 * 
 * [AAD - 24 octets]
 *   - Version (4 octets, little-endian) : 370
 *   - Réservé (16 octets) : extensibilité future
 *   - MemKiB (4 octets, little-endian) : paramètre mémoire Argon2id
 * 
 * [SALT - 32 octets]
 *   - Sel aléatoire pour Argon2id
 * 
 * [NONCE - 12 octets]
 *   - Nonce aléatoire pour AES-GCM
 * 
 * [CIPHERTEXT - longueur variable]
 *   - Données chiffrées
 * 
 * [TAG - 16 octets]
 *   - Tag d'authentification AES-GCM
 */

#define CURRENT_VERSION         371     // Version actuelle : 37.1
#define VERSION                 CURRENT_VERSION

/* ========================================
 * MESSAGES WINDOWS PERSONNALISÉS
 * ======================================== */

#define WM_USER_PROGRESS        (WM_USER + 1)
#define WM_USER_COMPLETE        (WM_USER + 2)

/* ========================================
 * INCLUDE DES STRUCTURES D'ÉTAT
 * ======================================== */

#include "Cryptage_State.h"

/* ========================================
 * DÉCLARATIONS DES FONCTIONS CRYPTOGRAPHIQUES
 * (Cryptage_Core.c)
 * ======================================== */

/**
 * Initialise OpenSSL en mode portable
 */
BOOL init_portable_openssl(void);

/**
 * Chiffre des données avec AES-256-GCM + Argon2id
 */
unsigned char* encrypt_data(HWND hwnd, const unsigned char* plaintext, 
                           size_t plaintext_len, const char* password,
                           size_t* ciphertext_len, unsigned int mem_kib);

/**
 * Déchiffre des données avec AES-256-GCM + Argon2id
 * 
 * @return 0 en cas de succès, 1 si mot de passe incorrect, -1 en cas d'erreur
 */
int decrypt_data(HWND hwnd, const unsigned char* ciphertext, 
                size_t ciphertext_len, const char* password,
                unsigned char** plaintext, size_t* plaintext_len,
                unsigned int mem_kib);

/* ========================================
 * UTILITAIRES CRYPTOGRAPHIQUES
 * ======================================== */

/**
 * Vérifie la robustesse d'un mot de passe
 * Critères : 8-64 caractères, maj+min+chiffre+symbole
 */
BOOL is_password_strong(const char* password);

/**
 * Lit un entier 32 bits en little-endian
 */
uint32_t read_uint32_le(const unsigned char* buf);

/**
 * Écrit un entier 32 bits en little-endian
 */
void write_uint32_le(unsigned char* buf, uint32_t value);

/* ========================================
 * GESTION MÉMOIRE SÉCURISÉE
 * (Cryptage_Core.c)
 * ======================================== */

/**
 * Initialise le système de gestion mémoire sécurisée
 */
void secure_mem_init(void);

/**
 * Nettoie le système de gestion mémoire sécurisée
 */
void secure_mem_cleanup(void);

/**
 * Alloue de la mémoire sécurisée (non swappable)
 */
void* secure_malloc(HWND hwnd, size_t size, BOOL zero_on_free);

/**
 * Libère de la mémoire sécurisée
 */
void secure_free(void* ptr);

/**
 * Efface puis libère de la mémoire sécurisée
 */
void secure_clean_and_free(void* ptr, size_t size);

/**
 * Récupère le texte d'un contrôle Edit de manière sécurisée
 */
char* secure_get_edit_text(HWND hEdit, HWND hwnd, const char* error_title, 
                           size_t max_len);

/**
 * Définit le texte d'un contrôle Edit de manière sécurisée
 */
void secure_set_edit_text(HWND hEdit, const char* text, size_t text_len);

/* ========================================
 * CONVERSION HEXADÉCIMAL
 * (Cryptage_Core.c)
 * ======================================== */

/**
 * Convertit des données binaires en hexadécimal
 */
char* bin_to_hex(const unsigned char* bin, size_t bin_len);

/**
 * Convertit une chaîne hexadécimale en binaire
 */
int hex_to_bin(const char* hex, unsigned char** bin, size_t* bin_len);

/**
 * Vérifie si une chaîne est hexadécimale valide
 */
BOOL is_valid_hex(const char* hex);

/* ========================================
 * GESTION DES FICHIERS
 * (Cryptage_Core.c)
 * ======================================== */

/**
 * Charge un fichier de manière sécurisée
 */
BOOL load_file_secure(const char* filename, unsigned char** data, 
                      size_t* len, HWND hwnd, BOOL text_mode);

/**
 * Vérifie les opérations sur fichiers
 */
BOOL check_file_operations(FILE* fp, const char* operation, HWND hwnd);

/* ========================================
 * FONCTIONS UI COMMUNES
 * (Cryptage_UI_Common.c)
 * ======================================== */

// Messages
void show_error(HWND hwnd, const char* message, const char* title);
void show_success(HWND hwnd, const char* message, const char* title);
void display_openssl_error(HWND hwnd, const char* operation);

// Dialogues de fichiers
BOOL open_file_dialog(HWND hwnd, char* filename, size_t filename_size, 
                      const char* filter, const char* ext, BOOL save);

// Barre de progression
void update_progress_bar(HWND hwnd, AppContext* ctx, int percent);
void reset_progress_bar(AppContext* ctx);

// Mot de passe
void toggle_password_visibility(AppContext* ctx);

// Mémoire Argon2id
void update_memory_default(AppContext* ctx);
unsigned int get_memory_param(AppContext* ctx);

// Sauvegarde de fichiers
BOOL save_binary_file_secure(const char* filename, const unsigned char* data, 
                              size_t data_len, HWND hwnd);
BOOL save_decrypted_text_file_secure(const char* filename, HWND hOutputEdit);
BOOL save_image_file_secure(const char* filename, const unsigned char* data, 
                             size_t data_len, const char* extension, HWND hwnd);

// Détection de type
FileType detect_file_type(const unsigned char* data, size_t data_len, 
                          AppContext* ctx);

// Réinitialisation
void reset_decrypt_state(AppContext* ctx);
void handle_clear(AppContext* ctx);

// Opérations crypto
void cleanup_crypto_operation(CryptoOperation* op);

// Polices
void create_fonts(AppContext* ctx);
void destroy_fonts(AppContext* ctx);

/* ========================================
 * INTERFACE UTILISATEUR
 * (Cryptage_UI.c)
 * ======================================== */

/**
 * Procédure de fenêtre principale
 */
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

/**
 * Crée les contrôles de l'interface
 */
void create_ui_controls(HWND hwnd, HINSTANCE hInstance, AppContext* ctx);

/**
 * Met à jour l'état des boutons
 */
void update_buttons(AppContext* ctx);

/* ========================================
 * REGISTRE DE MÉMOIRE SÉCURISÉE
 * ======================================== */

typedef struct SecureMemEntry {
    void* ptr;
    size_t size;
    BOOL zero_on_free;
    struct SecureMemEntry* next;
} SecureMemEntry;

typedef SecureMemEntry SecureMemNode;

typedef struct {
    SecureMemEntry* head;
    CRITICAL_SECTION lock;
    BOOL initialized;
} SecureMemRegistry;

/* ========================================
 * MACROS UTILITAIRES
 * ======================================== */

#define SECURE_ZERO(ptr, size) \
    do { \
        if ((ptr) && (size) > 0) { \
            SecureZeroMemory((ptr), (size)); \
        } \
    } while(0)

#define IS_VALID_PTR(ptr) ((ptr) != NULL)

#define MIN_ENCRYPTED_SIZE (AAD_LEN + SALT_LEN + NONCE_LEN + TAG_LEN)

/* ========================================
 * DÉCLARATIONS POUR LA COMPATIBILITÉ
 * ======================================== */

#ifdef __cplusplus
extern "C" {
#endif

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTAGE_H */
