#ifndef CRYPTAGE_H
#define CRYPTAGE_H

#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#define ID_KEY_EDIT         101
#define ID_INPUT_EDIT       102
#define ID_OUTPUT_EDIT      103
#define ID_ENCRYPT_BTN      104
#define ID_DECRYPT_BTN      105
#define ID_SAVE_BIN_BTN     106
#define ID_SAVE_HEX_BTN     107
#define ID_TOGGLE_PWD_BTN   108
#define ID_CLEAR_BTN        111
#define ID_MEMORY_EDIT      112
#define ID_PROGRESS_BAR     113
#define ID_EDIT_TEXT_BTN    115
#define ID_EXPORT_IMG_BTN   117
#define ID_IMPORT_AUTO_BTN  118        // Nouveau bouton d'import automatique

#define WM_USER_PROGRESS    (WM_USER + 1)
#define WM_USER_COMPLETE    (WM_USER + 2)

#define MAX_PASSWORD_LEN    64
#define MAX_TEXT_LEN        2097152
#define SALT_LEN            16
#define NONCE_LEN           12
#define TAG_LEN             16
#define DERIVED_KEY_LEN     32
#define HEX_COLUMNS         16
#define ARGON2_T_COST       2
#define ARGON2_PARALLELISM  1
#define VERSION             361        // Version 36.1 - Interface unifiée + import auto
#define AAD_LEN             28
#define EXTENSION_CODE_OFFSET 24
#define DEFAULT_MEMORY_COST_KIB 16384

#define EXT_JPG  0x4A504720
#define EXT_PNG  0x504E4720
#define EXT_BMP  0x424D5020
#define EXT_NONE 0x00000000

typedef struct SecureMemNode {
    void* ptr;
    size_t size;
    struct SecureMemNode* next;
} SecureMemNode;

typedef struct {
    SecureMemNode* head;
    CRITICAL_SECTION cs;
    BOOL initialized;
} SecureMemRegistry;

typedef struct {
    HWND hKeyEdit, hInputEdit, hOutputEdit, hMemoryEdit, hTogglePwdBtn, hProgressBar;
    BOOL pwdVisible;
    HFONT hFont;
    int progress;
    unsigned int default_mem_kib;
    unsigned char* loaded_data;
    size_t loaded_len;
    BOOL operation_in_progress;
    char* original_extension;
    size_t original_extension_len;
    BOOL decrypt_attempt_failed;
} AppContext;

typedef struct {
    HWND hwnd;
    AppContext* ctx;
    unsigned char* text;
    size_t text_len;
    char* password;
    unsigned int mem_kib;
    unsigned char* result;
    size_t result_len;
    BOOL is_encrypt;
    HANDLE hThread;
    DWORD thread_result;
    BOOL completed;
} CryptoOperation;

void secure_mem_init(void);
void secure_mem_cleanup(void);
void* secure_malloc(HWND hwnd, size_t size, BOOL force_lock);
void secure_free(void* ptr);
void secure_clean_and_free(void* ptr, size_t size);

char* secure_get_edit_text(HWND hEdit, HWND hwnd, const char* context, size_t max_len);
void secure_set_edit_text(HWND hEdit, const char* text, size_t len);

char* bin_to_hex(const unsigned char* data, size_t len);
int hex_to_bin(const char* input, unsigned char** output, size_t* out_len);
int is_valid_hex(const char* hex);

unsigned char* encrypt_data(HWND hwnd, const unsigned char* plaintext, size_t plaintext_len, const char* password, size_t* out_len, unsigned int memory_cost_kib);
int decrypt_data(HWND hwnd, const unsigned char* input, size_t input_len, const char* password, unsigned char** output, size_t* out_len, unsigned int memory_cost_kib);
int derive_key_argon2id(const char* password, const unsigned char* salt, unsigned char* enc_key, unsigned int memory_cost_kib);

void secure_clean(void* data, size_t size);
int is_password_strong(const char* pwd);
int validate_encrypted_data(const unsigned char* input, size_t input_len, unsigned int memory_cost_kib);

void write_uint32_le(unsigned char* buf, uint32_t value);
uint32_t read_uint32_le(const unsigned char* buf);

uint32_t get_extension_code(const char* ext);
const char* get_extension_from_code(uint32_t code);
int validate_encrypted_data_v32(const unsigned char* input, size_t input_len, unsigned int memory_cost_kib, uint32_t* extracted_ext_code);

const char* extract_file_extension(const char* filename);

BOOL load_file_secure(const char* filename, unsigned char** data, size_t* data_len, HWND hwnd, BOOL show_success);
BOOL is_text_file(const char* filename);
BOOL is_image_file(const char* filename);
BOOL validate_image_format(const unsigned char* data, size_t data_len, const char* expected_ext);
BOOL validate_decrypted_image_data(const unsigned char* data, size_t len, const char* expected_ext);

void show_error(HWND hwnd, const char* message, const char* title);
void display_openssl_error(HWND hwnd, const char* operation);
void create_window_controls(HWND hwnd, HINSTANCE hInstance, AppContext* ctx);
void update_memory_default(AppContext* ctx);
void toggle_password_visibility(AppContext* ctx);
void update_progress_bar(HWND hwnd, AppContext* ctx, int percent);

void handle_encrypt(HWND hwnd, AppContext* ctx);
void handle_decrypt(HWND hwnd, AppContext* ctx);
void handle_save_binary(HWND hwnd, AppContext* ctx);
void handle_save_hex(HWND hwnd, AppContext* ctx);
void handle_clear(AppContext* ctx);
void handle_edit_text(HWND hwnd, AppContext* ctx);
void handle_export_image(HWND hwnd, AppContext* ctx);
void handle_import_auto(HWND hwnd, AppContext* ctx);        // Nouvelle fonction

DWORD WINAPI encrypt_thread(LPVOID lpParam);
DWORD WINAPI decrypt_thread(LPVOID lpParam);
void cleanup_crypto_operation(CryptoOperation* op);

void handle_operation_complete_v326(HWND hwnd, AppContext* ctx, WPARAM wParam, LPARAM lParam);

BOOL save_decrypted_text_file_secure(const char* filename, HWND hOutputEdit);
BOOL save_binary_file_secure(const char* filename, const unsigned char* data, size_t data_len, HWND hwnd);
BOOL save_hex_file_secure(const char* filename, const char* hex, HWND hwnd);
BOOL save_image_file_secure(const char* filename, const unsigned char* data, size_t data_len, const char* extension, HWND hwnd);

BOOL open_file_dialog(HWND hwnd, char* filename, size_t filename_size, const char* filter, const char* ext, BOOL save);

BOOL check_virtuallock_result(void* ptr, size_t size, HWND hwnd);
BOOL check_file_operations(FILE* fp, const char* operation, HWND hwnd);
void reset_decrypt_state(AppContext* ctx);

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);

/*
 * HISTORIQUE DES CORRECTIONS V35:
 * 
 * NOUVEAUTÉ : Interface entièrement repensée et simplifiée
 * NOUVEAUTÉ : Bouton unique "Importer le fichier source" avec détection automatique (texte, image, crypté)
 * AMÉLIORATION : Labels "Entrée :" et "Sortie :" plus neutres et cohérents
 * ERGONOMIE : Disposition logique et épurée de la colonne droite
 * TITRE : Cryptage Version 35 (Portable) (c) Bernard DÉMARET
 */

#endif