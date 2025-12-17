/**
 * Cryptage_Core.c
 * Algorithmes cryptographiques et fonctions de base
 * Version 371
 * (c) Bernard DÉMARET - 2025
 */

#include "Cryptage.h"
#include <winsock2.h>
#include <openssl/core_names.h>
#include <windows.h>

// Déclaration anticipée
static BOOL check_virtuallock_result(void* ptr, size_t size, HWND hwnd);

static SecureMemRegistry g_secureRegistry = {NULL, {0}, FALSE};

// V33 - Table de correspondance des codes d'extension
static const struct {
    uint32_t code;
    const char* extension;
} extension_table[] = {
    {EXT_JPG, "jpg"},
    {EXT_PNG, "png"},
    {EXT_BMP, "bmp"},
    {EXT_NONE, NULL}
};
#define NUM_EXTENSIONS (sizeof(extension_table) / sizeof(extension_table[0]))

void secure_mem_init(void) {
    if (!g_secureRegistry.initialized) {
        InitializeCriticalSection(&g_secureRegistry.lock);
        g_secureRegistry.head = NULL;
        g_secureRegistry.initialized = TRUE;
    }
}

void secure_mem_cleanup(void) {
    if (g_secureRegistry.initialized) {
        EnterCriticalSection(&g_secureRegistry.lock);
        SecureMemNode* current = g_secureRegistry.head;
        while (current) {
            SecureMemNode* next = current->next;
            OPENSSL_cleanse(current->ptr, current->size);
            VirtualUnlock(current->ptr, current->size);
            VirtualFree(current->ptr, 0, MEM_RELEASE);
            free(current);
            current = next;
        }
        g_secureRegistry.head = NULL;
        LeaveCriticalSection(&g_secureRegistry.lock);
        DeleteCriticalSection(&g_secureRegistry.lock);
        g_secureRegistry.initialized = FALSE;
    }
}

void* secure_malloc(HWND hwnd, size_t size, BOOL force_lock) {
    if (!g_secureRegistry.initialized) {
        secure_mem_init();
    }
    void* ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        if (hwnd) show_error(hwnd, "Échec de l'allocation mémoire sécurisée", "Erreur Mémoire");
        return NULL;
    }
    SecureZeroMemory(ptr, size);
    SecureMemNode* node = malloc(sizeof(SecureMemNode));
    if (!node) {
        VirtualFree(ptr, 0, MEM_RELEASE);
        if (hwnd) show_error(hwnd, "Échec de l'allocation du nœud de registre mémoire", "Erreur Mémoire");
        return NULL;
    }
    node->ptr = ptr;
    node->size = size;
    
    if (force_lock) {
        check_virtuallock_result(ptr, size, hwnd);
    }
    
    EnterCriticalSection(&g_secureRegistry.lock);
    node->next = g_secureRegistry.head;
    g_secureRegistry.head = node;
    LeaveCriticalSection(&g_secureRegistry.lock);
    return ptr;
}

void secure_free(void* ptr) {
    if (!ptr || !g_secureRegistry.initialized) return;
    EnterCriticalSection(&g_secureRegistry.lock);
    SecureMemNode* current = g_secureRegistry.head;
    SecureMemNode* prev = NULL;
    while (current && current->ptr != ptr) {
        prev = current;
        current = current->next;
    }
    if (current) {
        if (prev) {
            prev->next = current->next;
        } else {
            g_secureRegistry.head = current->next;
        }
        OPENSSL_cleanse(current->ptr, current->size);
        VirtualUnlock(current->ptr, current->size);
        VirtualFree(current->ptr, 0, MEM_RELEASE);
        free(current);
    }
    LeaveCriticalSection(&g_secureRegistry.lock);
}

void secure_clean_and_free(void* ptr, size_t size) {
    if (ptr) {
        OPENSSL_cleanse(ptr, size);
        secure_free(ptr);
    }
}

BOOL check_virtuallock_result(void* ptr, size_t size, HWND hwnd) {
    BOOL result = VirtualLock(ptr, size);
    if (!result) {
        DWORD error = GetLastError();
        #ifdef _DEBUG
        char debug_msg[256];
        snprintf(debug_msg, sizeof(debug_msg), "VirtualLock failed (error %lu) - continuing without lock", error);
        OutputDebugStringA(debug_msg);
        #endif
    }
    return result;
}

BOOL check_file_operations(FILE* fp, const char* operation, HWND hwnd) {
    if (!fp) {
        char error_msg[512];
        snprintf(error_msg, sizeof(error_msg), "Échec de %s : %s", operation, strerror(errno));
        if (hwnd) show_error(hwnd, error_msg, "Erreur Fichier");
        return FALSE;
    }
    return TRUE;
}

char* secure_get_edit_text(HWND hEdit, HWND hwnd, const char* context, size_t max_len) {
    int wide_len = GetWindowTextLengthW(hEdit);
    if (wide_len > (int)max_len) {
        show_error(hwnd, "Entrée trop longue : dépasse la limite maximale (10 Mo pour données, 64 caractères pour mot de passe)", context);
        return NULL;
    }
    
    if (wide_len == 0) {
        char* empty = secure_malloc(hwnd, 1, TRUE);
        if (empty) empty[0] = '\0';
        return empty;
    }
    
    wchar_t* wide_text = (wchar_t*)secure_malloc(hwnd, (wide_len + 1) * sizeof(wchar_t), TRUE);
    if (!wide_text) {
        show_error(hwnd, "Échec de l'allocation mémoire sécurisée pour le texte UTF-16", context);
        return NULL;
    }
    
    int chars_copied = GetWindowTextW(hEdit, wide_text, wide_len + 1);
    if (chars_copied != wide_len) {
        show_error(hwnd, "Erreur lors de la récupération du texte", context);
        secure_free(wide_text);
        return NULL;
    }
    
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide_text, wide_len, NULL, 0, NULL, NULL);
    if (utf8_len <= 0) {
        show_error(hwnd, "Erreur de conversion d'encodage UTF-16 vers UTF-8", context);
        secure_free(wide_text);
        return NULL;
    }
    
    if (context && strstr(context, "Chiffrement") && utf8_len > MAX_TEXT_LEN) {
        show_error(hwnd, "Texte trop long après conversion UTF-8 : dépasse la limite de 10 Mo", context);
        secure_free(wide_text);
        return NULL;
    }
    
    char* utf8_text = secure_malloc(hwnd, utf8_len + 1, TRUE);
    if (!utf8_text) {
        show_error(hwnd, "Échec de l'allocation mémoire sécurisée pour le texte UTF-8", context);
        secure_free(wide_text);
        return NULL;
    }
    
    int bytes_written = WideCharToMultiByte(CP_UTF8, 0, wide_text, wide_len, utf8_text, utf8_len, NULL, NULL);
    secure_free(wide_text);
    
    if (bytes_written != utf8_len) {
        show_error(hwnd, "Erreur lors de la conversion UTF-16 vers UTF-8", context);
        secure_free(utf8_text);
        return NULL;
    }
    
    utf8_text[utf8_len] = '\0';
    
    return utf8_text;
}

void secure_set_edit_text(HWND hEdit, const char* text, size_t len) {
    if (!text || !hEdit) return;
    
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, text, (int)len, NULL, 0);
    if (wide_len <= 0) {
        wide_len = MultiByteToWideChar(CP_ACP, 0, text, (int)len, NULL, 0);
    }
    
    if (wide_len <= 0) {
        char* display_text = secure_malloc(NULL, len + 1, FALSE);
        if (!display_text) return;
        memcpy(display_text, text, len);
        display_text[len] = '\0';
        SetWindowTextA(hEdit, display_text);
        secure_clean_and_free(display_text, len + 1);
        UpdateWindow(hEdit);
        return;
    }
    
    wchar_t* wide_text = (wchar_t*)secure_malloc(NULL, (wide_len + 1) * sizeof(wchar_t), FALSE);
    if (!wide_text) return;
    
    int result = MultiByteToWideChar(CP_UTF8, 0, text, (int)len, wide_text, wide_len);
    if (result <= 0) {
        result = MultiByteToWideChar(CP_ACP, 0, text, (int)len, wide_text, wide_len);
    }
    
    if (result > 0) {
        wide_text[result] = L'\0';
        SetWindowTextW(hEdit, wide_text);
    } else {
        char* ansi_text = secure_malloc(NULL, len + 1, FALSE);
        if (ansi_text) {
            memcpy(ansi_text, text, len);
            ansi_text[len] = '\0';
            SetWindowTextA(hEdit, ansi_text);
            secure_clean_and_free(ansi_text, len + 1);
        }
    }
    
    secure_free(wide_text);
    UpdateWindow(hEdit);
}

char* bin_to_hex(const unsigned char* data, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    const size_t chars_per_line = HEX_COLUMNS * 3;
    const size_t num_lines = (len + HEX_COLUMNS - 1) / HEX_COLUMNS;
    const size_t buffer_size = len * 3 + num_lines * 2 + 1;
    char* buffer = secure_malloc(NULL, buffer_size, FALSE);
    if (!buffer) return NULL;
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        buffer[pos++] = hex[data[i] >> 4];
        buffer[pos++] = hex[data[i] & 0x0F];
        buffer[pos++] = ' ';
        if ((i + 1) % HEX_COLUMNS == 0 && i + 1 < len) {
            buffer[pos++] = '\r';
            buffer[pos++] = '\n';
        }
    }
    if (pos > 0 && buffer[pos - 1] == ' ') pos--;
    buffer[pos] = '\0';
    return buffer;
}

int is_valid_hex(const char* hex) {
    const size_t len = strlen(hex);
    if (len == 0) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)hex[i]) && !isspace((unsigned char)hex[i])) return 0;
    }
    return 1;
}

int hex_to_bin(const char* input, unsigned char** output, size_t* out_len) {
    if (!input || !output || !out_len) return -1;
    size_t hex_digits = 0;
    for (const char* p = input; *p; ++p) {
        if (isxdigit((unsigned char)*p)) {
            hex_digits++;
        } else if (isspace((unsigned char)*p)) {
            continue;
        } else {
            return -1;
        }
    }
    if (hex_digits == 0) {
        *output = NULL;
        *out_len = 0;
        return 0;
    }
    if (hex_digits % 2 != 0) {
        return -1;
    }
    size_t bytes = hex_digits / 2;
    unsigned char* buf = secure_malloc(NULL, bytes, FALSE);
    if (!buf) return -1;
    size_t idx = 0;
    int high = -1;
    for (const char* p = input; *p; ++p) {
        if (!isxdigit((unsigned char)*p)) continue;
        int val;
        if (*p >= '0' && *p <= '9') val = *p - '0';
        else if (*p >= 'a' && *p <= 'f') val = *p - 'a' + 10;
        else val = *p - 'A' + 10;
        if (high < 0) {
            high = val;
        } else {
            buf[idx++] = (unsigned char)((high << 4) | val);
            high = -1;
        }
    }
    if (idx != bytes) {
        secure_free(buf);
        return -1;
    }
    *output = buf;
    *out_len = bytes;
    return 0;
}

int is_password_strong(const char* pwd) {
    const size_t len = strlen(pwd);
    if (len < 8 || len > MAX_PASSWORD_LEN) return 0;
    int has_upper = 0, has_lower = 0, has_digit = 0, has_symbol = 0;
    for (size_t i = 0; pwd[i]; i++) {
        if (isupper((unsigned char)pwd[i])) has_upper = 1;
        else if (islower((unsigned char)pwd[i])) has_lower = 1;
        else if (isdigit((unsigned char)pwd[i])) has_digit = 1;
        else if (ispunct((unsigned char)pwd[i])) has_symbol = 1;
    }
    return has_upper && has_lower && has_digit && has_symbol;
}

void secure_clean(void* data, size_t size) {
    if (data) OPENSSL_cleanse(data, size);
}

uint32_t get_extension_code(const char* ext) {
    if (!ext) return EXT_NONE;
    
    char ext_lower[8] = {0};
    size_t ext_len = strlen(ext);
    if (ext_len > 7) return EXT_NONE;
    
    for (size_t i = 0; i < ext_len; i++) {
        ext_lower[i] = tolower((unsigned char)ext[i]);
    }
    
    if (strcmp(ext_lower, "jpg") == 0 || strcmp(ext_lower, "jpeg") == 0) {
        return EXT_JPG;
    } else if (strcmp(ext_lower, "png") == 0) {
        return EXT_PNG;
    } else if (strcmp(ext_lower, "bmp") == 0) {
        return EXT_BMP;
    }
    
    return EXT_NONE;
}

const char* get_extension_from_code(uint32_t code) {
    for (size_t i = 0; i < NUM_EXTENSIONS; i++) {
        if (extension_table[i].code == code) {
            return extension_table[i].extension;
        }
    }
    return NULL;
}

int derive_key_argon2id(const char* password, const unsigned char* salt, unsigned char* enc_key, unsigned int memory_cost_kib) {
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) return 0;
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        EVP_KDF_free(kdf);
        return 0;
    }

    uint32_t iter = ARGON2_T_COST;
    uint32_t memcost = memory_cost_kib;
    uint32_t lanes = ARGON2_PARALLELISM;

    OSSL_PARAM params[7];
    OSSL_PARAM *p = params;

    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, SALT_LEN);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void*)password, (password ? (unsigned int)strlen(password) : 0));
    *p++ = OSSL_PARAM_construct_end();

    int ret = EVP_KDF_derive(kctx, enc_key, DERIVED_KEY_LEN, params);

    if (ret <= 0) {
        OPENSSL_cleanse(enc_key, DERIVED_KEY_LEN);
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret > 0;
}

void write_uint32_le(unsigned char* buf, uint32_t value) {
    buf[0] = (unsigned char)(value & 0xFF);
    buf[1] = (unsigned char)((value >> 8) & 0xFF);
    buf[2] = (unsigned char)((value >> 16) & 0xFF);
    buf[3] = (unsigned char)((value >> 24) & 0xFF);
}

uint32_t read_uint32_le(const unsigned char* buf) {
    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

BOOL is_text_file(const char* filename) {
    if (!filename) return FALSE;
    const char* ext = strrchr(filename, '.');
    if (!ext) return FALSE;
    return (stricmp(ext, ".txt") == 0 || stricmp(ext, ".TXT") == 0);
}

BOOL is_image_file(const char* filename) {
    if (!filename) return FALSE;
    const char* ext = strrchr(filename, '.');
    if (!ext) return FALSE;
    
    char ext_lower[8] = {0};
    size_t ext_len = strlen(ext);
    if (ext_len > 7) return FALSE;
    
    for (size_t i = 0; i < ext_len; i++) {
        ext_lower[i] = tolower((unsigned char)ext[i]);
    }
    
    return (strcmp(ext_lower, ".jpg") == 0 || strcmp(ext_lower, ".jpeg") == 0 || 
            strcmp(ext_lower, ".png") == 0 || strcmp(ext_lower, ".bmp") == 0 ||
            strcmp(ext_lower, ".JPG") == 0 || strcmp(ext_lower, ".JPEG") == 0 || 
            strcmp(ext_lower, ".PNG") == 0 || strcmp(ext_lower, ".BMP") == 0);
}

BOOL validate_image_format(const unsigned char* data, size_t data_len, const char* expected_ext) {
    if (!data || data_len < 8) return FALSE;
    
    char ext_lower[8] = {0};
    if (expected_ext) {
        size_t ext_len = strlen(expected_ext);
        for (size_t i = 0; i < ext_len && i < 7; i++) {
            ext_lower[i] = tolower((unsigned char)expected_ext[i]);
        }
    }
    
    if (strcmp(ext_lower, "jpg") == 0 || strcmp(ext_lower, "jpeg") == 0) {
        return (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF);
    } else if (strcmp(ext_lower, "png") == 0) {
        return (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 &&
                data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A);
    } else if (strcmp(ext_lower, "bmp") == 0) {
        return (data[0] == 0x42 && data[1] == 0x4D);
    }
    
    return FALSE;
}

BOOL validate_decrypted_image_data(const unsigned char* data, size_t len, const char* expected_ext) {
    if (!data || len < 8) return FALSE;
    
    if (expected_ext) {
        char ext_lower[8] = {0};
        size_t ext_len = strlen(expected_ext);
        for (size_t i = 0; i < ext_len && i < 7; i++) {
            ext_lower[i] = tolower((unsigned char)expected_ext[i]);
        }
        
        if (strcmp(ext_lower, "jpg") == 0 || strcmp(ext_lower, "jpeg") == 0) {
            return (len >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF);
        } else if (strcmp(ext_lower, "png") == 0) {
            return (len >= 8 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && 
                   data[3] == 0x47 && data[4] == 0x0D && data[5] == 0x0A && 
                   data[6] == 0x1A && data[7] == 0x0A);
        } else if (strcmp(ext_lower, "bmp") == 0) {
            return (len >= 2 && data[0] == 0x42 && data[1] == 0x4D);
        }
    }
    
    return validate_image_format(data, len, expected_ext);
}

const char* extract_file_extension(const char* filename) {
    if (!filename) return NULL;
    const char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) return NULL;
    return dot + 1;
}

unsigned char* encrypt_data(HWND hwnd, const unsigned char* plaintext, size_t plaintext_len, const char* password, size_t* out_len, unsigned int memory_cost_kib) {
    if (plaintext_len > MAX_TEXT_LEN) {
        show_error(hwnd, "Données trop longues : limite de 10 Mo dépassée. Divisez votre fichier ou utilisez un outil adapté.", "Erreur Chiffrement");
        return NULL;
    }
    
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    unsigned char* enc_key = secure_malloc(hwnd, DERIVED_KEY_LEN, TRUE);
    unsigned char* ciphertext = NULL, *output = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    int len, total_len = 0;
    
    if (!enc_key) return NULL;
    
    if (!RAND_bytes(salt, SALT_LEN) || !RAND_bytes(nonce, NONCE_LEN)) {
        display_openssl_error(hwnd, "Génération de sel ou nonce");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        return NULL;
    }
    
    if (!derive_key_argon2id(password, salt, enc_key, memory_cost_kib)) {
        display_openssl_error(hwnd, "Dérivation de la clé");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        return NULL;
    }
    
    uint32_t extension_code = EXT_NONE;
    if (plaintext_len >= 8) {
        if (plaintext[0] == 0xFF && plaintext[1] == 0xD8 && plaintext[2] == 0xFF) {
            extension_code = EXT_JPG;
        } else if (plaintext[0] == 0x89 && plaintext[1] == 0x50 && plaintext[2] == 0x4E && 
                  plaintext[3] == 0x47 && plaintext[4] == 0x0D && plaintext[5] == 0x0A && 
                  plaintext[6] == 0x1A && plaintext[7] == 0x0A) {
            extension_code = EXT_PNG;
        } else if (plaintext[0] == 0x42 && plaintext[1] == 0x4D) {
            extension_code = EXT_BMP;
        }
    }
    
    unsigned char aad_data[AAD_LEN];
    write_uint32_le(aad_data, VERSION);
    write_uint32_le(aad_data + 4, SALT_LEN);
    write_uint32_le(aad_data + 8, NONCE_LEN);
    write_uint32_le(aad_data + 12, TAG_LEN);
    write_uint32_le(aad_data + 16, (uint32_t)plaintext_len);
    write_uint32_le(aad_data + 20, memory_cost_kib);
    write_uint32_le(aad_data + EXTENSION_CODE_OFFSET, extension_code);
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        show_error(hwnd, "Échec de l'allocation du contexte OpenSSL", "Erreur Chiffrement");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        return NULL;
    }
    
    ciphertext = secure_malloc(hwnd, plaintext_len + EVP_MAX_BLOCK_LENGTH, TRUE);
    if (!ciphertext) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    ERR_clear_error();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, enc_key, nonce) != 1) {
        display_openssl_error(hwnd, "Initialisation d'AES-256-GCM");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_EncryptUpdate(ctx, NULL, &len, aad_data, AAD_LEN) != 1) {
        display_openssl_error(hwnd, "Fourniture des données associées (AAD)");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        display_openssl_error(hwnd, "Chiffrement des données");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        display_openssl_error(hwnd, "Finalisation du chiffrement");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        display_openssl_error(hwnd, "Récupération de la balise GCM");
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    *out_len = AAD_LEN + SALT_LEN + NONCE_LEN + TAG_LEN + total_len;
    output = secure_malloc(hwnd, *out_len, TRUE);
    if (!output) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    size_t offset = 0;
    memcpy(output + offset, aad_data, AAD_LEN); offset += AAD_LEN;
    memcpy(output + offset, salt, SALT_LEN); offset += SALT_LEN;
    memcpy(output + offset, nonce, NONCE_LEN); offset += NONCE_LEN;
    memcpy(output + offset, tag, TAG_LEN); offset += TAG_LEN;
    memcpy(output + offset, ciphertext, total_len);

    secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
    secure_free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return output;
}
int decrypt_data(HWND hwnd, const unsigned char* input, size_t input_len, const char* password, unsigned char** output, size_t* out_len, unsigned int memory_cost_kib) {
    *output = NULL;
    *out_len = 0;
    uint32_t version = 0;

    // Validation basique : taille minimale et version
    if (input_len < AAD_LEN + SALT_LEN + NONCE_LEN + TAG_LEN) {
        return 2;
    }

    version = read_uint32_le(input);

    // V37 : Accepter UNIQUEMENT la version 370
    if (version != CURRENT_VERSION) {
        return 2;
    }

    uint32_t stored_mem_kib = read_uint32_le(input + 20);
    if (stored_mem_kib < 4096 || stored_mem_kib > 1048576) {
        return 2;
    }

    // Utiliser le paramètre stocké dans le fichier
    memory_cost_kib = stored_mem_kib;

    uint32_t ciphertext_len = read_uint32_le(input + 16);
    size_t offset = AAD_LEN;
    const unsigned char* salt = input + offset; offset += SALT_LEN;
    const unsigned char* nonce = input + offset; offset += NONCE_LEN;
    const unsigned char* tag = input + offset; offset += TAG_LEN;
    const unsigned char* ciphertext = input + offset;

    unsigned char* enc_key = secure_malloc(hwnd, DERIVED_KEY_LEN, TRUE);
    if (!enc_key) return 3;

    if (!derive_key_argon2id(password, salt, enc_key, memory_cost_kib)) {
    secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
    return 4;
    }

    unsigned char aad_data[AAD_LEN];
    memcpy(aad_data, input, AAD_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        return 3;
    }   

    *output = secure_malloc(hwnd, ciphertext_len, TRUE);
    if (!*output) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        EVP_CIPHER_CTX_free(ctx);
        return 3;
    }

    int len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, enc_key, nonce) != 1) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(*output);
        *output = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return 5;
    }

    if (EVP_DecryptUpdate(ctx, NULL, &len, aad_data, AAD_LEN) != 1) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(*output);
        *output = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return 5;
    }

    size_t total_len = 0;
    if (EVP_DecryptUpdate(ctx, *output, &len, ciphertext, ciphertext_len) != 1) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(*output);
        *output = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return 5;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(*output);
        *output = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return 5;
    }

    if (EVP_DecryptFinal_ex(ctx, *output + total_len, &len) != 1) {
        secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
        secure_free(*output);
        *output = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    total_len += len;

    *out_len = total_len;

    secure_clean_and_free(enc_key, DERIVED_KEY_LEN);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

BOOL load_file_secure(const char* filename, unsigned char** data, size_t* data_len, HWND hwnd, BOOL show_success) {
    *data = NULL;
    *data_len = 0;

    FILE* fp = fopen(filename, "rb");
    if (!check_file_operations(fp, "l'ouverture du fichier", hwnd)) {
        return FALSE;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        show_error(hwnd, "Erreur lors du positionnement dans le fichier", "Erreur Chargement");
        fclose(fp);
        return FALSE;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
    show_error(hwnd, "Erreur lors de la détermination de la taille du fichier", "Erreur Chargement");
    fclose(fp);
    return FALSE;
    }

    if (file_size > MAX_TEXT_LEN) {
        show_error(hwnd, "Fichier trop volumineux : limite de 10 Mo dépassée. Divisez votre fichier ou utilisez un outil adapté.", "Erreur Chargement");
        fclose(fp);
        return FALSE;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        show_error(hwnd, "Erreur lors du retour au début du fichier", "Erreur Chargement");
        fclose(fp);
        return FALSE;
    }

    *data = secure_malloc(hwnd, (size_t)file_size + 1, TRUE);
    if (!*data) {
        fclose(fp);
        return FALSE;
    }

    size_t bytes_read = fread(*data, 1, (size_t)file_size, fp);

    if (fclose(fp) != 0) {
        show_error(hwnd, "Avertissement : échec de la fermeture propre du fichier", "Avertissement");
    }

    if (bytes_read != (size_t)file_size) {
        show_error(hwnd, "Échec de la lecture complète du fichier", "Erreur Chargement");
        secure_clean_and_free(*data, (size_t)file_size + 1);
        *data = NULL;
        *data_len = 0;
        return FALSE;
    }

    (*data)[bytes_read] = '\0';
    *data_len = bytes_read;

    if (show_success) {
        MessageBoxA(hwnd, "Fichier chargé avec succès", "Succès", MB_ICONINFORMATION);
    }
    return TRUE;
}
