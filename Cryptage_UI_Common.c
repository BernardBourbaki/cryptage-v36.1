/**
 * Cryptage_UI_Common.c
 * Fonctions UI communes - Version 371
 * (c) Bernard DÉMARET - 2025
 */

#include "Cryptage.h"
#include "Cryptage_State.h"
#include <windows.h>
#include <commctrl.h>

/* ========================================
 * GESTION DES MESSAGES ET ERREURS
 * ======================================== */

/**
 * Affiche un message d'erreur
 */
void show_error(HWND hwnd, const char* message, const char* title) {
    MessageBoxA(hwnd, message, title, MB_ICONWARNING | MB_OK);
}

/**
 * Affiche un message de succès
 */
void show_success(HWND hwnd, const char* message, const char* title) {
    MessageBoxA(hwnd, message, title, MB_ICONINFORMATION | MB_OK);
}

/**
 * Affiche les erreurs OpenSSL détaillées
 */
void display_openssl_error(HWND hwnd, const char* operation) {
    char err_msg[256];
    unsigned long err = ERR_get_error();
    
    if (err) {
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        char full_msg[512];
        snprintf(full_msg, sizeof(full_msg), 
            "Erreur lors de %s :\n\n%s", operation, err_msg);
        MessageBoxA(hwnd, full_msg, "Erreur OpenSSL", MB_ICONERROR);
        ERR_clear_error();
    } else {
        char full_msg[512];
        snprintf(full_msg, sizeof(full_msg), 
            "Erreur inconnue lors de %s", operation);
        MessageBoxA(hwnd, full_msg, "Erreur OpenSSL", MB_ICONERROR);
    }
}

/* ========================================
 * GESTION DES DIALOGUES DE FICHIERS
 * ======================================== */

/**
 * Ouvre une boîte de dialogue pour sélectionner/sauvegarder un fichier
 */
BOOL open_file_dialog(HWND hwnd, char* filename, size_t filename_size, 
                      const char* filter, const char* ext, BOOL save) {
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(OPENFILENAMEA);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = (DWORD)filename_size;
    ofn.lpstrDefExt = ext;
    ofn.Flags = OFN_PATHMUSTEXIST | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    
    return save ? GetSaveFileNameA(&ofn) : GetOpenFileNameA(&ofn);
}

/* ========================================
 * GESTION DE LA BARRE DE PROGRESSION
 * ======================================== */

/**
 * Met à jour la barre de progression
 */
void update_progress_bar(HWND hwnd, AppContext* ctx, int percent) {
    if (ctx->hProgressBar) {
        SendMessageA(ctx->hProgressBar, PBM_SETPOS, percent, 0);
        UpdateWindow(ctx->hProgressBar);
    }
}

/**
 * Réinitialise la barre de progression
 */
void reset_progress_bar(AppContext* ctx) {
    if (ctx->hProgressBar) {
        SendMessageA(ctx->hProgressBar, PBM_SETPOS, 0, 0);
    }
}

/* ========================================
 * GESTION DU MOT DE PASSE
 * ======================================== */

/**
 * Bascule la visibilité du mot de passe
 */
void toggle_password_visibility(AppContext* ctx) {
    ctx->pwdVisible = !ctx->pwdVisible;
    SendMessageA(ctx->hKeyEdit, EM_SETPASSWORDCHAR, 
                 ctx->pwdVisible ? 0 : '*', 0);
    InvalidateRect(ctx->hKeyEdit, NULL, TRUE);
    SetWindowTextA(ctx->hTogglePwdBtn, 
                   ctx->pwdVisible ? "Masquer" : "Afficher");
}

/* ========================================
 * GESTION DE LA MÉMOIRE ARGON2ID
 * ======================================== */

/**
 * Calcule et met à jour la valeur par défaut de la mémoire Argon2id
 * (25% de la RAM disponible, entre 4 Mo et 1024 Mo)
 */
void update_memory_default(AppContext* ctx) {
    MEMORYSTATUSEX mem_status = {sizeof(MEMORYSTATUSEX)};
    
    if (GlobalMemoryStatusEx(&mem_status)) {
        ULONGLONG available_mem_kb = mem_status.ullAvailPhys / 1024;
        unsigned int default_mem_kib = (unsigned int)(available_mem_kb * 0.25);
        
        // Limites : 4 Mo minimum, 1024 Mo maximum
        if (default_mem_kib < 4096) default_mem_kib = 4096;
        if (default_mem_kib > 1048576) default_mem_kib = 1048576;
        
        ctx->state.default_mem_kib = default_mem_kib;
        ctx->state.mem_kib = default_mem_kib;
    } else {
        // Valeur par défaut en cas d'échec
        ctx->state.default_mem_kib = DEFAULT_MEMORY_COST_KIB;
        ctx->state.mem_kib = DEFAULT_MEMORY_COST_KIB;
    }
}

/**
 * Retourne le paramètre mémoire calculé automatiquement
 */
unsigned int get_memory_param(AppContext* ctx) {
    return ctx->state.mem_kib;
}

/* ========================================
 * SAUVEGARDE DE FICHIERS
 * ======================================== */

/**
 * Sauvegarde un fichier binaire
 */
BOOL save_binary_file_secure(const char* filename, const unsigned char* data, 
                              size_t data_len, HWND hwnd) {
    FILE* fp = fopen(filename, "wb");
    if (!check_file_operations(fp, "l'ouverture du fichier pour écriture", hwnd)) {
        return FALSE;
    }
    
    if (fwrite(data, 1, data_len, fp) != data_len) {
        show_error(hwnd, "Échec de l'écriture des données", 
                   "Erreur Sauvegarde");
        fclose(fp);
        return FALSE;
    }
    
    if (fclose(fp) != 0) {
        show_error(hwnd, 
            "Avertissement : échec de la fermeture propre du fichier", 
            "Avertissement");
    }
    
    show_success(hwnd, "Fichier sauvegardé avec succès !", "Succès");
    return TRUE;
}

/**
 * Sauvegarde le texte déchiffré
 */
BOOL save_decrypted_text_file_secure(const char* filename, HWND hOutputEdit) {
    int text_len = GetWindowTextLengthA(hOutputEdit);
    if (text_len == 0) {
        show_error(NULL, "Aucun texte à sauvegarder dans le champ Sortie", 
                   "Erreur Sauvegarde");
        return FALSE;
    }
    
    char* text = secure_malloc(NULL, text_len + 1, TRUE);
    if (!text) return FALSE;
    
    GetWindowTextA(hOutputEdit, text, text_len + 1);
    
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        secure_clean_and_free(text, text_len + 1);
        return FALSE;
    }
    
    fprintf(fp, "%s", text);
    fclose(fp);
    secure_clean_and_free(text, text_len + 1);
    
    show_success(NULL, "Texte déchiffré sauvegardé avec succès !", "Succès");
    return TRUE;
}

/**
 * Sauvegarde une image déchiffrée
 */
BOOL save_image_file_secure(const char* filename, const unsigned char* data, 
                             size_t data_len, const char* extension, HWND hwnd) {
    FILE* fp = fopen(filename, "wb");
    if (!check_file_operations(fp, "l'ouverture du fichier pour écriture", hwnd)) {
        return FALSE;
    }
    
    if (fwrite(data, 1, data_len, fp) != data_len) {
        show_error(hwnd, "Échec de l'écriture des données image", 
                   "Erreur Sauvegarde Image");
        fclose(fp);
        return FALSE;
    }
    
    fclose(fp);
    
    char success_msg[512];
    snprintf(success_msg, sizeof(success_msg), 
             "Image %s sauvegardée avec succès !", extension);
    show_success(hwnd, success_msg, "Succès");
    
    return TRUE;
}

/* ========================================
 * DÉTECTION DU TYPE DE FICHIER
 * ======================================== */

/**
 * Détecte le type de fichier à partir des données binaires
 */
FileType detect_file_type(const unsigned char* data, size_t data_len, 
                          AppContext* ctx) {
    if (!data || data_len == 0) {
        return FILE_TYPE_NONE;
    }
    
    // Vérifier si c'est un fichier crypté V370 (V37)
    if (data_len >= AAD_LEN + SALT_LEN + NONCE_LEN + TAG_LEN) {
        uint32_t version = read_uint32_le(data);
        uint32_t stored_mem_kib = read_uint32_le(data + 20);
        
        // V37 : Accepter UNIQUEMENT version 370
        if (version == CURRENT_VERSION &&
            stored_mem_kib >= 4096 && stored_mem_kib <= 1048576) {
            
            // Extraire et stocker le paramètre mémoire
            ctx->state.mem_kib = stored_mem_kib;
            return FILE_TYPE_CRYPT;
        }
    }
    
    // Vérifier les formats d'image
    if (data_len >= 8) {
        // JPEG
        if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
            if (ctx->state.original_extension) {
                secure_free(ctx->state.original_extension);
            }
            ctx->state.original_extension = _strdup("jpg");
            ctx->state.original_extension_len = 4;
            return FILE_TYPE_IMAGE;
        }
        
        // PNG
        if (memcmp(data, "\x89PNG\r\n\x1A\n", 8) == 0) {
            if (ctx->state.original_extension) {
                secure_free(ctx->state.original_extension);
            }
            ctx->state.original_extension = _strdup("png");
            ctx->state.original_extension_len = 4;
            return FILE_TYPE_IMAGE;
        }
        
        // BMP
        if (data[0] == 'B' && data[1] == 'M') {
            if (ctx->state.original_extension) {
                secure_free(ctx->state.original_extension);
            }
            ctx->state.original_extension = _strdup("bmp");
            ctx->state.original_extension_len = 4;
            return FILE_TYPE_IMAGE;
        }
    }
    
    // Vérifier si c'est du texte
    BOOL is_text = TRUE;
    size_t check_len = (data_len < 1024) ? data_len : 1024;
    
    for (size_t i = 0; i < check_len; i++) {
        if (data[i] == 0 || 
            (data[i] < 32 && data[i] != '\t' && 
             data[i] != '\r' && data[i] != '\n')) {
            is_text = FALSE;
            break;
        }
    }
    
    if (is_text) {
        return FILE_TYPE_TEXT;
    }
    
    return FILE_TYPE_NONE;
}

/* ========================================
 * RÉINITIALISATION DE L'ÉTAT
 * ======================================== */

/**
 * Réinitialise l'état de déchiffrement après un échec
 */
void reset_decrypt_state(AppContext* ctx) {
    ctx->state.decrypt_attempt_failed = FALSE;
}

/**
 * Efface tous les champs et réinitialise l'état
 */
void handle_clear(AppContext* ctx) {
    if (ctx->state.operation_in_progress) {
        show_error(NULL, 
            "Une opération est en cours. Impossible d'effacer maintenant.", 
            "Opération en cours");
        return;
    }
    
    // Réinitialiser l'état
    reset_decrypt_state(ctx);
    RESET_SHARED_STATE(&ctx->state);
    
    // Effacer les champs
    SetWindowTextA(ctx->hKeyEdit, "");
    SetWindowTextA(ctx->hInputEdit, "");
    SetWindowTextA(ctx->hOutputEdit, "");
    
    // Libérer les données
    if (ctx->state.loaded_data) {
        secure_free(ctx->state.loaded_data);
        ctx->state.loaded_data = NULL;
        ctx->state.loaded_len = 0;
    }
    
    if (ctx->state.original_extension) {
        secure_free(ctx->state.original_extension);
        ctx->state.original_extension = NULL;
        ctx->state.original_extension_len = 0;
    }
    
    // Réinitialiser la mémoire à la valeur par défaut
    ctx->state.mem_kib = ctx->state.default_mem_kib;
    
    // Réinitialiser la barre de progression
    reset_progress_bar(ctx);
}

/* ========================================
 * NETTOYAGE DES OPÉRATIONS CRYPTO
 * ======================================== */

/**
 * Nettoie et libère une opération cryptographique
 */
void cleanup_crypto_operation(CryptoOperation* op) {
    if (!op) return;
    
    if (op->text) {
        secure_clean_and_free(op->text, 
            op->text_len + (op->is_encrypt ? 1 : 0));
    }
    
    if (op->password) {
        secure_clean_and_free(op->password, strlen(op->password));
    }
    
    if (op->result) {
        secure_clean_and_free(op->result, op->result_len);
    }
    
    if (op->hThread) {
        CloseHandle(op->hThread);
    }
    
    free(op);
}

/* ========================================
 * CRÉATION DES POLICES
 * ======================================== */

/**
 * Crée les polices utilisées dans l'interface
 */
void create_fonts(AppContext* ctx) {
    // Police Courier New pour les champs de texte
    ctx->hFont = CreateFontA(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Courier New"
    );
    
    // Police grasse pour les labels
    ctx->hBoldFont = CreateFontA(
        15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI"
    );
}

/**
 * Libère les polices
 */
void destroy_fonts(AppContext* ctx) {
    if (ctx->hFont) {
        DeleteObject(ctx->hFont);
        ctx->hFont = NULL;
    }
    if (ctx->hBoldFont) {
        DeleteObject(ctx->hBoldFont);
        ctx->hBoldFont = NULL;
    }
}
