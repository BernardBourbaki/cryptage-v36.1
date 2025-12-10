#include "Cryptage.h"
#include <winsock2.h>
#include <openssl/core_names.h>
#include <windows.h>

static SecureMemRegistry g_secureRegistry = {NULL, {0}, FALSE};

BOOL init_portable_openssl(void) {
    static BOOL initialized = FALSE;
    if (!initialized) {
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
        if (EVP_aes_256_gcm() == NULL) {
            MessageBoxA(NULL, "Erreur: Algorithme AES-256-GCM non disponible", "Erreur", MB_ICONERROR);
            return FALSE;
        }
        initialized = TRUE;
    }
    return TRUE;
}

void show_error(HWND hwnd, const char* message, const char* title) {
    MessageBoxA(hwnd, message, title, MB_ICONWARNING);
}

void display_openssl_error(HWND hwnd, const char* operation) {
    char err_msg[256];
    unsigned long err = ERR_get_error();
    if (err) {
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        char full_msg[512];
        snprintf(full_msg, sizeof(full_msg), "Erreur lors de %s : %s", operation, err_msg);
        MessageBoxA(hwnd, full_msg, "Erreur OpenSSL", MB_ICONERROR);
        ERR_clear_error();
    } else {
        char full_msg[512];
        snprintf(full_msg, sizeof(full_msg), "Erreur inconnue lors de %s", operation);
        MessageBoxA(hwnd, full_msg, "Erreur OpenSSL", MB_ICONERROR);
    }
}

BOOL open_file_dialog(HWND hwnd, char* filename, size_t filename_size, const char* filter, const char* ext, BOOL save) {
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(OPENFILENAMEA);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = filename_size;
    ofn.lpstrDefExt = ext;
    ofn.Flags = OFN_PATHMUSTEXIST | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    return save ? GetSaveFileNameA(&ofn) : GetOpenFileNameA(&ofn);
}

BOOL save_binary_file_secure(const char* filename, const unsigned char* data, size_t data_len, HWND hwnd) {
    FILE* fp = fopen(filename, "wb");
    if (!check_file_operations(fp, "l'ouverture du fichier pour écriture", hwnd)) return FALSE;
    if (fwrite(data, 1, data_len, fp) != data_len) {
        show_error(hwnd, "Échec de l'écriture des données", "Erreur Sauvegarde");
        fclose(fp);
        return FALSE;
    }
    if (fclose(fp) != 0) show_error(hwnd, "Avertissement : échec de la fermeture propre du fichier", "Avertissement");
    MessageBoxA(hwnd, "Sauvegarde binaire réussie !", "Succès", MB_OK | MB_ICONINFORMATION);
    return TRUE;
}

BOOL save_hex_file_secure(const char* filename, const char* hex, HWND hwnd) {
    FILE* fp = fopen(filename, "w");
    if (!check_file_operations(fp, "l'ouverture du fichier pour écriture", hwnd)) return FALSE;
    if (fprintf(fp, "%s", hex) < 0) {
        show_error(hwnd, "Échec de l'écriture des données hexadécimales", "Erreur Sauvegarde");
        fclose(fp);
        return FALSE;
    }
    if (fclose(fp) != 0) show_error(hwnd, "Avertissement : échec de la fermeture propre du fichier", "Avertissement");
    MessageBoxA(hwnd, "Sauvegarde hexadécimale réussie !", "Succès", MB_OK | MB_ICONINFORMATION);
    return TRUE;
}

BOOL save_decrypted_text_file_secure(const char* filename, HWND hOutputEdit) {
    int text_len = GetWindowTextLengthA(hOutputEdit);
    if (text_len == 0) {
        show_error(NULL, "Aucun texte à sauvegarder dans le champ Sortie", "Erreur Sauvegarde");
        return FALSE;
    }
    char* text = secure_malloc(NULL, text_len + 1, TRUE);
    if (!text) return FALSE;
    GetWindowTextA(hOutputEdit, text, text_len + 1);
    FILE* fp = fopen(filename, "w");
    if (!fp) { secure_clean_and_free(text, text_len + 1); return FALSE; }
    fprintf(fp, "%s", text);
    fclose(fp);
    secure_clean_and_free(text, text_len + 1);
    MessageBoxA(NULL, "Texte déchiffré sauvegardé avec succès !", "Succès", MB_OK | MB_ICONINFORMATION);
    return TRUE;
}

BOOL save_image_file_secure(const char* filename, const unsigned char* data, size_t data_len, const char* extension, HWND hwnd) {
    FILE* fp = fopen(filename, "wb");
    if (!check_file_operations(fp, "l'ouverture du fichier pour écriture", hwnd)) return FALSE;
    if (fwrite(data, 1, data_len, fp) != data_len) {
        show_error(hwnd, "Échec de l'écriture des données image", "Erreur Sauvegarde Image");
        fclose(fp);
        return FALSE;
    }
    fclose(fp);
    char success_msg[512];
    snprintf(success_msg, sizeof(success_msg), "Image %s sauvegardée avec succès !", extension);
    MessageBoxA(hwnd, success_msg, "Succès", MB_OK | MB_ICONINFORMATION);
    return TRUE;
}

void update_memory_default(AppContext* ctx) {
    MEMORYSTATUSEX mem_status = { sizeof(MEMORYSTATUSEX) };
    if (GlobalMemoryStatusEx(&mem_status)) {
        ULONGLONG available_mem_kb = mem_status.ullAvailPhys / 1024;
        unsigned int default_mem_kib = (unsigned int)(available_mem_kb * 0.25);
        if (default_mem_kib < 4096) default_mem_kib = 4096;
        if (default_mem_kib > 1048576) default_mem_kib = 1048576;
        ctx->default_mem_kib = default_mem_kib;
        char mem_buf[10];
        snprintf(mem_buf, sizeof(mem_buf), "%u", default_mem_kib / 1024);
        SetWindowTextA(ctx->hMemoryEdit, mem_buf);
    } else {
        ctx->default_mem_kib = DEFAULT_MEMORY_COST_KIB;
        SetWindowTextA(ctx->hMemoryEdit, "16");
    }
}

void update_progress_bar(HWND hwnd, AppContext* ctx, int percent) {
    SendMessageA(ctx->hProgressBar, PBM_SETPOS, percent, 0);
    UpdateWindow(ctx->hProgressBar);
}

void toggle_password_visibility(AppContext* ctx) {
    ctx->pwdVisible = !ctx->pwdVisible;
    SendMessageA(ctx->hKeyEdit, EM_SETPASSWORDCHAR, ctx->pwdVisible ? 0 : '*', 0);
    InvalidateRect(ctx->hKeyEdit, NULL, TRUE);
    SetWindowTextA(ctx->hTogglePwdBtn, ctx->pwdVisible ? "Masquer" : "Afficher");
}

void cleanup_crypto_operation(CryptoOperation* op) {
    if (!op) return;
    if (op->text) secure_clean_and_free(op->text, op->text_len + (op->is_encrypt ? 1 : 0));
    if (op->password) secure_clean_and_free(op->password, strlen(op->password));
    if (op->result) secure_clean_and_free(op->result, op->result_len);
    if (op->hThread) CloseHandle(op->hThread);
    free(op);
}

DWORD WINAPI encrypt_thread(LPVOID lpParam) {
    CryptoOperation* op = (CryptoOperation*)lpParam;
    op->result = encrypt_data(op->hwnd, op->text, op->text_len, op->password, &op->result_len, op->mem_kib);
    for (int i = 0; i <= 100; i += 10) {
        PostMessage(op->hwnd, WM_USER_PROGRESS, i, (LPARAM)op);
        Sleep(30);
    }
    op->completed = TRUE;
    PostMessage(op->hwnd, WM_USER_COMPLETE, op->result ? 0 : 1, (LPARAM)op);
    return op->result ? 0 : 1;
}

DWORD WINAPI decrypt_thread(LPVOID lpParam) {
    CryptoOperation* op = (CryptoOperation*)lpParam;
    int result = decrypt_data(op->hwnd, op->text, op->text_len, op->password, &op->result, &op->result_len, op->mem_kib);
    for (int i = 0; i <= 100; i += 10) {
        PostMessage(op->hwnd, WM_USER_PROGRESS, i, (LPARAM)op);
        Sleep(30);
    }
    op->completed = TRUE;
    op->thread_result = result;
    PostMessage(op->hwnd, WM_USER_COMPLETE, result, (LPARAM)op);
    return result;
}

void handle_encrypt(HWND hwnd, AppContext* ctx) {
    if (ctx->operation_in_progress) { show_error(hwnd, "Une opération est déjà en cours. Veuillez patienter.", "Opération en cours"); return; }
    reset_decrypt_state(ctx);
    char* password = secure_get_edit_text(ctx->hKeyEdit, hwnd, "Erreur Chiffrement", MAX_PASSWORD_LEN);
    if (!password) return;
    if (!is_password_strong(password)) {
        show_error(hwnd, "Mot de passe faible : doit contenir entre 8 et 64 caractères, incluant une majuscule, une minuscule, un chiffre et un symbole", "Erreur Chiffrement");
        secure_clean_and_free(password, strlen(password));
        return;
    }
    char* text = secure_get_edit_text(ctx->hInputEdit, hwnd, "Erreur Chiffrement", MAX_TEXT_LEN);
    if (!text) { secure_clean_and_free(password, strlen(password)); return; }
    size_t text_len = strlen(text);
    if (text_len == 0) { show_error(hwnd, "Aucune donnée à chiffrer", "Erreur Chiffrement"); secure_free(text); secure_clean_and_free(password, strlen(password)); return; }

    char mem_buf[10];
    GetWindowTextA(ctx->hMemoryEdit, mem_buf, sizeof(mem_buf));
    char* endptr;
    errno = 0;
    unsigned long mem_mo = strtol(mem_buf, &endptr, 10);
    if (*endptr != '\0' || mem_buf[0] == '\0' || errno == ERANGE || mem_mo < 4 || mem_mo > 1024) {
        show_error(hwnd, "Mémoire doit être un nombre entre 4 et 1024 Mo. Utilisation de la valeur par défaut.", "Avertissement Mémoire");
        mem_mo = ctx->default_mem_kib / 1024;
        char default_buf[10];
        snprintf(default_buf, sizeof(default_buf), "%lu", mem_mo);
        SetWindowTextA(ctx->hMemoryEdit, default_buf);
    }
    unsigned int mem_kib = (unsigned int)(mem_mo * 1024);

    CryptoOperation* op = (CryptoOperation*)malloc(sizeof(CryptoOperation));
    if (!op) { show_error(hwnd, "Échec de l'allocation mémoire pour l'opération", "Erreur Chiffrement"); secure_free(text); secure_clean_and_free(password, strlen(password)); return; }
    memset(op, 0, sizeof(CryptoOperation));
    op->hwnd = hwnd; op->ctx = ctx; op->text = (unsigned char*)text; op->text_len = text_len;
    op->password = password; op->mem_kib = mem_kib; op->is_encrypt = TRUE;
    ctx->operation_in_progress = TRUE; update_progress_bar(hwnd, ctx, 0);
    op->hThread = CreateThread(NULL, 0, encrypt_thread, op, 0, NULL);
    if (!op->hThread) { show_error(hwnd, "Échec de la création du thread de chiffrement", "Erreur Chiffrement"); cleanup_crypto_operation(op); ctx->operation_in_progress = FALSE; return; }
    SetWindowTextA(ctx->hKeyEdit, "");
}

void handle_decrypt(HWND hwnd, AppContext* ctx) {
    if (ctx->operation_in_progress) { 
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", "Opération en cours"); 
        return; 
    }
    if (ctx->decrypt_attempt_failed) reset_decrypt_state(ctx);

    unsigned char* text = NULL; 
    size_t text_len = 0;
    BOOL from_loaded_data = FALSE;
    
    // ========================================
    // Charger les données (binaire ou hex)
    // ========================================
    if (ctx->loaded_data && ctx->loaded_len > 0) {
        // Cas 1 : Données chargées via "Importer" (déjà en binaire)
        text = secure_malloc(hwnd, ctx->loaded_len, TRUE);
        if (!text) { 
            show_error(hwnd, "Échec d'allocation mémoire", "Erreur Mémoire"); 
            ctx->decrypt_attempt_failed = TRUE; 
            return; 
        }
        memcpy(text, ctx->loaded_data, ctx->loaded_len); 
        text_len = ctx->loaded_len;
        from_loaded_data = TRUE;
        
    } else if (GetWindowTextLengthA(ctx->hInputEdit) > 0) {
        // Cas 2 : Données saisies/collées en hex dans le champ Entrée
        char* hex = secure_get_edit_text(ctx->hInputEdit, hwnd, "Erreur Déchiffrement", MAX_TEXT_LEN * 4);
        if (hex && is_valid_hex(hex) && hex_to_bin(hex, &text, &text_len) == 0) { 
            secure_free(hex); 
        } else { 
            if (hex) secure_free(hex); 
            show_error(hwnd, "Données hexadécimales invalides ou absentes", "Erreur Déchiffrement"); 
            ctx->decrypt_attempt_failed = TRUE; 
            return; 
        }
        
    } else { 
        show_error(hwnd, "Aucune donnée à déchiffrer", "Erreur Déchiffrement"); 
        ctx->decrypt_attempt_failed = TRUE; 
        return; 
    }

    // ========================================
    // CORRECTION : Extraire le paramètre mémoire du fichier crypté
    // avant la validation, si ce n'est pas déjà fait
    // ========================================
    unsigned int mem_kib;
    
    if (text_len >= AAD_LEN) {
        // Lire le paramètre mémoire stocké dans le fichier crypté
        uint32_t stored_mem_kib = read_uint32_le(text + 20);
        
        // Vérifier si c'est une valeur valide
        if (stored_mem_kib >= 4096 && stored_mem_kib <= 1048576) {
            // Utiliser le paramètre du fichier
            mem_kib = stored_mem_kib;
            
            // Mettre à jour l'interface si ce n'était pas un fichier chargé via Import
            // (Import met déjà à jour l'interface automatiquement)
            if (!from_loaded_data) {
                char mem_buf[10];
                snprintf(mem_buf, sizeof(mem_buf), "%u", mem_kib / 1024);
                SetWindowTextA(ctx->hMemoryEdit, mem_buf);
            }
        } else {
            // Si le paramètre du fichier est invalide, utiliser celui de l'interface
            char mem_buf[10];
            GetWindowTextA(ctx->hMemoryEdit, mem_buf, sizeof(mem_buf));
            char* endptr; 
            errno = 0;
            unsigned long mem_mo = strtol(mem_buf, &endptr, 10);
            
            if (*endptr != '\0' || mem_buf[0] == '\0' || errno == ERANGE || mem_mo < 4 || mem_mo > 1024) {
                show_error(hwnd, "Paramètre mémoire invalide dans le fichier et dans l'interface. Utilisation de la valeur par défaut.", "Avertissement Mémoire");
                mem_mo = ctx->default_mem_kib / 1024;
                char default_buf[10]; 
                snprintf(default_buf, sizeof(default_buf), "%lu", mem_mo);
                SetWindowTextA(ctx->hMemoryEdit, default_buf);
            }
            mem_kib = (unsigned int)(mem_mo * 1024);
        }
    } else {
        // Fichier trop petit pour être un fichier crypté valide
        show_error(hwnd, "Fichier trop petit pour être un fichier crypté valide", "Erreur Déchiffrement");
        secure_free(text); 
        ctx->decrypt_attempt_failed = TRUE; 
        return;
    }

    // ========================================
    // Récupérer le mot de passe
    // ========================================
    char* password = secure_get_edit_text(ctx->hKeyEdit, hwnd, "Erreur Déchiffrement", MAX_PASSWORD_LEN);
    if (!password) { 
        if (text) secure_free(text); 
        ctx->decrypt_attempt_failed = TRUE; 
        return; 
    }

    // ========================================
    // Valider la structure du fichier crypté
    // (maintenant avec le bon paramètre mémoire)
    // ========================================
    uint32_t dummy_ext_code;
    if (validate_encrypted_data_v32(text, text_len, mem_kib, &dummy_ext_code) != 0) {
        show_error(hwnd, "Fichier corrompu, incompatible ou mauvaise configuration mémoire", "Erreur Déchiffrement");
        secure_clean_and_free(password, strlen(password));
        secure_free(text); 
        ctx->decrypt_attempt_failed = TRUE; 
        return;
    }

    // ========================================
    // Créer et lancer l'opération de déchiffrement
    // ========================================
    CryptoOperation* op = (CryptoOperation*)malloc(sizeof(CryptoOperation));
    if (!op) { 
        show_error(hwnd, "Échec allocation mémoire", "Erreur"); 
        secure_clean_and_free(password, strlen(password)); 
        secure_free(text); 
        ctx->decrypt_attempt_failed = TRUE; 
        return; 
    }
    
    memset(op, 0, sizeof(CryptoOperation));
    op->hwnd = hwnd; 
    op->ctx = ctx; 
    op->text = text; 
    op->text_len = text_len;
    op->password = password; 
    op->mem_kib = mem_kib; 
    op->is_encrypt = FALSE;
    
    ctx->operation_in_progress = TRUE; 
    update_progress_bar(hwnd, ctx, 0);
    
    op->hThread = CreateThread(NULL, 0, decrypt_thread, op, 0, NULL);
    if (!op->hThread) { 
        show_error(hwnd, "Échec création thread", "Erreur"); 
        cleanup_crypto_operation(op); 
        ctx->operation_in_progress = FALSE; 
        ctx->decrypt_attempt_failed = TRUE; 
        return; 
    }
    
    SetWindowTextA(ctx->hKeyEdit, "");
}

void handle_save_binary(HWND hwnd, AppContext* ctx) {
    if (ctx->operation_in_progress) { 
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", "Opération en cours"); 
        return; 
    }
    
    char* hex = secure_get_edit_text(ctx->hOutputEdit, hwnd, "Erreur Sauvegarde", MAX_TEXT_LEN * 4);
    if (!hex) return;
    
    unsigned char* bin_data = NULL; 
    size_t bin_len;
    if (hex_to_bin(hex, &bin_data, &bin_len) != 0) { 
        show_error(hwnd, "Données hexadécimales invalides", "Erreur"); 
        secure_free(hex); 
        return; 
    }
    secure_free(hex);
    
    if (bin_len == 0) { 
        show_error(hwnd, "Aucune donnée à sauvegarder", "Erreur"); 
        secure_free(bin_data); 
        return; 
    }
    
    char filename[260] = "encrypted.crypt";
    if (open_file_dialog(hwnd, filename, sizeof(filename), 
        "Fichiers cryptés (*.crypt)\0*.crypt\0Fichiers binaires (*.bin)\0*.bin\0Tous les fichiers (*.*)\0*.*\0", 
        "crypt", TRUE)) {
        
        if (save_binary_file_secure(filename, bin_data, bin_len, hwnd)) {
            // AJOUT : Nettoyage automatique après sauvegarde réussie
            secure_free(bin_data);
            handle_clear(ctx);
            return;
        }
    }
    
    secure_free(bin_data);
}

void handle_save_hex(HWND hwnd, AppContext* ctx) {
    if (ctx->operation_in_progress) { 
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", "Opération en cours"); 
        return; 
    }
    
    char* hex = secure_get_edit_text(ctx->hOutputEdit, hwnd, "Erreur Sauvegarde", MAX_TEXT_LEN * 4);
    if (!hex || strlen(hex) == 0) { 
        show_error(hwnd, "Aucune donnée à exporter en hex", "Erreur"); 
        secure_free(hex); 
        return; 
    }
    
    char filename[260] = "encrypted.txt";
    if (open_file_dialog(hwnd, filename, sizeof(filename), 
        "Fichiers texte (*.txt)\0*.txt\0Tous les fichiers (*.*)\0*.*\0", 
        "txt", TRUE)) {
        
        if (save_hex_file_secure(filename, hex, hwnd)) {
            // AJOUT : Nettoyage automatique après export réussi
            secure_free(hex);
            handle_clear(ctx);
            return;
        }
    }
    
    secure_free(hex);
}

void handle_clear(AppContext* ctx) {
    if (ctx->operation_in_progress) { show_error(NULL, "Une opération est en cours. Impossible d'effacer maintenant.", "Opération en cours"); return; }
    reset_decrypt_state(ctx);
    SetWindowTextA(ctx->hKeyEdit, "");
    SetWindowTextA(ctx->hInputEdit, "");
    SetWindowTextA(ctx->hOutputEdit, "");
    if (ctx->loaded_data) { secure_free(ctx->loaded_data); ctx->loaded_data = NULL; ctx->loaded_len = 0; }
    if (ctx->original_extension) { secure_free(ctx->original_extension); ctx->original_extension = NULL; ctx->original_extension_len = 0; }
    char mem_buf[10]; snprintf(mem_buf, sizeof(mem_buf), "%u", ctx->default_mem_kib / 1024);
    SetWindowTextA(ctx->hMemoryEdit, mem_buf);
    SendMessageA(ctx->hProgressBar, PBM_SETPOS, 0, 0);
}

void handle_edit_text(HWND hwnd, AppContext* ctx) {
    if (ctx->operation_in_progress) { 
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", "Opération en cours"); 
        return; 
    }
    
    char filename[260] = "decrypted.txt";
    if (open_file_dialog(hwnd, filename, sizeof(filename), 
        "Fichiers texte (*.txt)\0*.txt\0Tous les fichiers (*.*)\0*.*\0", 
        "txt", TRUE)) {
        
        if (save_decrypted_text_file_secure(filename, ctx->hOutputEdit)) {
            // AJOUT : Nettoyage automatique après export réussi
            handle_clear(ctx);
        }
    }
}

void handle_export_image(HWND hwnd, AppContext* ctx) {
    if (ctx->operation_in_progress) { 
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", "Opération en cours"); 
        return; 
    }
    
    int len = GetWindowTextLengthA(ctx->hOutputEdit);
    if (len == 0) { 
        show_error(hwnd, "Aucune donnée déchiffrée à exporter.", "Erreur"); 
        return; 
    }
    
    char* hex = secure_get_edit_text(ctx->hOutputEdit, hwnd, "Erreur Exportation", MAX_TEXT_LEN * 4);
    if (!hex) return;
    
    unsigned char* data = NULL; 
    size_t data_len;
    if (hex_to_bin(hex, &data, &data_len) != 0) { 
        show_error(hwnd, "Conversion hex ? binaire échouée", "Erreur"); 
        secure_free(hex); 
        return; 
    }
    secure_free(hex);
    
    if (data_len == 0) { 
        show_error(hwnd, "Aucune donnée image valide", "Erreur"); 
        secure_free(data); 
        return; 
    }

    const char* ext = NULL;
    const char* filter = NULL;
    
    if (data_len >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) { 
        ext = "jpg"; 
        filter = "JPEG (*.jpg)\0*.jpg\0Tous les fichiers (*.*)\0*.*\0"; 
    }
    else if (data_len >= 8 && memcmp(data, "\x89PNG\r\n\x1A\n", 8) == 0) { 
        ext = "png"; 
        filter = "PNG (*.png)\0*.png\0Tous les fichiers (*.*)\0*.*\0"; 
    }
    else if (data_len >= 2 && data[0] == 'B' && data[1] == 'M') { 
        ext = "bmp"; 
        filter = "BMP (*.bmp)\0*.bmp\0Tous les fichiers (*.*)\0*.*\0"; 
    }
    else if (ctx->original_extension) { 
        ext = ctx->original_extension; 
    }
    else { 
        show_error(hwnd, "Format image non reconnu", "Erreur"); 
        secure_free(data); 
        return; 
    }

    char filename[260]; 
    snprintf(filename, sizeof(filename), "decrypted_image.%s", ext);
    
    if (open_file_dialog(hwnd, filename, sizeof(filename), 
        filter ? filter : "Tous les fichiers (*.*)\0*.*\0", 
        ext, TRUE)) {
        
        if (save_image_file_secure(filename, data, data_len, ext, hwnd)) {
            // AJOUT : Nettoyage automatique après export réussi
            secure_free(data);
            handle_clear(ctx);
            return;
        }
    }
    
    secure_free(data);
}

void handle_operation_complete_v36(HWND hwnd, AppContext* ctx, WPARAM wParam, LPARAM lParam) {
    CryptoOperation* op = (CryptoOperation*)lParam;
    ctx->operation_in_progress = FALSE;
    update_progress_bar(hwnd, ctx, 100);
    if (op->is_encrypt) {
        if (wParam == 0 && op->result) {
            char* hex = bin_to_hex(op->result, op->result_len);
            if (hex) { secure_set_edit_text(ctx->hOutputEdit, hex, strlen(hex)); secure_free(hex); }
            reset_decrypt_state(ctx);
        }
    } else {
        if (wParam == 0 && op->result) {
            secure_set_edit_text(ctx->hOutputEdit, (char*)op->result, op->result_len);
            reset_decrypt_state(ctx);
        } else if (wParam == 1) {
            show_error(hwnd, "Mot de passe incorrect ou données corrompues", "Échec Déchiffrement");
            ctx->decrypt_attempt_failed = TRUE;
        } else {
            show_error(hwnd, "Échec du déchiffrement", "Erreur");
            ctx->decrypt_attempt_failed = TRUE;
        }
    }
    cleanup_crypto_operation(op);
}

void handle_import_auto(HWND hwnd, AppContext* ctx) {
    if (ctx->operation_in_progress) { 
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", "Opération en cours"); 
        return; 
    }

    char filename[260] = "";
    const char* filter = "Tous fichiers supportés\0*.txt;*.jpg;*.jpeg;*.png;*.bmp;*.crypt;*.bin\0Texte (*.txt)\0*.txt\0Images (*.jpg;*.jpeg;*.png;*.bmp)\0*.jpg;*.jpeg;*.png;*.bmp\0Fichiers cryptés (*.crypt;*.bin)\0*.crypt;*.bin\0Tous les fichiers (*.*)\0*.*\0";

    if (!open_file_dialog(hwnd, filename, sizeof(filename), filter, NULL, FALSE)) return;

    reset_decrypt_state(ctx);

    unsigned char* data = NULL; 
    size_t data_len = 0;
    if (!load_file_secure(filename, &data, &data_len, hwnd, FALSE)) return;
    if (data_len == 0) { 
        secure_free(data); 
        return; 
    }

    char msg[512]; 
    BOOL handled = FALSE;

    // ========================================
    // CORRECTION : Vérifier d'abord le format crypté
    // avant les formats d'image
    // ========================================
    if (data_len >= AAD_LEN + SALT_LEN + NONCE_LEN + TAG_LEN) {
        uint32_t version = read_uint32_le(data);
        uint32_t stored_mem_kib = read_uint32_le(data + 20);
        uint32_t dummy;
        
        // CORRECTION : Accepter toutes les versions >= 31 au lieu d'une liste fixe
        if (version >= 31 && version <= 999 &&
            stored_mem_kib >= 4096 && stored_mem_kib <= 1048576 &&
            validate_encrypted_data_v32(data, data_len, stored_mem_kib, &dummy) == 0) {
            
            snprintf(msg, sizeof(msg), "Fichier crypté détecté (v%u — %u Mo) — %zu octets", 
                     version, stored_mem_kib / 1024, data_len);
            MessageBoxA(hwnd, msg, "Import automatique", MB_OK | MB_ICONINFORMATION);
            
            ctx->loaded_data = data; 
            ctx->loaded_len = data_len;
            
            // Extraction automatique du paramètre mémoire
            uint32_t stored_mem_mo = stored_mem_kib / 1024;
            char mem_buf[10];
            snprintf(mem_buf, sizeof(mem_buf), "%u", stored_mem_mo);
            SetWindowTextA(ctx->hMemoryEdit, mem_buf);
            
            char* hex = bin_to_hex(data, data_len);
            if (hex) { 
                secure_set_edit_text(ctx->hInputEdit, hex, strlen(hex)); 
                secure_free(hex); 
            }
            handled = TRUE;
        }
    }

    // ========================================
    // Vérification des formats d'image
    // (seulement si ce n'est pas un fichier crypté)
    // ========================================
    if (!handled && data_len >= 8) {
        if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
            snprintf(msg, sizeof(msg), "Image JPEG détectée — %zu octets", data_len);
            MessageBoxA(hwnd, msg, "Import automatique", MB_OK | MB_ICONINFORMATION);
            ctx->loaded_data = data; 
            ctx->loaded_len = data_len;
            if (ctx->original_extension) secure_free(ctx->original_extension);
            ctx->original_extension = _strdup("jpg"); 
            ctx->original_extension_len = 4;
            char* hex = bin_to_hex(data, data_len);
            if (hex) { 
                secure_set_edit_text(ctx->hInputEdit, hex, strlen(hex)); 
                secure_free(hex); 
            }
            handled = TRUE;
        }
        else if (memcmp(data, "\x89PNG\r\n\x1A\n", 8) == 0) {
            snprintf(msg, sizeof(msg), "Image PNG détectée — %zu octets", data_len);
            MessageBoxA(hwnd, msg, "Import automatique", MB_OK | MB_ICONINFORMATION);
            ctx->loaded_data = data; 
            ctx->loaded_len = data_len;
            if (ctx->original_extension) secure_free(ctx->original_extension);
            ctx->original_extension = _strdup("png"); 
            ctx->original_extension_len = 4;
            char* hex = bin_to_hex(data, data_len);
            if (hex) { 
                secure_set_edit_text(ctx->hInputEdit, hex, strlen(hex)); 
                secure_free(hex); 
            }
            handled = TRUE;
        }
        else if (data[0] == 'B' && data[1] == 'M') {
            snprintf(msg, sizeof(msg), "Image BMP détectée — %zu octets", data_len);
            MessageBoxA(hwnd, msg, "Import automatique", MB_OK | MB_ICONINFORMATION);
            ctx->loaded_data = data; 
            ctx->loaded_len = data_len;
            if (ctx->original_extension) secure_free(ctx->original_extension);
            ctx->original_extension = _strdup("bmp"); 
            ctx->original_extension_len = 4;
            char* hex = bin_to_hex(data, data_len);
            if (hex) { 
                secure_set_edit_text(ctx->hInputEdit, hex, strlen(hex)); 
                secure_free(hex); 
            }
            handled = TRUE;
        }
    }

    // ========================================
    // Vérification du format texte
    // ========================================
    if (!handled) {
        BOOL is_text = TRUE;
        size_t check = (data_len < 1024 ? data_len : 1024);
        for (size_t i = 0; i < check; i++) {
            if (data[i] == 0 || (data[i] < 32 && data[i] != '\t' && data[i] != '\r' && data[i] != '\n')) { 
                is_text = FALSE; 
                break; 
            }
        }
        if (is_text) {
            MessageBoxA(hwnd, "Fichier texte détecté", "Import automatique", MB_OK | MB_ICONINFORMATION);
            secure_set_edit_text(ctx->hInputEdit, (char*)data, data_len);
            secure_free(data);
            handled = TRUE;
        }
    }

    if (!handled) { 
        show_error(hwnd, "Format de fichier non reconnu ou non supporté", "Type inconnu"); 
        secure_free(data); 
    }
}

void create_window_controls(HWND hwnd, HINSTANCE hInstance, AppContext* ctx) {
    InitCommonControls();
    ctx->hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Courier New");
    HFONT hBoldFont = CreateFontA(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

    // Ligne du haut
    CreateWindowA("Static", "Mot de passe [8-64 caractères] :", WS_VISIBLE | WS_CHILD, 10, 10, 200, 20, hwnd, NULL, hInstance, NULL);
    ctx->hKeyEdit = CreateWindowA("Edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 210, 10, 300, 24, hwnd, (HMENU)ID_KEY_EDIT, hInstance, NULL);
    SendMessageA(ctx->hKeyEdit, WM_SETFONT, (WPARAM)ctx->hFont, TRUE);
    ctx->hTogglePwdBtn = CreateWindowA("Button", "Afficher", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 520, 10, 80, 24, hwnd, (HMENU)ID_TOGGLE_PWD_BTN, hInstance, NULL);
    CreateWindowA("Static", "Mémoire [Mo] :", WS_VISIBLE | WS_CHILD, 610, 10, 100, 20, hwnd, NULL, hInstance, NULL);
    ctx->hMemoryEdit = CreateWindowA("Edit", "16", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 715, 10, 55, 24, hwnd, (HMENU)ID_MEMORY_EDIT, hInstance, NULL);

    // Entrée / Sortie
    CreateWindowA("Static", "Entrée :", WS_VISIBLE | WS_CHILD, 10, 40, 200, 20, hwnd, NULL, hInstance, NULL);
    ctx->hInputEdit = CreateWindowA("Edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, 10, 60, 500, 180, hwnd, (HMENU)ID_INPUT_EDIT, hInstance, NULL);
    SendMessageA(ctx->hInputEdit, WM_SETFONT, (WPARAM)ctx->hFont, TRUE);

    CreateWindowA("Static", "Sortie :", WS_VISIBLE | WS_CHILD, 10, 250, 100, 20, hwnd, NULL, hInstance, NULL);
    ctx->hOutputEdit = CreateWindowA("Edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 10, 270, 500, 180, hwnd, (HMENU)ID_OUTPUT_EDIT, hInstance, NULL);
    SendMessageA(ctx->hOutputEdit, WM_SETFONT, (WPARAM)ctx->hFont, TRUE);

    // ========================================
    // PARTIE CENTRALE DROITE - VERSION 36
    // Organisation en 5 groupes bien séparés
    // ========================================
    int rightPanelX = 520;
    int buttonWidth = 270;
    int buttonX = rightPanelX + 10;
    int smallButtonWidth = 130;
    int currentY = 60;

    // ========================================
    // GROUPE 1 : IMPORT (CYAN)
    // ========================================
    CreateWindowA("Button", "Importer le fichier source\n(txt, jpg, png, bmp, crypt, bin)",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_MULTILINE | BS_CENTER,
        buttonX, currentY, buttonWidth, 50,
        hwnd, (HMENU)ID_IMPORT_AUTO_BTN, hInstance, NULL);

    currentY += 70;

    // ========================================
    // GROUPE 2 : CHIFFRER (VERT) / DÉCHIFFRER (BLEU)
    // ========================================
    CreateWindowA("Button", "Chiffrer",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        buttonX, currentY, buttonWidth, 40,
        hwnd, (HMENU)ID_ENCRYPT_BTN, hInstance, NULL);

    CreateWindowA("Button", "Déchiffrer",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        buttonX, currentY + 50, buttonWidth, 40,
        hwnd, (HMENU)ID_DECRYPT_BTN, hInstance, NULL);

    currentY += 110;

    // ========================================
    // GROUPE 3 : EXPORTER LE FICHIER CHIFFRÉ
    // ========================================
    HWND hLabel1 = CreateWindowA("Static", "Exporter le fichier chiffré",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        buttonX, currentY, buttonWidth, 20,
        hwnd, NULL, hInstance, NULL);
    SendMessageA(hLabel1, WM_SETFONT, (WPARAM)hBoldFont, TRUE);

    CreateWindowA("Button", "Sauvegarder [.crypt]",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        buttonX, currentY + 25, smallButtonWidth, 35,
        hwnd, (HMENU)ID_SAVE_BIN_BTN, hInstance, NULL);

    CreateWindowA("Button", "Exporter hex [.txt]",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        buttonX + smallButtonWidth + 10, currentY + 25, smallButtonWidth, 35,
        hwnd, (HMENU)ID_SAVE_HEX_BTN, hInstance, NULL);

    currentY += 80;

    // ========================================
    // GROUPE 4 : EXPORTER LE FICHIER DÉCHIFFRÉ
    // ========================================
    HWND hLabel2 = CreateWindowA("Static", "Exporter le fichier déchiffré",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        buttonX, currentY, buttonWidth, 20,
        hwnd, NULL, hInstance, NULL);
    SendMessageA(hLabel2, WM_SETFONT, (WPARAM)hBoldFont, TRUE);

    CreateWindowA("Button", "Texte",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        buttonX, currentY + 25, smallButtonWidth, 35,
        hwnd, (HMENU)ID_EDIT_TEXT_BTN, hInstance, NULL);

    CreateWindowA("Button", "Image",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        buttonX + smallButtonWidth + 10, currentY + 25, smallButtonWidth, 35,
        hwnd, (HMENU)ID_EXPORT_IMG_BTN, hInstance, NULL);

    currentY += 80;

    // ========================================
    // GROUPE 5 : EFFACER (ROUGE)
    // ========================================
    CreateWindowA("Button", "Effacer",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        buttonX, currentY, buttonWidth, 40,
        hwnd, (HMENU)ID_CLEAR_BTN, hInstance, NULL);

    ctx->hProgressBar = CreateWindowA(PROGRESS_CLASS, NULL, WS_VISIBLE | WS_CHILD | PBS_SMOOTH,
                                      10, 465, 850, 25, hwnd, (HMENU)ID_PROGRESS_BAR, hInstance, NULL);
    SendMessageA(ctx->hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

    update_memory_default(ctx);
    ctx->loaded_data = NULL; ctx->loaded_len = 0; ctx->operation_in_progress = FALSE;
    ctx->original_extension = NULL; ctx->original_extension_len = 0; ctx->decrypt_attempt_failed = FALSE;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AppContext* ctx = (msg == WM_CREATE) ? (AppContext*)((LPCREATESTRUCT)lParam)->lpCreateParams : (AppContext*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    if (msg == WM_CREATE) SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);
    if (!ctx) return DefWindowProcA(hwnd, msg, wParam, lParam);

    switch (msg) {
        case WM_CREATE: secure_mem_init(); create_window_controls(hwnd, ((LPCREATESTRUCT)lParam)->hInstance, ctx); break;
        case WM_USER_PROGRESS: update_progress_bar(hwnd, ctx, (int)wParam); break;
        case WM_USER_COMPLETE: handle_operation_complete_v36(hwnd, ctx, wParam, lParam); break;
        
        // ========================================
        // GESTION DES COULEURS - VERSION 36
        // ========================================
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT p = (LPDRAWITEMSTRUCT)lParam;
            if (p->CtlType == ODT_BUTTON) {
                COLORREF bg;
                COLORREF fg;
                
                // Couleurs par bouton
                switch(p->CtlID) {
                    case ID_IMPORT_AUTO_BTN:
                        bg = RGB(0, 188, 212);    // Cyan
                        fg = RGB(255, 255, 255);  // Blanc
                        break;
                    case ID_ENCRYPT_BTN:
                        bg = RGB(76, 175, 80);    // Vert
                        fg = RGB(255, 255, 255);  // Blanc
                        break;
                    case ID_DECRYPT_BTN:
                        bg = RGB(33, 150, 243);   // Bleu
                        fg = RGB(255, 255, 255);  // Blanc
                        break;
                    case ID_SAVE_BIN_BTN:
                        bg = RGB(255, 182, 193);  // Rose pastel
                        fg = RGB(0, 0, 0);        // Noir
                        break;
                    case ID_SAVE_HEX_BTN:
                        bg = RGB(255, 218, 185);  // Pêche pastel
                        fg = RGB(0, 0, 0);        // Noir
                        break;
                    case ID_EDIT_TEXT_BTN:
                        bg = RGB(230, 230, 250);  // Lavande pastel
                        fg = RGB(0, 0, 0);        // Noir
                        break;
                    case ID_EXPORT_IMG_BTN:
                        bg = RGB(189, 252, 201);  // Menthe pastel
                        fg = RGB(0, 0, 0);        // Noir
                        break;
                    case ID_CLEAR_BTN:
                        bg = RGB(244, 67, 54);    // Rouge
                        fg = RGB(255, 255, 255);  // Blanc
                        break;
                    default:
                        return DefWindowProcA(hwnd, msg, wParam, lParam);
                }
                
                FillRect(p->hDC, &p->rcItem, CreateSolidBrush(bg));
                SetBkMode(p->hDC, TRANSPARENT);
                SetTextColor(p->hDC, fg);
                
                char txt[128];
                GetWindowTextA(p->hwndItem, txt, sizeof(txt));
                
                // Pour le bouton Import qui est multilignes
                if (p->CtlID == ID_IMPORT_AUTO_BTN) {
                    DrawTextA(p->hDC, txt, -1, &p->rcItem, DT_CENTER | DT_VCENTER | DT_WORDBREAK);
                } else {
                    DrawTextA(p->hDC, txt, -1, &p->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                }
                
                if (p->itemState & ODS_SELECTED) {
                    DrawEdge(p->hDC, &p->rcItem, EDGE_SUNKEN, BF_RECT);
                }
                
                return TRUE;
            }
            break;
        }
        
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TOGGLE_PWD_BTN: toggle_password_visibility(ctx); break;
                case ID_IMPORT_AUTO_BTN: handle_import_auto(hwnd, ctx); break;
                case ID_ENCRYPT_BTN: handle_encrypt(hwnd, ctx); break;
                case ID_DECRYPT_BTN: handle_decrypt(hwnd, ctx); break;
                case ID_SAVE_BIN_BTN: handle_save_binary(hwnd, ctx); break;
                case ID_SAVE_HEX_BTN: handle_save_hex(hwnd, ctx); break;
                case ID_EDIT_TEXT_BTN: handle_edit_text(hwnd, ctx); break;
                case ID_EXPORT_IMG_BTN: handle_export_image(hwnd, ctx); break;
                case ID_CLEAR_BTN: handle_clear(ctx); break;
            }
            break;
        case WM_CLOSE:
            if (ctx->operation_in_progress && MessageBoxA(hwnd, "Une opération est en cours. Fermer interrompra le traitement. Continuer ?", "Confirmation", MB_YESNO | MB_ICONQUESTION) == IDNO) return 0;
            handle_clear(ctx); DestroyWindow(hwnd); break;
        case WM_DESTROY:
            if (ctx->hFont) DeleteObject(ctx->hFont);
            if (ctx->loaded_data) secure_free(ctx->loaded_data);
            if (ctx->original_extension) secure_free(ctx->original_extension);
            secure_mem_cleanup(); PostQuitMessage(0); break;
        default: return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!init_portable_openssl()) return 1;
#ifdef NDEBUG
    if (IsDebuggerPresent()) { MessageBoxA(NULL, "Débogueur détecté. L'application ne peut pas s'exécuter en mode debug pour des raisons de sécurité.", "Sécurité", MB_ICONERROR); return 1; }
#endif
    WNDCLASSEXA wc = { sizeof(WNDCLASSEXA), CS_HREDRAW | CS_VREDRAW, WndProc, 0, 0, hInstance, NULL, LoadCursor(NULL, IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), NULL, "CryptoAppClass", NULL };
    RegisterClassExA(&wc);
    AppContext ctx = {0};
    HWND hwnd = CreateWindowExA(0, "CryptoAppClass", "Cryptage Version 36.1 (Portable) (c) Bernard DÉMARET",
                               WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 950, 580, NULL, NULL, hInstance, &ctx);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    secure_mem_cleanup(); OPENSSL_cleanup();
    return 0;
}