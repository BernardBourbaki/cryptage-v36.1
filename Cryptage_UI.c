/**
 * Cryptage_UI.c
 * Interface utilisateur unique - Version 37
 * (c) Bernard DÉMARET - 2025
 */

#include "Cryptage.h"
#include "Cryptage_State.h"
#include <windows.h>
#include <commctrl.h>

/* ========================================
 * IDENTIFIANTS DES CONTRÔLES
 * ======================================== */

#define ID_KEY_EDIT         1001
#define ID_TOGGLE_PWD_BTN   1002
#define ID_INPUT_EDIT       1003
#define ID_OUTPUT_EDIT      1004
#define ID_PROGRESS_BAR     1005

#define ID_IMPORT_BTN       2001
#define ID_ENCRYPT_BTN      2002
#define ID_SAVE_BTN         2003
#define ID_DECRYPT_BTN      2004
#define ID_EXPORT_TEXT_BTN  2005
#define ID_EXPORT_IMAGE_BTN 2006
#define ID_CLEAR_BTN        2007

#define ID_HELP_TOGGLE_BTN  2009

/* ========================================
 * COULEURS DES BOUTONS
 * ======================================== */

#define COLOR_IMPORT        RGB(0, 188, 212)      // Cyan
#define COLOR_ENCRYPT       RGB(76, 175, 80)      // Vert
#define COLOR_SAVE          RGB(255, 182, 193)    // Rose pastel
#define COLOR_DECRYPT       RGB(33, 150, 243)     // Bleu
#define COLOR_EXPORT_TEXT   RGB(230, 230, 250)    // Lavande
#define COLOR_EXPORT_IMAGE  RGB(189, 252, 201)    // Menthe
#define COLOR_CLEAR         RGB(244, 67, 54)      // Rouge

/* ========================================
 * DÉCLARATIONS DES FONCTIONS
 * ======================================== */

void create_ui_controls(HWND hwnd, HINSTANCE hInstance, AppContext* ctx);
void update_buttons(AppContext* ctx);
void handle_import(HWND hwnd, AppContext* ctx);
void handle_encrypt(HWND hwnd, AppContext* ctx);
void handle_save(HWND hwnd, AppContext* ctx);
void handle_decrypt(HWND hwnd, AppContext* ctx);
void handle_export_text(HWND hwnd, AppContext* ctx);
void handle_export_image(HWND hwnd, AppContext* ctx);
void toggle_help_panel(AppContext* ctx);
void handle_operation_complete(HWND hwnd, AppContext* ctx, WPARAM wParam, LPARAM lParam);
DWORD WINAPI encrypt_thread(LPVOID lpParam);
DWORD WINAPI decrypt_thread(LPVOID lpParam);

/* ========================================
 * CRÉATION DES CONTRÔLES
 * ======================================== */

/**
 * Crée tous les contrôles de l'interface
 */
void create_ui_controls(HWND hwnd, HINSTANCE hInstance, AppContext* ctx) {
    InitCommonControls();
    create_fonts(ctx);
    
    int y = 10;
    
    // ========================================
    // LIGNE 1 : Mot de passe
    // ========================================
    CreateWindowA("Static", "Mot de passe [8-64 caractères] :", 
        WS_VISIBLE | WS_CHILD, 10, y, 200, 20, 
        hwnd, NULL, hInstance, NULL);
    
    ctx->hKeyEdit = CreateWindowA("Edit", NULL, 
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 
        210, y, 300, 24, 
        hwnd, (HMENU)ID_KEY_EDIT, hInstance, NULL);
    SendMessageA(ctx->hKeyEdit, WM_SETFONT, (WPARAM)ctx->hFont, TRUE);
    
    ctx->hTogglePwdBtn = CreateWindowA("Button", "Afficher", 
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 
        520, y, 80, 24, 
        hwnd, (HMENU)ID_TOGGLE_PWD_BTN, hInstance, NULL);
    
    y += 40;
    
    // ========================================
    // PARTIE CENTRALE : 2 zones de texte + 7 boutons
    // ========================================
    int leftPanelWidth = 500;
    int rightPanelX = 520;
    int buttonWidth = 270;
    int textAreaHeight = 205;
    
    // Zone Entrée
    CreateWindowA("Static", "Entrée :", 
        WS_VISIBLE | WS_CHILD, 10, y, 100, 20, 
        hwnd, NULL, hInstance, NULL);
    
    ctx->hInputEdit = CreateWindowA("Edit", NULL, 
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | 
        ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 
        10, y + 20, leftPanelWidth, textAreaHeight, 
        hwnd, (HMENU)ID_INPUT_EDIT, hInstance, NULL);
    SendMessageA(ctx->hInputEdit, WM_SETFONT, (WPARAM)ctx->hFont, TRUE);
    
    // Zone Sortie
    int outputY = y + 20 + textAreaHeight + 10;
    CreateWindowA("Static", "Sortie :", 
        WS_VISIBLE | WS_CHILD, 10, outputY, 100, 20, 
        hwnd, NULL, hInstance, NULL);
    
    ctx->hOutputEdit = CreateWindowA("Edit", NULL, 
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | 
        ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 
        10, outputY + 20, leftPanelWidth, textAreaHeight, 
        hwnd, (HMENU)ID_OUTPUT_EDIT, hInstance, NULL);
    SendMessageA(ctx->hOutputEdit, WM_SETFONT, (WPARAM)ctx->hFont, TRUE);
    
    // ========================================
    // PANNEAU DROIT : 7 BOUTONS (réorganisés verticalement)
    // ========================================
    int btnY = y;
    int spacer = 10;
    
    // 1. IMPORTER (hauteur 50px)
    ctx->hImportBtn = CreateWindowA("Button", 
        "IMPORTER\nle fichier à chiffrer/déchiffrer", 
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_MULTILINE | BS_CENTER, 
        rightPanelX, btnY, buttonWidth, 50, 
        hwnd, (HMENU)ID_IMPORT_BTN, hInstance, NULL);
    btnY += 50 + spacer;
    
    // 2. CHIFFRER (hauteur 40px)
    ctx->hEncryptBtn = CreateWindowA("Button", 
        "CHIFFRER\nle fichier importé", 
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_MULTILINE | BS_CENTER, 
        rightPanelX, btnY, buttonWidth, 40, 
        hwnd, (HMENU)ID_ENCRYPT_BTN, hInstance, NULL);
    btnY += 40 + spacer;
    
    // 3. SAUVEGARDER (hauteur 40px)
    ctx->hSaveBtn = CreateWindowA("Button", 
        "SAUVEGARDER\nle fichier chiffré", 
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_MULTILINE | BS_CENTER, 
        rightPanelX, btnY, buttonWidth, 40, 
        hwnd, (HMENU)ID_SAVE_BTN, hInstance, NULL);
    btnY += 40 + spacer;
    
    // 4. DÉCHIFFRER (hauteur 40px)
    ctx->hDecryptBtn = CreateWindowA("Button", 
        "DÉCHIFFRER\nle fichier importé", 
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_MULTILINE | BS_CENTER, 
        rightPanelX, btnY, buttonWidth, 40, 
        hwnd, (HMENU)ID_DECRYPT_BTN, hInstance, NULL);
    btnY += 40 + spacer;
    
    // 5. EXPORTER TEXTE (hauteur 40px)
    ctx->hExportTextBtn = CreateWindowA("Button", 
        "EXPORTER\nle texte déchiffré", 
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_MULTILINE | BS_CENTER, 
        rightPanelX, btnY, buttonWidth, 40, 
        hwnd, (HMENU)ID_EXPORT_TEXT_BTN, hInstance, NULL);
    btnY += 40 + spacer;
    
    // 6. EXPORTER IMAGE (hauteur 40px)
    ctx->hExportImageBtn = CreateWindowA("Button", 
        "EXPORTER\nl'image déchiffrée", 
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_MULTILINE | BS_CENTER, 
        rightPanelX, btnY, buttonWidth, 40, 
        hwnd, (HMENU)ID_EXPORT_IMAGE_BTN, hInstance, NULL);
    btnY += 40 + spacer;
    
    // 7. EFFACER (hauteur 40px)
    ctx->hClearBtn = CreateWindowA("Button", "EFFACER", 
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW | BS_CENTER, 
        rightPanelX, btnY, buttonWidth, 40, 
        hwnd, (HMENU)ID_CLEAR_BTN, hInstance, NULL);
    
    // ========================================
    // BARRE DE PROGRESSION
    // ========================================
    int progressY = outputY + 20 + textAreaHeight + 15;
    ctx->hProgressBar = CreateWindowA(PROGRESS_CLASS, NULL, 
        WS_VISIBLE | WS_CHILD | PBS_SMOOTH, 
        10, progressY, 780, 25, 
        hwnd, (HMENU)ID_PROGRESS_BAR, hInstance, NULL);
    SendMessageA(ctx->hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    
    // ========================================
    // PANNEAU "PRISE EN MAIN RAPIDE"
    // ========================================
    int helpY = progressY + 35;
    
    // Bouton de toggle (en-tête) - Panneau masqué par défaut
    CreateWindowA("Button", 
        "Prise en main rapide                                                                                                 [Afficher]",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 
        10, helpY, 780, 30, 
        hwnd, (HMENU)ID_HELP_TOGGLE_BTN, hInstance, NULL);
    
    // Contenu du panneau (initialement masqué)
    ctx->hHelpPanel = CreateWindowA("Static", 
        "Etape 1 - Créez un mot de passe FORT (16+ caractères recommandés)\r\n"
        "   > Utilisez KeePass ou un gestionnaire de mot de passe\r\n"
        "   > Ne transmettez JAMAIS le mot de passe et le(s) fichier(s) crypté(s) ensemble !\r\n\r\n"
        "Etape 2 - Pour chiffrer un texte ou une image : IMPORTER > CHIFFRER > SAUVEGARDER\r\n\r\n"
        "Etape 3 - Pour déchiffrer un fichier crypté : IMPORTER > DÉCHIFFRER > EXPORTER\r\n\r\n"
        "IMPORTANT - Fichiers V31-V36 : Utilisez Cryptage_V36.1.exe pour déchiffrer",
        WS_CHILD | SS_LEFT,  // MASQUÉ par défaut (pas de WS_VISIBLE)
        10, helpY + 35, 780, 140, 
        hwnd, NULL, hInstance, NULL);
    
    ctx->help_expanded = FALSE;
    
    // Initialiser l'état
    update_memory_default(ctx);
    RESET_SHARED_STATE(&ctx->state);
    update_buttons(ctx);
}

/* ========================================
 * LOGIQUE D'ACTIVATION DES BOUTONS
 * ======================================== */

/**
 * Met à jour l'état des boutons selon la logique
 */
void update_buttons(AppContext* ctx) {
    // IMPORTER et EFFACER : toujours actifs
    SET_BUTTON_STATE(ctx->hImportBtn, TRUE);
    SET_BUTTON_STATE(ctx->hClearBtn, TRUE);
    
    if (!ctx->state.file_imported) {
        // État initial : aucun fichier
        SET_BUTTON_STATE(ctx->hEncryptBtn, FALSE);
        SET_BUTTON_STATE(ctx->hSaveBtn, FALSE);
        SET_BUTTON_STATE(ctx->hDecryptBtn, FALSE);
        SET_BUTTON_STATE(ctx->hExportTextBtn, FALSE);
        SET_BUTTON_STATE(ctx->hExportImageBtn, FALSE);
        
    } else if (ctx->state.file_type == FILE_TYPE_CRYPT) {
        // Fichier .crypt importé (V370 uniquement)
        SET_BUTTON_STATE(ctx->hEncryptBtn, FALSE);
        SET_BUTTON_STATE(ctx->hSaveBtn, FALSE);
        SET_BUTTON_STATE(ctx->hDecryptBtn, !ctx->state.decrypted);
        
        if (ctx->state.decrypted) {
            // Après déchiffrement réussi
            SET_BUTTON_STATE(ctx->hExportTextBtn, 
                ctx->state.decrypted_type == CONTENT_TYPE_TEXT);
            SET_BUTTON_STATE(ctx->hExportImageBtn, 
                ctx->state.decrypted_type == CONTENT_TYPE_IMAGE);
        } else {
            SET_BUTTON_STATE(ctx->hExportTextBtn, FALSE);
            SET_BUTTON_STATE(ctx->hExportImageBtn, FALSE);
        }
        
    } else {
        // Fichier normal (texte/image) importé
        SET_BUTTON_STATE(ctx->hEncryptBtn, !ctx->state.encrypted);
        SET_BUTTON_STATE(ctx->hSaveBtn, ctx->state.encrypted);
        SET_BUTTON_STATE(ctx->hDecryptBtn, FALSE);
        SET_BUTTON_STATE(ctx->hExportTextBtn, FALSE);
        SET_BUTTON_STATE(ctx->hExportImageBtn, FALSE);
    }
}

/* ========================================
 * HANDLERS DES BOUTONS
 * ======================================== */

/**
 * Handler IMPORTER : charge un fichier et détecte automatiquement son type
 */
void handle_import(HWND hwnd, AppContext* ctx) {
    if (IS_OPERATION_BUSY(ctx)) {
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", 
                   "Opération en cours");
        return;
    }
    
    char filename[260] = "";
    const char* filter = 
        "Tous fichiers supportés\0*.txt;*.jpg;*.jpeg;*.png;*.bmp;*.crypt\0"
        "Texte (*.txt)\0*.txt\0"
        "Images (*.jpg;*.jpeg;*.png;*.bmp)\0*.jpg;*.jpeg;*.png;*.bmp\0"
        "Fichiers cryptés (*.crypt)\0*.crypt\0"
        "Tous les fichiers (*.*)\0*.*\0";
    
    if (!open_file_dialog(hwnd, filename, sizeof(filename), filter, NULL, FALSE)) {
        return;
    }
    
    reset_decrypt_state(ctx);
    
    // Charger le fichier
    unsigned char* data = NULL;
    size_t data_len = 0;
    if (!load_file_secure(filename, &data, &data_len, hwnd, FALSE)) {
        return;
    }
    
    if (data_len == 0) {
        secure_free(data);
        return;
    }
    
    // Détecter le type
    FileType type = detect_file_type(data, data_len, ctx);
    
    char msg[512];
    
    // Vérifier si c'est une version antérieure (V31-V36)
    if (data_len >= 4) {
        uint32_t version = read_uint32_le(data);
        
        if (version >= 31 && version < 370) {
            // Fichier d'une version antérieure détecté
            snprintf(msg, sizeof(msg), 
                "?? Fichier crypté v%u détecté (%u Mo) — %zu octets\n\n"
                "Ce fichier a été chiffré avec une version antérieure.\n\n"
                "Pour le déchiffrer, utilisez :\n"
                "Cryptage_V36.1.exe\n\n"
                "Disponible sur :\n"
                "github.com/BernardBourbaki/cryptage-v36.1/releases",
                version, 
                (version >= 32 && data_len >= 24) ? read_uint32_le(data + 20) / 1024 : 0,
                data_len);
            
            MessageBoxA(hwnd, msg, "Version antérieure détectée", 
                       MB_OK | MB_ICONWARNING);
            
            // NE PAS importer le fichier
            secure_free(data);
            return;
        }
    }
    
    if (type == FILE_TYPE_NONE) {
        show_error(hwnd, "Format de fichier non reconnu ou non supporté", 
                   "Type inconnu");
        secure_free(data);
        return;
    }
    
    // Stocker les données
    ctx->state.loaded_data = data;
    ctx->state.loaded_len = data_len;
    ctx->state.file_imported = TRUE;
    ctx->state.file_type = type;
    ctx->state.file_size = data_len;
    ctx->state.encrypted = FALSE;
    ctx->state.decrypted = FALSE;
    ctx->state.decrypted_type = CONTENT_TYPE_NONE;
    
    // Afficher dans le champ Entrée
    if (type == FILE_TYPE_TEXT) {
        secure_set_edit_text(ctx->hInputEdit, (char*)data, data_len);
        show_success(hwnd, "Fichier texte importé avec succès", "Import");
        
    } else {
        // Binaire -> hex
        char* hex = bin_to_hex(data, data_len);
        if (hex) {
            secure_set_edit_text(ctx->hInputEdit, hex, strlen(hex));
            secure_free(hex);
        }
        
        if (type == FILE_TYPE_CRYPT) {
            uint32_t version = read_uint32_le(data);
            snprintf(msg, sizeof(msg), 
                "Fichier crypté importé (v%u — %u Mo)\n%zu octets", 
                version, ctx->state.mem_kib / 1024, data_len);
            show_success(hwnd, msg, "Import");
            
        } else if (type == FILE_TYPE_IMAGE) {
            snprintf(msg, sizeof(msg), 
                "Image %s importée\n%zu octets", 
                ctx->state.original_extension, data_len);
            show_success(hwnd, msg, "Import");
        }
    }
    
    SetWindowTextA(ctx->hOutputEdit, "");
    update_buttons(ctx);
}

/**
 * Handler CHIFFRER
 */
void handle_encrypt(HWND hwnd, AppContext* ctx) {
    if (IS_OPERATION_BUSY(ctx)) {
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", 
                   "Opération en cours");
        return;
    }
    
    reset_decrypt_state(ctx);
    
    // Récupérer le mot de passe
    char* password = secure_get_edit_text(ctx->hKeyEdit, hwnd, 
                                          "Erreur Chiffrement", MAX_PASSWORD_LEN);
    if (!password) return;
    
    if (!is_password_strong(password)) {
        show_error(hwnd, 
            "Mot de passe faible :\n"
            "Doit contenir entre 8 et 64 caractères,\n"
            "incluant une majuscule, une minuscule,\n"
            "un chiffre et un symbole", 
            "Erreur Chiffrement");
        secure_clean_and_free(password, strlen(password));
        return;
    }
    
    // Récupérer les données à chiffrer
    unsigned char* text = ctx->state.loaded_data;
    size_t text_len = ctx->state.loaded_len;
    
    if (!text || text_len == 0) {
        show_error(hwnd, "Aucune donnée à chiffrer", "Erreur Chiffrement");
        secure_clean_and_free(password, strlen(password));
        return;
    }
    
    // Créer une copie des données pour le thread
    unsigned char* text_copy = secure_malloc(hwnd, text_len, TRUE);
    if (!text_copy) {
        secure_clean_and_free(password, strlen(password));
        return;
    }
    memcpy(text_copy, text, text_len);
    
    // Obtenir le paramètre mémoire (calculé automatiquement)
    unsigned int mem_kib = get_memory_param(ctx);
    
    // Créer l'opération
    CryptoOperation* op = (CryptoOperation*)malloc(sizeof(CryptoOperation));
    if (!op) {
        show_error(hwnd, "Échec allocation mémoire", "Erreur");
        secure_free(text_copy);
        secure_clean_and_free(password, strlen(password));
        return;
    }
    
    memset(op, 0, sizeof(CryptoOperation));
    op->hwnd = hwnd;
    op->ctx = ctx;
    op->text = text_copy;
    op->text_len = text_len;
    op->password = password;
    op->mem_kib = mem_kib;
    op->is_encrypt = TRUE;
    
    ctx->state.operation_in_progress = TRUE;
    update_progress_bar(hwnd, ctx, 0);
    
    op->hThread = CreateThread(NULL, 0, encrypt_thread, op, 0, NULL);
    if (!op->hThread) {
        show_error(hwnd, "Échec création thread", "Erreur");
        cleanup_crypto_operation(op);
        ctx->state.operation_in_progress = FALSE;
        return;
    }
    
    SetWindowTextA(ctx->hKeyEdit, "");
}

/**
 * Thread de chiffrement
 */
DWORD WINAPI encrypt_thread(LPVOID lpParam) {
    CryptoOperation* op = (CryptoOperation*)lpParam;
    
    op->result = encrypt_data(op->hwnd, op->text, op->text_len, 
                              op->password, &op->result_len, op->mem_kib);
    
    for (int i = 0; i <= 100; i += 10) {
        PostMessage(op->hwnd, WM_USER_PROGRESS, i, (LPARAM)op);
        Sleep(30);
    }
    
    op->completed = TRUE;
    PostMessage(op->hwnd, WM_USER_COMPLETE, op->result ? 0 : 1, (LPARAM)op);
    
    return op->result ? 0 : 1;
}

/**
 * Handler SAUVEGARDER
 */
void handle_save(HWND hwnd, AppContext* ctx) {
    if (IS_OPERATION_BUSY(ctx)) {
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", 
                   "Opération en cours");
        return;
    }
    
    char* hex = secure_get_edit_text(ctx->hOutputEdit, hwnd, 
                                     "Erreur Sauvegarde", MAX_TEXT_LEN * 4);
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
        "Fichiers cryptés (*.crypt)\0*.crypt\0Tous les fichiers (*.*)\0*.*\0", 
        "crypt", TRUE)) {
        
        if (save_binary_file_secure(filename, bin_data, bin_len, hwnd)) {
            secure_free(bin_data);
            handle_clear(ctx);
            update_buttons(ctx);
            return;
        }
    }
    
    secure_free(bin_data);
}

/**
 * Handler DÉCHIFFRER
 */
void handle_decrypt(HWND hwnd, AppContext* ctx) {
    if (IS_OPERATION_BUSY(ctx)) {
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", 
                   "Opération en cours");
        return;
    }
    
    if (ctx->state.decrypt_attempt_failed) {
        reset_decrypt_state(ctx);
    }
    
    unsigned char* text = ctx->state.loaded_data;
    size_t text_len = ctx->state.loaded_len;
    
    if (!text || text_len == 0) {
        show_error(hwnd, "Aucune donnée à déchiffrer", "Erreur Déchiffrement");
        ctx->state.decrypt_attempt_failed = TRUE;
        return;
    }
    
    // Récupérer le mot de passe
    char* password = secure_get_edit_text(ctx->hKeyEdit, hwnd, 
                                          "Erreur Déchiffrement", MAX_PASSWORD_LEN);
    if (!password) {
        ctx->state.decrypt_attempt_failed = TRUE;
        return;
    }
    
    // Le paramètre mémoire est déjà extrait dans detect_file_type()
    unsigned int mem_kib = ctx->state.mem_kib;
    
    // Créer une copie des données
    unsigned char* text_copy = secure_malloc(hwnd, text_len, TRUE);
    if (!text_copy) {
        secure_clean_and_free(password, strlen(password));
        ctx->state.decrypt_attempt_failed = TRUE;
        return;
    }
    memcpy(text_copy, text, text_len);
    
    // Créer l'opération
    CryptoOperation* op = (CryptoOperation*)malloc(sizeof(CryptoOperation));
    if (!op) {
        show_error(hwnd, "Échec allocation mémoire", "Erreur");
        secure_clean_and_free(password, strlen(password));
        secure_free(text_copy);
        ctx->state.decrypt_attempt_failed = TRUE;
        return;
    }
    
    memset(op, 0, sizeof(CryptoOperation));
    op->hwnd = hwnd;
    op->ctx = ctx;
    op->text = text_copy;
    op->text_len = text_len;
    op->password = password;
    op->mem_kib = mem_kib;
    op->is_encrypt = FALSE;
    
    ctx->state.operation_in_progress = TRUE;
    update_progress_bar(hwnd, ctx, 0);
    
    op->hThread = CreateThread(NULL, 0, decrypt_thread, op, 0, NULL);
    if (!op->hThread) {
        show_error(hwnd, "Échec création thread", "Erreur");
        cleanup_crypto_operation(op);
        ctx->state.operation_in_progress = FALSE;
        ctx->state.decrypt_attempt_failed = TRUE;
        return;
    }
    
    SetWindowTextA(ctx->hKeyEdit, "");
}

/**
 * Thread de déchiffrement
 */
DWORD WINAPI decrypt_thread(LPVOID lpParam) {
    CryptoOperation* op = (CryptoOperation*)lpParam;
    
    int result = decrypt_data(op->hwnd, op->text, op->text_len, 
                             op->password, &op->result, &op->result_len, 
                             op->mem_kib);
    
    for (int i = 0; i <= 100; i += 10) {
        PostMessage(op->hwnd, WM_USER_PROGRESS, i, (LPARAM)op);
        Sleep(30);
    }
    
    op->completed = TRUE;
    op->thread_result = result;
    PostMessage(op->hwnd, WM_USER_COMPLETE, result, (LPARAM)op);
    
    return result;
}

/**
 * Handler EXPORTER TEXTE
 */
void handle_export_text(HWND hwnd, AppContext* ctx) {
    if (IS_OPERATION_BUSY(ctx)) {
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", 
                   "Opération en cours");
        return;
    }
    
    char filename[260] = "decrypted.txt";
    if (open_file_dialog(hwnd, filename, sizeof(filename), 
        "Fichiers texte (*.txt)\0*.txt\0Tous les fichiers (*.*)\0*.*\0", 
        "txt", TRUE)) {
        
        if (save_decrypted_text_file_secure(filename, ctx->hOutputEdit)) {
            handle_clear(ctx);
            update_buttons(ctx);
        }
    }
}

/**
 * Handler EXPORTER IMAGE
 */
void handle_export_image(HWND hwnd, AppContext* ctx) {
    if (IS_OPERATION_BUSY(ctx)) {
        show_error(hwnd, "Une opération est en cours. Veuillez patienter.", 
                   "Opération en cours");
        return;
    }
    
    int len = GetWindowTextLengthA(ctx->hOutputEdit);
if (len == 0) {
show_error(hwnd, "Aucune donnée déchiffrée à exporter.", "Erreur");
return;
}
char* hex = secure_get_edit_text(ctx->hOutputEdit, hwnd, 
                                 "Erreur Exportation", MAX_TEXT_LEN * 4);
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

// Détecter le format
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
else if (ctx->state.original_extension) {
    ext = ctx->state.original_extension;
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
        secure_free(data);
        handle_clear(ctx);
        update_buttons(ctx);
        return;
    }
}

secure_free(data);
}

/**
 * Toggle le panneau d'aide
 */
void toggle_help_panel(AppContext* ctx) {
    ctx->help_expanded = !ctx->help_expanded;
    
    ShowWindow(ctx->hHelpPanel, 
               ctx->help_expanded ? SW_SHOW : SW_HIDE);
    
    HWND hToggleBtn = GetDlgItem(ctx->hwnd, ID_HELP_TOGGLE_BTN);
    if (hToggleBtn) {
        SetWindowTextA(hToggleBtn, 
            ctx->help_expanded ? 
            "Prise en main rapide                                                                                                 [Masquer]" : 
            "Prise en main rapide                                                                                                 [Afficher]");
    }
}

/* ========================================
 * GESTION DE LA COMPLÉTION DES OPÉRATIONS
 * ======================================== */

/**
 * Gère la fin d'une opération crypto (chiffrement/déchiffrement)
 */
void handle_operation_complete(HWND hwnd, AppContext* ctx, 
                               WPARAM wParam, LPARAM lParam) {
    CryptoOperation* op = (CryptoOperation*)lParam;
    ctx->state.operation_in_progress = FALSE;
    update_progress_bar(hwnd, ctx, 100);
    
    if (op->is_encrypt) {
        // Chiffrement terminé
        if (wParam == 0 && op->result) {
            char* hex = bin_to_hex(op->result, op->result_len);
            if (hex) {
                secure_set_edit_text(ctx->hOutputEdit, hex, strlen(hex));
                secure_free(hex);
            }
            ctx->state.encrypted = TRUE;
            show_success(hwnd, "Chiffrement réussi !", "Succès");
            reset_decrypt_state(ctx);
        } else {
            show_error(hwnd, "Échec du chiffrement", "Erreur");
        }
    } else {
        // Déchiffrement terminé
        if (wParam == 0 && op->result) {
            // Déterminer le type de contenu
            BOOL is_text = TRUE;
            size_t check_len = (op->result_len < 1024) ? op->result_len : 1024;
            
            for (size_t i = 0; i < check_len; i++) {
                if (op->result[i] == 0 || 
                    (op->result[i] < 32 && op->result[i] != '\t' && 
                     op->result[i] != '\r' && op->result[i] != '\n')) {
                    is_text = FALSE;
                    break;
                }
            }
            
            if (is_text) {
                secure_set_edit_text(ctx->hOutputEdit, 
                                    (char*)op->result, op->result_len);
                ctx->state.decrypted_type = CONTENT_TYPE_TEXT;
            } else {
                char* hex = bin_to_hex(op->result, op->result_len);
                if (hex) {
                    secure_set_edit_text(ctx->hOutputEdit, hex, strlen(hex));
                    secure_free(hex);
                }
                ctx->state.decrypted_type = CONTENT_TYPE_IMAGE;
            }
            
            ctx->state.decrypted = TRUE;
            show_success(hwnd, "Déchiffrement réussi !", "Succès");
            reset_decrypt_state(ctx);
            
        } else if (wParam == 1) {
            show_error(hwnd, 
                "Mot de passe incorrect ou données corrompues", 
                "Échec Déchiffrement");
            ctx->state.decrypt_attempt_failed = TRUE;
        } else {
            show_error(hwnd, "Échec du déchiffrement", "Erreur");
            ctx->state.decrypt_attempt_failed = TRUE;
        }
    }
    
    cleanup_crypto_operation(op);
    update_buttons(ctx);
}

/* ========================================
 * PROCÉDURE DE FENÊTRE
 * ======================================== */

/**
 * Procédure de fenêtre principale
 */
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AppContext* ctx = (msg == WM_CREATE) ? 
        (AppContext*)((LPCREATESTRUCT)lParam)->lpCreateParams : 
        (AppContext*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    
    if (msg == WM_CREATE) {
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);
        ctx->hwnd = hwnd;
    }
    
    if (!ctx) return DefWindowProcA(hwnd, msg, wParam, lParam);
    
    switch (msg) {
        case WM_CREATE:
            secure_mem_init();
            create_ui_controls(hwnd, 
                ((LPCREATESTRUCT)lParam)->hInstance, ctx);
            break;
            
        case WM_USER_PROGRESS:
            update_progress_bar(hwnd, ctx, (int)wParam);
            break;
            
        case WM_USER_COMPLETE:
            handle_operation_complete(hwnd, ctx, wParam, lParam);
            break;
            
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT p = (LPDRAWITEMSTRUCT)lParam;
            if (p->CtlType == ODT_BUTTON) {
                COLORREF bg, fg;
                
                switch(p->CtlID) {
                    case ID_IMPORT_BTN:
                        bg = COLOR_IMPORT; fg = RGB(255, 255, 255); break;
                    case ID_ENCRYPT_BTN:
                        bg = COLOR_ENCRYPT; fg = RGB(255, 255, 255); break;
                    case ID_SAVE_BTN:
                        bg = COLOR_SAVE; fg = RGB(0, 0, 0); break;
                    case ID_DECRYPT_BTN:
                        bg = COLOR_DECRYPT; fg = RGB(255, 255, 255); break;
                    case ID_EXPORT_TEXT_BTN:
                        bg = COLOR_EXPORT_TEXT; fg = RGB(0, 0, 0); break;
                    case ID_EXPORT_IMAGE_BTN:
                        bg = COLOR_EXPORT_IMAGE; fg = RGB(0, 0, 0); break;
                    case ID_CLEAR_BTN:
                        bg = COLOR_CLEAR; fg = RGB(255, 255, 255); break;
                    default:
                        return DefWindowProcA(hwnd, msg, wParam, lParam);
                }
                
                FillRect(p->hDC, &p->rcItem, CreateSolidBrush(bg));
                SetBkMode(p->hDC, TRANSPARENT);
                SetTextColor(p->hDC, fg);
                
                char txt[128];
                GetWindowTextA(p->hwndItem, txt, sizeof(txt));
                
                DrawTextA(p->hDC, txt, -1, &p->rcItem, 
                         DT_CENTER | DT_VCENTER | DT_WORDBREAK);
                
                // Griser fortement les boutons désactivés
                if (!IsWindowEnabled(p->hwndItem)) {
                    HBRUSH hGrayBrush = CreateSolidBrush(RGB(200, 200, 200));
                    FillRect(p->hDC, &p->rcItem, hGrayBrush);
                    DeleteObject(hGrayBrush);
                    SetTextColor(p->hDC, RGB(160, 160, 160));
                    DrawTextA(p->hDC, txt, -1, &p->rcItem, 
                             DT_CENTER | DT_VCENTER | DT_WORDBREAK);
                    return TRUE;
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
                case ID_TOGGLE_PWD_BTN:
                    toggle_password_visibility(ctx);
                    break;
                case ID_IMPORT_BTN:
                    handle_import(hwnd, ctx);
                    break;
                case ID_ENCRYPT_BTN:
                    handle_encrypt(hwnd, ctx);
                    break;
                case ID_SAVE_BTN:
                    handle_save(hwnd, ctx);
                    break;
                case ID_DECRYPT_BTN:
                    handle_decrypt(hwnd, ctx);
                    break;
                case ID_EXPORT_TEXT_BTN:
                    handle_export_text(hwnd, ctx);
                    break;
                case ID_EXPORT_IMAGE_BTN:
                    handle_export_image(hwnd, ctx);
                    break;
                case ID_CLEAR_BTN:
                    handle_clear(ctx);
                    update_buttons(ctx);
                    break;
                case ID_HELP_TOGGLE_BTN:
                    toggle_help_panel(ctx);
                    break;
            }
            break;
            
        case WM_CLOSE:
            if (IS_OPERATION_BUSY(ctx) && 
                MessageBoxA(hwnd, 
                    "Une opération est en cours.\n"
                    "Fermer interrompra le traitement. Continuer ?", 
                    "Confirmation", 
                    MB_YESNO | MB_ICONQUESTION) == IDNO) {
                return 0;
            }
            handle_clear(ctx);
            DestroyWindow(hwnd);
            break;
            
        case WM_DESTROY:
            destroy_fonts(ctx);
            if (ctx->state.loaded_data) secure_free(ctx->state.loaded_data);
            if (ctx->state.original_extension) 
                secure_free(ctx->state.original_extension);
            secure_mem_cleanup();
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    
    return 0;
}