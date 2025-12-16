/**
 * Cryptage_Main.c
 * Point d'entrée principal - Version 37 (Interface unique)
 * (c) Bernard DÉMARET - 2025
 */

#include "Cryptage.h"
#include "Cryptage_State.h"
#include <windows.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* ========================================
 * VARIABLES GLOBALES
 * ======================================== */

static AppContext g_AppContext = {0};

/* ========================================
 * INITIALISATION OPENSSL
 * ======================================== */

/**
 * Initialise OpenSSL en mode portable
 */
BOOL init_portable_openssl(void) {
    static BOOL initialized = FALSE;
    if (!initialized) {
        OPENSSL_init_crypto(
            OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
            OPENSSL_INIT_ADD_ALL_CIPHERS | 
            OPENSSL_INIT_ADD_ALL_DIGESTS, 
            NULL
        );
        
        if (EVP_aes_256_gcm() == NULL) {
            MessageBoxA(NULL, 
                "Erreur: Algorithme AES-256-GCM non disponible\n\n"
                "Vérifiez l'installation d'OpenSSL.", 
                "Erreur d'initialisation", 
                MB_ICONERROR
            );
            return FALSE;
        }
        
        initialized = TRUE;
    }
    return TRUE;
}

/* ========================================
 * CRÉATION DE LA FENÊTRE PRINCIPALE
 * ======================================== */

/**
 * Crée la fenêtre principale de l'application
 */
HWND create_main_window(HINSTANCE hInstance, int nCmdShow) {
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "CryptoMainClass";
    
    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, 
            "Échec de l'enregistrement de la classe de fenêtre", 
            "Erreur", 
            MB_ICONERROR
        );
        return NULL;
    }
    
    HWND hwnd = CreateWindowExA(
        0,
        "CryptoMainClass",
        "Cryptage V37 (c) Bernard DÉMARET",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 750,
        NULL, NULL, hInstance, &g_AppContext
    );
    
    if (!hwnd) {
        MessageBoxA(NULL, 
            "Échec de la création de la fenêtre principale", 
            "Erreur", 
            MB_ICONERROR
        );
        return NULL;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    return hwnd;
}

/* ========================================
 * POINT D'ENTRÉE PRINCIPAL
 * ======================================== */

/**
 * Point d'entrée de l'application
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    
    // Initialiser OpenSSL
    if (!init_portable_openssl()) {
        return 1;
    }
    
#ifdef NDEBUG
    // Protection contre le débogage en mode Release
    if (IsDebuggerPresent()) {
        MessageBoxA(NULL, 
            "Débogueur détecté.\n\n"
            "L'application ne peut pas s'exécuter en mode debug "
            "pour des raisons de sécurité.", 
            "Sécurité", 
            MB_ICONERROR
        );
        return 1;
    }
#endif
    
    // Initialiser le contexte global
    memset(&g_AppContext, 0, sizeof(AppContext));
    RESET_SHARED_STATE(&g_AppContext.state);
    
    // Initialiser le système de mémoire sécurisée
    secure_mem_init();
    
    // Créer la fenêtre principale
    g_AppContext.hwnd = create_main_window(hInstance, nCmdShow);
    
    if (!g_AppContext.hwnd) {
        secure_mem_cleanup();
        OPENSSL_cleanup();
        return 1;
    }
    
    // Boucle de messages
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    
    // Nettoyage final
    if (g_AppContext.state.loaded_data) {
        secure_free(g_AppContext.state.loaded_data);
    }
    if (g_AppContext.state.original_extension) {
        secure_free(g_AppContext.state.original_extension);
    }
    
    secure_mem_cleanup();
    OPENSSL_cleanup();
    
    return (int)msg.wParam;
}