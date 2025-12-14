/*
 * Hodur - D810 Deobfuscation Test Sample
 *
 * This sample replicates the obfuscation patterns found in the "Hodur" malware:
 * 1. Control Flow Flattening: The main logic is wrapped in a single while(1) loop
 *    with a state dispatcher, mimicking OLLVM/obfuscator-llvm structures.
 * 2. Arithmetic String Decryption: API names are decrypted at runtime using
 *    three different arithmetic expressions observed in the decompiled code.
 * 3. Dynamic API Resolution: APIs are resolved dynamically after decryption.
 *
 * Compile with: cl hodur.c
 */

#include "polyfill.h"
#include <stdio.h>
#include <string.h>

// Global timeout variable
DWORD g_timeout_msec = 10000;

// Function pointer typedefs
typedef BOOL(WINAPI *t_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef HINTERNET(WINAPI *t_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL(WINAPI *t_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *t_WinHttpReceiveResponse)(HINTERNET, LPVOID);

// Helper to resolve APIs (Simulates fn_resolve_API_addr_4)
void *resolve_api(const char *func_name)
{
    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp)
        return NULL;
    return (void *)GetProcAddress(hWinHttp, func_name);
}

int _hodur_func()
{
    // State variables for the flattened control flow
    // Using specific constants observed in the "Issue 1/2" images
    int32_t state = -1292005450;

    // Session handles
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    // Function pointers
    t_WinHttpSetOption fn_WinHttpSetOption = NULL;
    t_WinHttpOpenRequest fn_WinHttpOpenRequest = NULL;
    t_WinHttpSendRequest fn_WinHttpSendRequest = NULL;
    t_WinHttpReceiveResponse fn_WinHttpReceiveResponse = NULL;

    // Buffers for decrypted strings
    unsigned char enc_buf[64];

    // Initialize Session/Connect for the simulation
    hSession = WinHttpOpen(L"Hodur/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
        return 1;
    hConnect = WinHttpConnect(hSession, L"example.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return 1;
    }

    printf("[*] Starting flattened execution flow...\n");

    // ---------------------------------------------------------
    // FLATTENED CONTROL FLOW LOOP
    // ---------------------------------------------------------
    while (1)
    {
        // Dispatcher

        // STATE: ENTRY / DECRYPT WinHttpSetOption (Variant 1)
        if (state == -1292005450)
        {
            // Encrypted "WinHttpSetOption"
            unsigned char raw[] = {
                0x57, 0x6E, 0x68, 0x4D, 0x70, 0x7F, 0x7A, 0x5A,
                0x6D, 0x7B, 0x41, 0x7D, 0x78, 0x7A, 0x7D, 0x7F, 0x00};
            memcpy(enc_buf, raw, sizeof(raw));

            // Algo 1: enc[k] ^= 0x19 ^ (0x1C - k) & 0xFA ^ (k - 0x1D) & 5;
            for (int k = 0; k < 16; k++)
            {
                enc_buf[k] ^= 0x19 ^ (0x1C - k) & 0xFA ^ (k - 0x1D) & 5;
            }

            printf("[+] Decrypted (Algo 1): %s\n", enc_buf);

            // Transition to Resolve
            state = 0xC6685257;
        }

        // STATE: RESOLVE & CALL WinHttpSetOption (Connect Timeout)
        else if (state == 0xC6685257)
        {
            fn_WinHttpSetOption = (t_WinHttpSetOption)resolve_api((char *)enc_buf);
            if (fn_WinHttpSetOption)
            {
                fn_WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &g_timeout_msec, sizeof(g_timeout_msec));
            }
            // Transition to Next Block
            state = 0xB92456DE;
        }

        // STATE: DECRYPT WinHttpSetOption (Variant 2)
        else if (state == 0xB92456DE)
        {
            unsigned char raw[] = {
                0x57, 0x6E, 0x68, 0x4D, 0x70, 0x7F, 0x7A, 0x5A,
                0x6D, 0x7B, 0x41, 0x7D, 0x78, 0x7A, 0x7D, 0x7F, 0x00};
            memcpy(enc_buf, raw, sizeof(raw));

            // Algo 2: enc[k] = ~((k - 0x1D) ^ enc[k] ^ 0x1C);
            for (int k = 0; k < 16; k++)
            {
                enc_buf[k] = ~((k - 0x1D) ^ enc_buf[k] ^ 0x1C);
            }

            printf("[+] Decrypted (Algo 2): %s\n", enc_buf);
            state = 0x3C8960A9;
        }

        // STATE: RESOLVE & CALL WinHttpSetOption (Receive Timeout)
        else if (state == 0x3C8960A9)
        {
            fn_WinHttpSetOption = (t_WinHttpSetOption)resolve_api((char *)enc_buf);
            if (fn_WinHttpSetOption)
            {
                fn_WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &g_timeout_msec, sizeof(g_timeout_msec));
            }
            state = 0xEC031199;
        }

        // STATE: DECRYPT WinHttpSetOption (Variant 3)
        else if (state == 0xEC031199)
        {
            unsigned char raw[] = {
                0x57, 0x6E, 0x68, 0x4D, 0x70, 0x7F, 0x7A, 0x5A,
                0x6D, 0x7B, 0x41, 0x7D, 0x78, 0x7A, 0x7D, 0x7F, 0x00};
            memcpy(enc_buf, raw, sizeof(raw));

            // Algo 3: enc[k] ^= (k - 0x1D) ^ 0xE3;
            for (int k = 0; k < 16; k++)
            {
                enc_buf[k] ^= (k - 0x1D) ^ 0xE3;
            }

            printf("[+] Decrypted (Algo 3): %s\n", enc_buf);
            state = 0x87A0CA6E;
        }

        // STATE: RESOLVE & CALL WinHttpSetOption (Send Timeout)
        else if (state == 0x87A0CA6E)
        {
            fn_WinHttpSetOption = (t_WinHttpSetOption)resolve_api((char *)enc_buf);
            if (fn_WinHttpSetOption)
            {
                fn_WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT, &g_timeout_msec, sizeof(g_timeout_msec));
            }
            state = 0xB7F8A88B;
        }

        // STATE: DECRYPT WinHttpOpenRequest (Variant 3 Logic)
        else if (state == 0xB7F8A88B)
        {
            // "WinHttpOpenRequest" encrypted
            unsigned char raw[] = {
                0x57, 0x6E, 0x68, 0x4D, 0x70, 0x7F, 0x7A, 0x46,
                0x78, 0x6A, 0x60, 0x5F, 0x69, 0x62, 0x67, 0x74,
                0x63, 0x63, 0x00};
            memcpy(enc_buf, raw, sizeof(raw));

            for (int i = 0; i < 18; i++)
            {
                enc_buf[i] ^= (i - 29) ^ 0xE3;
            }

            printf("[+] Decrypted: %s\n", enc_buf);
            state = 0x0B8148F6;
        }

        // STATE: RESOLVE & CALL WinHttpOpenRequest
        else if (state == 0x0B8148F6)
        {
            fn_WinHttpOpenRequest = (t_WinHttpOpenRequest)resolve_api((char *)enc_buf);
            if (fn_WinHttpOpenRequest)
            {
                DWORD dwFlags = WINHTTP_FLAG_SECURE; // Simplified logic
                hRequest = fn_WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
            }

            if (hRequest)
                state = 0xB86ECBE0;
            else
                state = -731028004; // FAIL STATE
        }

        // STATE: DECRYPT WinHttpSendRequest
        else if (state == 0xB86ECBE0)
        {
            // "WinHttpSendRequest" encrypted
            unsigned char raw[] = {
                0x57, 0x6E, 0x68, 0x4D, 0x70, 0x7F, 0x7A, 0x5A,
                0x6D, 0x61, 0x6A, 0x5F, 0x69, 0x62, 0x67, 0x74,
                0x63, 0x63, 0x00};
            memcpy(enc_buf, raw, sizeof(raw));

            for (int i = 0; i < 18; i++)
            {
                enc_buf[i] ^= (i - 29) ^ 0xE3;
            }

            printf("[+] Decrypted: %s\n", enc_buf);
            state = 0x16DA1DAC;
        }

        // STATE: RESOLVE & CALL WinHttpSendRequest
        else if (state == 0x16DA1DAC)
        {
            fn_WinHttpSendRequest = (t_WinHttpSendRequest)resolve_api((char *)enc_buf);
            BOOL res = FALSE;
            if (fn_WinHttpSendRequest)
            {
                char *post_data = "data";
                res = fn_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, post_data, 4, 4, 0);
            }

            // Branching based on result (mimics Issue 1 Fix logic)
            if (!res)
            {
                state = -731028004; // FAIL STATE
            }
            else
            {
                state = 0x4E4A2BBD; // SUCCESS -> Next
            }
        }

        // STATE: DECRYPT WinHttpReceiveResponse
        else if (state == 0x4E4A2BBD)
        {
            // "WinHttpReceiveResponse" encrypted
            unsigned char raw[] = {
                0x57, 0x6E, 0x68, 0x4D, 0x70, 0x7F, 0x7A, 0x5B,
                0x6D, 0x6C, 0x6B, 0x64, 0x7A, 0x76, 0x40, 0x74,
                0x63, 0x67, 0x79, 0x7B, 0x67, 0x7E, 0x00};
            memcpy(enc_buf, raw, sizeof(raw));

            for (int i = 0; i < 22; i++)
            {
                enc_buf[i] ^= (i - 29) ^ 0xE3;
            }

            printf("[+] Decrypted: %s\n", enc_buf);
            state = 0xD62B0F79;
        }

        // STATE: RESOLVE & CALL WinHttpReceiveResponse
        else if (state == 0xD62B0F79)
        {
            fn_WinHttpReceiveResponse = (t_WinHttpReceiveResponse)resolve_api((char *)enc_buf);
            if (fn_WinHttpReceiveResponse)
            {
                fn_WinHttpReceiveResponse(hRequest, NULL);
            }
            state = 0xB2D8EADE; // END STATE
        }

        // STATE: FAIL
        else if (state == -731028004)
        {
            printf("[-] Error occurred in flattened flow.\n");
            break;
        }

        // STATE: END
        else if (state == 0xB2D8EADE)
        {
            printf("[+] Execution completed successfully.\n");
            break;
        }

        // Unknown state (should not happen)
        else
        {
            break;
        }
    }

    // Cleanup
    if (hRequest)
        WinHttpCloseHandle(hRequest);
    if (hConnect)
        WinHttpCloseHandle(hConnect);
    if (hSession)
        WinHttpCloseHandle(hSession);

    return 0;
}