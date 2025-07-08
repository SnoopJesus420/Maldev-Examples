#include <windows.h>
#include <stdio.h>
#include <string.h>

FARPROC CustomGetProc(IN HMODULE hModule, IN LPCSTR lpApiName) {
    PBYTE pBase = (PBYTE)hModule;

    // Get DOS headers and check signature
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return NULL;
    }

    // Get NT headers and check signature
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return NULL;
    }

    // Get optional header
    IMAGE_OPTIONAL_HEADER pImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Get image export directory
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase +
        pImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExportDir->AddressOfNames) {
        printf("[-] No export names found\n");
        return NULL;
    }

    // Get arrays for names, addresses, and ordinals
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    // Loop through exported function names
    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        // Get function name
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (!pFunctionName) {
            continue;
        }

        // Get function address via ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // Compare with requested API name
        if (strcmp(lpApiName, pFunctionName) == 0) {
            printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p -\t ORDINAL: %d\n",
                i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return (FARPROC)pFunctionAddress;
        }
    }

    printf("[-] API '%s' not found in export table\n", lpApiName);
    return NULL;
}

int main() {
    HMODULE hModule = NULL;
    LPCSTR lpApiName = "VirtualAllocEx";

    printf("[i] Getting handle to kernel32.dll... ");
    hModule = GetModuleHandleA("kernel32.dll");
    if (hModule == NULL) {
        printf("Failed! Error: %d\n", GetLastError());
        return 1;
    }
    printf("Success!!\n");

    printf("[+] Using CustomGetProc\n");
    printf("[i] Searching for: %s\n", lpApiName);
    FARPROC result = CustomGetProc(hModule, lpApiName);
    if (result == NULL) {
        printf("[-] Failed to find %s\n", lpApiName);
    }
    else {
        printf("[+] Success! Function address: 0x%p\n", result);
    }

    FARPROC WinAPI = GetProcAddress(hModule, lpApiName);
    if (WinAPI == NULL) {
        printf("[!] GetProcAddress Failed! %d", GetLastError());
        return 1;

    }
    else {
        printf("[+] GetProcAddress Results: 0x%p\n", WinAPI);
    }

    printf("[i] Done! Press Enter to exit...");
    getchar();

    // No need to close hModule from GetModuleHandleA
    return 0;
}
