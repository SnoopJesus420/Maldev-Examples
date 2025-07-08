#include <Windows.h>
#include <winternl.h>
#include <stdio.h>



BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR   lStr1[MAX_PATH],
		lStr2[MAX_PATH];

	int		len1 = lstrlenW(Str1),
		len2 = lstrlenW(Str2);

	int		i = 0,
		j = 0;

	// Checking length. We dont want to overflow the buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// Converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating

	// Converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating

	// Comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

HMODULE CustomGetModule(IN LPCWSTR szModuleName){
	// Getting PEB
#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	// Getting Ldr
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	// Getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// If not null
		if (pDte->FullDllName.Length != NULL) {

			// Check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll Using Custom GetModuleHandle \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}

		// Next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}

int main() {
	printf("[i] Original 0x%p\n", GetModuleHandle(L"NTDLL.DLL"));
	printf("[i] Custom GetModuleHandle 0x%p\n", CustomGetModule(L"NTDLL.DLL"));
	printf("Press <Enter> To Quit...");
	getchar();

	return 0;
}
