#include "ManualMapInject.h"


void __stdcall ShellCode(DATA* mm_data);

bool ManualMap(HANDLE hProc, const char* dllFile) {
	BYTE* dllSrcData = nullptr;

	IMAGE_NT_HEADERS* oldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* oldOptHeader = nullptr;
	IMAGE_FILE_HEADER* oldFileHeader = nullptr;

	BYTE* dllDataStart = nullptr;

	
	if (GetFileAttributesA(dllFile) == INVALID_FILE_ATTRIBUTES) {
		printf("File does not exist.\n");
		return false;
	}
	
	std::ifstream DLLObject(dllFile, std::ios::binary | std::ios::ate);
	if (DLLObject.fail()) {
		printf("File Open failed: %X\n", (DWORD)DLLObject.rdstate());
		DLLObject.close();
		return false;
	}

	auto fileSize = DLLObject.tellg();
	if (fileSize < 0x1000) {
		printf("File size invalid, probably invalid file\n");
		DLLObject.close();
		return false;
	}
	dllSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];
	if (!dllSrcData) {
		printf("Memory allocation failed, your file is too large. \n");
		DLLObject.close();
		return false;
	}

	DLLObject.seekg(0, std::ios::beg);
	DLLObject.read(reinterpret_cast<char*>(dllSrcData), fileSize);
	DLLObject.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(dllSrcData)->e_magic != 0x5A4D) {
		printf("Invalid file, not a DLL\n");
		delete[] dllSrcData;
		return false;
	}
	

	// We have a valid file and have transcribed its data.
	oldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(dllSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(dllSrcData)->e_lfanew);
	oldOptHeader = &oldNtHeader->OptionalHeader;
	oldFileHeader = &oldNtHeader->FileHeader;


#ifdef _WIN64
	if (oldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("Invalid platform \n");
		delete[] dllSrcData;
		return false;
	}
	printf("Ran windows 64 directive");
#else // x86
	if (oldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		printf("Invalid platform \n");
		delete[] dllSrcData;
		return false;
	}
#endif

	dllDataStart = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(oldOptHeader->ImageBase), oldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!dllDataStart) {
		dllDataStart = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, oldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!dllDataStart) {
			printf("Sorry bud, SOL. Failed: 0x%X\n", GetLastError());
			delete[] dllSrcData;
			return false;
		}

	}

	DATA mm_data{ 0 };
	mm_data.pLoadLibraryA = LoadLibraryA;
	mm_data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);

	
	// Transfer data in allocated space 

	auto* pSectionHeader = IMAGE_FIRST_SECTION(oldNtHeader);
	for (UINT i = 0; i != oldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, dllDataStart + pSectionHeader->VirtualAddress, dllSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				printf("Unable to map data sections: 0x%X\n", GetLastError());
				delete[] dllSrcData;
				VirtualFreeEx(hProc, dllDataStart, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	
	memcpy(dllSrcData, &mm_data, sizeof(mm_data));
	WriteProcessMemory(hProc, dllDataStart, dllSrcData, 0x1000, nullptr);

	delete[] dllSrcData;

	// PICK BACK UP
	// Allocate space within the process memory
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// Check if allocated successfully
	if (!pShellcode) {
		printf("Unable to allocate memory for the shellcode. Ex: 0x%X\n", GetLastError());
		// Free the memory of the dll code we allocated
		VirtualFreeEx(hProc, dllDataStart, 0, MEM_RELEASE);
	}
	// Write the shell code into the process memory
	if (!WriteProcessMemory(hProc, pShellcode, ShellCode, 0x1000, nullptr)) {
		printf("Unable to write the shellcode into memory. Ex: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, dllDataStart, 0, MEM_RELEASE);
	}
	// Call the shell code (by creating a remote thread)
	HANDLE shellThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), dllDataStart, 0, nullptr);
	// Check that it ran successfully
	if (!shellThread) {
		printf("Thread creation failed: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, dllDataStart, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	// Close out all of our variables / deallocate memory
	// Return true to let the program know that we injected successfully
	CloseHandle(shellThread);

	HINSTANCE check = NULL;
	while (!check) {
		DATA comparedData{ 0 };
		ReadProcessMemory(hProc, dllDataStart, &comparedData, sizeof(comparedData), nullptr);
		check = comparedData.hMod;
		Sleep(10);
	}
	
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
	return true;

}


#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif
void __stdcall ShellCode(DATA* mm_data) {
	if (!mm_data) {
		return;
	}

	BYTE* baseAddress = reinterpret_cast<BYTE*>(mm_data);

	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(baseAddress + (reinterpret_cast<IMAGE_DOS_HEADER*>(mm_data)->e_lfanew))->OptionalHeader;

	auto _LoadLibraryA = mm_data->pLoadLibraryA;
	auto _GetProcAddress = mm_data->pGetProcAddress;

	auto dllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(baseAddress + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = baseAddress - pOpt->ImageBase;

	if (LocationDelta) {
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return;
		}
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(baseAddress + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress) {
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(baseAddress + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
				
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	// Import section
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportImgDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(baseAddress + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportImgDescr->Name) {
			char* dllMod = reinterpret_cast<char*>(baseAddress + pImportImgDescr->Name);
			HINSTANCE hDLL = _LoadLibraryA(dllMod);
			ULONG_PTR* pOThunkRef = reinterpret_cast<ULONG_PTR*>(baseAddress + pImportImgDescr->OriginalFirstThunk);
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(baseAddress + pImportImgDescr->FirstThunk);

			if (!pOThunkRef) {
				pOThunkRef = pThunkRef;
			}
			
			for (; *pOThunkRef; ++pOThunkRef, ++pThunkRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pOThunkRef)) {
					// FIX: this should be 4 F and & rather than *
					*pThunkRef = _GetProcAddress(hDLL, reinterpret_cast<char*>(*pOThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(baseAddress + *pOThunkRef);
					*pThunkRef = _GetProcAddress(hDLL, pImport->Name);
				}
			}

			++pImportImgDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(baseAddress + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallbacks && *pCallbacks; ++pCallbacks) {
			(*pCallbacks)(baseAddress, DLL_PROCESS_ATTACH, nullptr);
		}

	}

	dllMain(baseAddress, DLL_PROCESS_ATTACH, nullptr);

	mm_data->hMod = reinterpret_cast<HINSTANCE>(baseAddress);


}