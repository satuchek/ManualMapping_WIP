#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <tlhelp32.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* injectedDLLPath);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE process, const char* processName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDLL, DWORD dwReason, void* pReserved);

struct DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hMod;
};

bool ManualMap(HANDLE hProc, const char* dllFile);



