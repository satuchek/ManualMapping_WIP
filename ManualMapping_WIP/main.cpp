#include "ManualMapInject.h"

const char dllFile[] = "C:\\Users\\StormTuchek\\source\\repos\\CSGO_EntityTest\\Debug\\CSGO_EntityTest.dll";
const char testDLL[] = "C:\\Users\\StormTuchek\\Downloads\\test.dll";
const char targetProcess[] = "csgo.exe";

// missing architecture function

int main() {
	PROCESSENTRY32 PE32{ 0 };
	// Basically, if you don't do this part, then the thing fails. Good going C++
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolHelp32Snapshot failed: 0x%X\n", GetLastError());
		system("PAUSE");
		return 0;
	}

	BOOL bReturnedProc = Process32First(hSnap, &PE32);
	DWORD PID = 0;

	while (bReturnedProc) {
	
		// We want to check if we've found the target process, and then store its ID
		if (!strcmp(targetProcess, PE32.szExeFile)) {
			PID = PE32.th32ProcessID;
			break;
		}
		// If not, move on to the next one
		bReturnedProc = Process32Next(hSnap, &PE32);
	}
	CloseHandle(hSnap);

	if (PID == 0) {
		std::cout << "Did not find that process. Are you sure the game you're hacking is running?" << std::endl;
		system("PAUSE");
		return 0;
	}

	// FIX: capitalize false here
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		printf("OpenProcess failed: 0x%X\n", GetLastError());
		system("PAUSE");
		return 0;
	}

	// FIX: ADD TARGET ARCHITECTURE CHECK HERE

	// POSSIBLE FIX: rearrange this check
	if (!ManualMap(hProc, dllFile)) {
		CloseHandle(hProc);
		printf("Unable to inject :( sorry bro ur hax bad\n");
		system("PAUSE");
		return 0;
	}
	else {
		CloseHandle(hProc);
		printf("Mapped successfully. \n");
		return 0;
	}
}