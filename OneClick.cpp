#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>


DWORD WINAPI NeverLose(LPVOID lparam) {

	LPVOID IMAGEBASE;
	DWORD TargetAddr;
	DWORD OldProtect = 0;

	IMAGEBASE = GetModuleHandleA("minesweeper.exe");


	TargetAddr = (DWORD)IMAGEBASE + 0x28964;


	VirtualProtect((LPVOID)TargetAddr, 2, PAGE_EXECUTE_READWRITE, &OldProtect);

	*((LPBYTE)TargetAddr + 0) = 0x90;
	*((LPBYTE)TargetAddr + 1) = 0x90;


	VirtualProtect((LPVOID)TargetAddr, 2, OldProtect, &OldProtect);


	return 0;
}

BOOL WINAPI DllMain(HMODULE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{

	HANDLE hThread = NULL;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "One Click", "One Click", MB_OK);
		hThread = CreateThread(NULL, 0, NeverLose, NULL, 0, NULL);
	}
	return TRUE;
}