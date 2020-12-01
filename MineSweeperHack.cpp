#include <Windows.h>
#include <tchar.h>
#include <Psapi.h>


DWORD WINAPI NeverLose(LPVOID lparam) {

	LPVOID IMAGEBASE;
	DWORD TargetAddr;
	DWORD OldProtect = 0;

	IMAGEBASE = GetModuleHandleA("minesweeper.exe");


	TargetAddr = (DWORD)IMAGEBASE + 0x26fe5;


	VirtualProtect((LPVOID)TargetAddr, 1, PAGE_EXECUTE_READWRITE, &OldProtect);

	*((LPBYTE)TargetAddr + 0) = 0xEB;


	VirtualProtect((LPVOID)TargetAddr, 1, OldProtect, &OldProtect);


	return 0;
}

BOOL WINAPI DllMain(HMODULE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{

	HANDLE hThread = NULL;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "Hook Ready", "Hook Ready", MB_OK);
		hThread = CreateThread(NULL, 0, NeverLose, NULL, 0, NULL);
	}
	return TRUE;
}