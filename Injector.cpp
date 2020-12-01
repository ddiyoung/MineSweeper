#include <Windows.h>
#include <tchar.h>

BOOL Inject(DWORD hwPID, LPCTSTR DllPath) {

	//프로세스, 쓰레드, 모듈의 핸들을 담을 구조체 변수입니다.
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HMODULE hMod = NULL;

	// DLL 경로를 기록한 메모리 주소를 넣을 포인터 변수입니다.
	LPVOID pRemoteBuf = NULL;

	// DLL 경로의 사이즈를 나타냅니다.
	DWORD dwBufSize = (DWORD)(_tcslen(DllPath)+1) * sizeof(TCHAR);

	// 쓰레드 시작 루틴함수주소를 저장할 변수입니다.
	LPTHREAD_START_ROUTINE pThreadProc;

	// Step 1. 인젝션 할 프로세스 제어권 얻기
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hwPID);

	// Step 2. 인젝션 할 DLL 경로를 해당 프로세스에 기록
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)DllPath, dwBufSize, NULL);

	// Step 3. 쓰여진 DLL을 프로세스에서 로드하기 위한 작업하기
	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

	// Step 4. 쓰여진 DLL을 원격쓰레드 생성을 통해 프로세스에서 로드
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	// 쓰레드가 실행될때 까지 무한정 대기합니다.
	WaitForSingleObject(hThread, INFINITE);

	// 사용한 핸들들을 닫아줍니다.
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return 1;
}



int _tmain(int argc, TCHAR* argv[]) {
	if (argc != 3) {
		_tprintf(L"USAGE : %s pid dll_path\n", argv[0]);
		return 1;
	}

	if (Inject((DWORD)_tstol(argv[1]), argv[2]))
		_tprintf(L"%s inject success!\n", argv[2]);
	else
		_tprintf(L"%s inject failed..\n", argv[2]);

		return 0;
}
