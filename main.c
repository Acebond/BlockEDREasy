#include <Windows.h>

#include <stdio.h>

#define ArraySize(x) (sizeof x / sizeof x[0])

//PVOID fnNtCreateSection;

wchar_t* blockedDLLs[] = {
    L"cryptbase.dll",
    L"lolz.dll",
    L"umppc18613.dll",
};

//LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
//
//    // Check if this is a single-step exception caused by a hardware breakpoint
//    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
//        // Check if the breakpoint was hit for NtCreateSection
//        if (ExceptionInfo->ContextRecord->Dr0 == (DWORD_PTR)fnNtCreateSection) {
//            //printf("NtCreateSection Hooked via hardware breakpoint!\n");
//
//            TCHAR lpFilename[256] = { 0 };
//            HANDLE fileHandle = *(HANDLE*)(ExceptionInfo->ContextRecord->Rsp + 0x38);
//            DWORD res = GetFinalPathNameByHandle(fileHandle, lpFilename, ArraySize(lpFilename), FILE_NAME_OPENED);
//
//            if (res == 0) {
//                ExceptionInfo->ContextRecord->EFlags |= 0x10000;
//                return EXCEPTION_CONTINUE_EXECUTION;
//            }
//
//            wchar_t* pLastSlash = wcsrchr(lpFilename, L'\\');
//            wchar_t* dllName = pLastSlash ? pLastSlash + 1 : lpFilename;
//            
//            
//            
//            int banned = 0;
//            for (int i = 0; i < ArraySize(blockedDLLs); i++) {
//                if (wcscmp(dllName, blockedDLLs[i]) == 0) {
//                    // we dont want to load it
//                    ExceptionInfo->ContextRecord->Rip = *(ULONG_PTR*)ExceptionInfo->ContextRecord->Rsp;
//                    ExceptionInfo->ContextRecord->Rsp += sizeof(PVOID);
//                    ExceptionInfo->ContextRecord->Rax = -1;
//                    banned = 1;
//                    break;
//                }
//            }
//
//            if (banned) {
//                wprintf(L"BLOCKED: %s\n", dllName);
//            } else {
//                wprintf(L"LOADED: %s\n", dllName);
//            }
//
//            // Set the resume flag before continuing execution
//            ExceptionInfo->ContextRecord->EFlags |= 0x10000;
//            return EXCEPTION_CONTINUE_EXECUTION;
//        }
//    }
//
//
//	return EXCEPTION_CONTINUE_SEARCH;
//}

void EnableBreakpoint(HANDLE hThread, DWORD64 address, int index) {

    // Ensure the index is valid (between 0 and 3)
    if (index < 0 || index > 3) {
        return;
    }

    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

    // Get the thread context to modify the debug registers
    if (!GetThreadContext(hThread, &context)) {
        return;
    }

    // Set the appropriate Dr register based on the index
    switch (index) {
    case 0:
        context.Dr0 = address;
        context.Dr7 |= (1 << 0);
        break;
    case 1:
        context.Dr1 = address;
        context.Dr7 |= (1 << 2);
        break;
    case 2:
        context.Dr2 = address;
        context.Dr7 |= (1 << 4);
        break;
    case 3:
        context.Dr3 = address;
        context.Dr7 |= (1 << 6);
        break;
    }

    // Set the thread context with the updated debug registers
    if (!SetThreadContext(hThread, &context)) {
        return;
    }

}

typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

DWORD WINAPI ThreadFunction(LPVOID lpParam) {
    Sleep(1000);
    ResumeThread((HANDLE)lpParam);
    return 0;
}

int main(void) {

	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	if (!ntdll) return 1;

    PVOID fnNtCreateSection = GetProcAddress(ntdll, "NtCreateSection");
	if (!fnNtCreateSection) return 1;

    PVOID fnNtCreateUserProcess = GetProcAddress(ntdll, "NtCreateUserProcess");
    if (!fnNtCreateUserProcess) return 1;

    PROCESS_INFORMATION processInfo = { 0 };
    STARTUPINFO startupInfo = { .cb = sizeof(STARTUPINFO) };

    //wchar_t applicationName[] = L"C:\\test\\child.exe";
    wchar_t applicationName[] = L"C:\\Users\\acebond\\source\\repos\\child\\x64\\Release\\child.exe";

    BOOL success = CreateProcess(
        applicationName,  // Application name
        NULL,             // Command line arguments
        NULL,             // Process handle not inheritable
        NULL,             // Thread handle not inheritable
        FALSE,            // Set handle inheritance to FALSE
        CREATE_SUSPENDED | DEBUG_PROCESS, // Create the process in a suspended state
        NULL,             // Use parent's environment block
        NULL,             // Use parent's starting directory 
        &startupInfo,     // Pointer to STARTUPINFO structure
        &processInfo      // Pointer to PROCESS_INFORMATION structure
    );
    
    if (!success) {
        printf("Failed to create process. Error: %lu\n", GetLastError());
    }

    EnableBreakpoint(processInfo.hThread, fnNtCreateSection, 0);
    EnableBreakpoint(processInfo.hThread, fnNtCreateUserProcess, 1);

    HANDLE hThread = CreateThread(NULL, 0, ThreadFunction, processInfo.hThread, 0,NULL);

    DEBUG_EVENT dbgEvent = { 0 };
    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {

        if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            break;
        }
        
        // Check if this is a single-step exception caused by a hardware breakpoint
        if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && 
            dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {

            // Check if the breakpoint was hit for NtCreateSection
            if (dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == fnNtCreateSection) {
                //printf("NtCreateSection Hooked via hardware breakpoint!\n");

                CONTEXT newCtx = { .ContextFlags = CONTEXT_ALL };
                GetThreadContext(processInfo.hThread, &newCtx);


                TCHAR lpFilename[256] = { 0 };
                //HANDLE fileHandle = *(HANDLE*)(newCtx.Rsp + 0x38);

                HANDLE fileHandle;
                SIZE_T read = 0;
                BOOL ret = ReadProcessMemory(processInfo.hProcess, newCtx.Rsp + 0x38, &fileHandle, sizeof(HANDLE), &read);

                HANDLE fileHandleReal = NULL;
                ret = DuplicateHandle(processInfo.hProcess, fileHandle, GetCurrentProcess(), &fileHandleReal, 0, FALSE, DUPLICATE_SAME_ACCESS);

                DWORD res = GetFinalPathNameByHandle(fileHandleReal, lpFilename, ArraySize(lpFilename), FILE_NAME_OPENED);

                if (res == 0) {
                    newCtx.EFlags |= 0x10000;
                    SetThreadContext(processInfo.hThread, &newCtx);
                    ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                    continue;
                    //ExceptionInfo->ContextRecord->EFlags |= 0x10000;
                    //return EXCEPTION_CONTINUE_EXECUTION;

                }

                wchar_t* pLastSlash = wcsrchr(lpFilename, L'\\');
                wchar_t* dllName = pLastSlash ? pLastSlash + 1 : lpFilename;



                int banned = 0;
                for (int i = 0; i < ArraySize(blockedDLLs); i++) {
                    if (wcscmp(dllName, blockedDLLs[i]) == 0) {
                        // we dont want to load it

                        DWORD64 newRip;
                        BOOL ret = ReadProcessMemory(processInfo.hProcess, newCtx.Rsp, &newRip, sizeof(DWORD64), NULL);

                        //newCtx.Rip = *(ULONG_PTR*)newCtx.Rsp;
                        newCtx.Rip = newRip;
                        newCtx.Rsp += sizeof(PVOID);
                        newCtx.Rax = -1;
                        banned = 1;
                        break;
                    }
                }

                if (banned) {
                    wprintf(L"BLOCKED: %s\n", dllName);
                }
                else {
                    wprintf(L"LOADED: %s\n", dllName);
                }

                // Set the resume flag before continuing execution
                newCtx.EFlags |= 0x10000;
                SetThreadContext(processInfo.hThread, &newCtx);
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                continue;
            }

            if (dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == fnNtCreateUserProcess) {
                printf("Hit create thread\n");
                ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
                continue;
            }
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
    }
	return 0;
}
