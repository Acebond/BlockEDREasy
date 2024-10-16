#include <Windows.h>

#include <stdio.h>

#define ArraySize(x) (sizeof x / sizeof x[0])

PVOID fnNtCreateSection;

wchar_t* blockedDLLs[] = {
    L"cryptbase.dll",
    L"lolz.dll",
};

LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {

    // Check if this is a single-step exception caused by a hardware breakpoint
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Check if the breakpoint was hit for NtCreateSection
        if (ExceptionInfo->ContextRecord->Dr0 == (DWORD_PTR)fnNtCreateSection) {
            //printf("NtCreateSection Hooked via hardware breakpoint!\n");

            TCHAR lpFilename[256] = { 0 };
            HANDLE fileHandle = *(HANDLE*)(ExceptionInfo->ContextRecord->Rsp + 0x38);
            DWORD res = GetFinalPathNameByHandle(fileHandle, lpFilename, ArraySize(lpFilename), FILE_NAME_OPENED);

            if (res == 0) {
                ExceptionInfo->ContextRecord->EFlags |= 0x10000;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            wchar_t* pLastSlash = wcsrchr(lpFilename, L'\\');
            wchar_t* dllName = pLastSlash ? pLastSlash + 1 : lpFilename;
            
            
            
            int banned = 0;
            for (int i = 0; i < ArraySize(blockedDLLs); i++) {
                if (wcscmp(dllName, blockedDLLs[i]) == 0) {
                    // we dont want to load it
                    ExceptionInfo->ContextRecord->Rip = *(ULONG_PTR*)ExceptionInfo->ContextRecord->Rsp;
                    ExceptionInfo->ContextRecord->Rsp += sizeof(PVOID);
                    ExceptionInfo->ContextRecord->Rax = -1;
                    banned = 1;
                    break;
                }
            }

            if (banned) {
                wprintf(L"BLOCKED: %s\n", dllName);
            } else {
                wprintf(L"LOADED: %s\n", dllName);
            }

            // Set the resume flag before continuing execution
            ExceptionInfo->ContextRecord->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }


	return EXCEPTION_CONTINUE_SEARCH;
}

void EnableBreakpoint(HANDLE hThread, PVOID address) {

    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

    if (!GetThreadContext(hThread, &context)) {
        return;
    }

    context.Dr0 = (DWORD_PTR)address;
    context.Dr7 |= 1;  // Enable the breakpoint for execution on DR0

    // Set the thread context with the updated debug registers
    if (!SetThreadContext(hThread, &context)) {
        return;
    }

}

typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);


int main(void) {

	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	if (!ntdll) return 1;

	fnNtCreateSection = GetProcAddress(ntdll, "NtCreateSection");
	if (!fnNtCreateSection) return 1;

	HANDLE hExHandler = AddVectoredExceptionHandler(1, ExceptionHandler);

    EnableBreakpoint(GetCurrentThread(), fnNtCreateSection);

    //NtCreateSection_t test = fnNtCreateSection;
    //test(1, 2, 3, 4, 5, 6, 7);
    LoadLibraryW(L"cryptbase.dll");
    LoadLibraryW(L"secur32.dll");

	return 0;
}