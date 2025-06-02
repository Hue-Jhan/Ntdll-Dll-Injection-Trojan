#pragma once
#include <stdio.h>
#include <windows.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L
#define PRINTXD(FUNCTION_NAME, NTSTATUS_ERROR)                        \
    do {                                                                  \
        fprintf(stderr,                                                   \
                FUNCTION_NAME " %s %d error: 0x%lx\n", \
                __FILE__, __LINE__, NTSTATUS_ERROR);                      \
    } while (0)

typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* xd_NtOpenProcess)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
    );

typedef NTSTATUS(NTAPI* xd_NtAllocateVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

typedef NTSTATUS(NTAPI* xd_NtProtectVirtualMemory)(
    _In_      HANDLE ProcessHandle,
    _Inout_   PVOID* BaseAddress,
    _Inout_   PSIZE_T RegionSize,
    _In_      ULONG NewProtect,
    _Out_     PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* xd_NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
    );

typedef NTSTATUS(NTAPI* xd_NtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
    );

typedef NTSTATUS(NTAPI* xd_NtWaitForSingleObject)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* xd_NtFreeVirtualMemory)(
    _In_      HANDLE ProcessHandle,
    _Inout_   PVOID* BaseAddress,
    _Inout_   PSIZE_T RegionSize,
    _In_      ULONG FreeType
    );

typedef NTSTATUS(NTAPI* xd_NtClose)(
    IN HANDLE Handle
    );

UINT_PTR GetNtFunctionAddress(LPCSTR FunctionName, HMODULE ModuleHandle) {
    return (UINT_PTR)GetProcAddress(ModuleHandle, FunctionName);
}

