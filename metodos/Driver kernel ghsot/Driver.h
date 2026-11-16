#pragma once


#if defined(_KERNEL_MODE) && !defined(WIN32)
    #include <ntifs.h>
    #include <ntddk.h>
    #include <wdm.h>
#else
    #include <windows.h>
    #include <winternl.h>
    #ifndef PUNICODE_STRING
    typedef struct _UNICODE_STRING *PUNICODE_STRING;
    #endif
#endif

#define DRIVER_NAME L"\\Device\\WLoaderDriver"
#define SYMBOLIC_LINK L"\\DosDevices\\WLoaderDriver"
#define DRIVER_DEVICE_NAME L"\\\\.\\WLoaderDriver"

#define IO_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_MODULE_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_PROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_ELEVATE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_HIDE_PROCESS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_CLEAN_USN        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_CLEAN_BAM        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _KERNEL_READ_REQUEST {
    ULONG ProcessId;
    ULONGLONG Address;
    ULONGLONG Size;
    PVOID OutputBuffer;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
    ULONG ProcessId;
    ULONGLONG Address;
    ULONGLONG Size;
    PVOID InputBuffer;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_BASE_REQUEST {
    ULONG ProcessId;
    WCHAR ModuleName[256];
    ULONGLONG BaseAddress;
    ULONGLONG Size;
} KERNEL_BASE_REQUEST, *PKERNEL_BASE_REQUEST;

typedef struct _KERNEL_PROCESS_REQUEST {
    ULONG ProcessId;
} KERNEL_PROCESS_REQUEST, *PKERNEL_PROCESS_REQUEST;

typedef struct _HIDE_PROCESS_REQUEST {
    ULONG ProcessId;
} HIDE_PROCESS_REQUEST, *PHIDE_PROCESS_REQUEST;

typedef struct _CLEAN_USN_REQUEST {
    ULONG DriveLetter;
} CLEAN_USN_REQUEST, *PCLEAN_USN_REQUEST;

#if defined(_KERNEL_MODE)

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDeviceObject, PIRP Irp);

#endif
