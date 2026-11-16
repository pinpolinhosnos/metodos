#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string, ... )                   \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?                            \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _string, __VA_ARGS__) : \
        ((int)0))

//
//  Prototypes
//

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
HideFsUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
HideFsPostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
HideFsPreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, HideFsUnload)
#pragma alloc_text(PAGE, HideFsPostDirectoryControl)
#endif

//
//  Operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      HideFsPreDirectoryControl,
      HideFsPostDirectoryControl },

    { IRP_MJ_OPERATION_END }
};

//
//  Filter Registration
//

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    HideFsUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

//
//  Files to hide (Hardcoded for example, should be dynamic in real usage)
//
WCHAR* g_HiddenFiles[] = {
    L"mysource.exe",
    L"cheat.dll",
    L"injector.exe",
    L"config.json"
};

ULONG g_HiddenFilesCount = sizeof(g_HiddenFiles) / sizeof(g_HiddenFiles[0]);

//
//  Functions
//

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, "HideFs!DriverEntry: Entered\n");

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter(DriverObject,
                               &FilterRegistration,
                               &gFilterHandle);

    ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status)) {
            FltUnregisterFilter(gFilterHandle);
        }
    }

    return status;
}

NTSTATUS
HideFsUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, "HideFs!HideFsUnload: Entered\n");

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
HideFsPreDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // We only care about QueryDirectory
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

//
//  Structure for Directory Enumeration (Common ones)
//
typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;


BOOLEAN ShouldHideFile(WCHAR* FileName, ULONG FileNameLength)
{
    if (!FileName || FileNameLength == 0) return FALSE;

    for (ULONG i = 0; i < g_HiddenFilesCount; i++) {
        SIZE_T hiddenLen = wcslen(g_HiddenFiles[i]);
        // Simple substring check or exact match
        // Note: FileName is not null-terminated in buffer usually
        if (FileNameLength >= hiddenLen * sizeof(WCHAR)) {
            if (_wcsnicmp(FileName, g_HiddenFiles[i], hiddenLen) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

FLT_POSTOP_CALLBACK_STATUS
HideFsPostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFLT_PARAMETERS params = &Data->Iopb->Parameters;
    ULONG FileInformationClass = ((PFILE_INFORMATION_CLASS)params->DirectoryControl.QueryDirectory.FileInformationClass)[0];
    PVOID Buffer = params->DirectoryControl.QueryDirectory.DirectoryBuffer;

    // Handle MDL if present
    if (params->DirectoryControl.QueryDirectory.MdlAddress) {
        Buffer = MmGetSystemAddressForMdlSafe(params->DirectoryControl.QueryDirectory.MdlAddress, NormalPagePriority);
    }

    if (!Buffer) return FLT_POSTOP_FINISHED_PROCESSING;

    // Iterate and hide
    // We need to handle different info classes.
    // Common ones: FileIdBothDirectoryInformation, FileBothDirectoryInformation, FileDirectoryInformation, FileFullDirectoryInformation, FileIdFullDirectoryInformation, FileNamesInformation

    ULONG Offset = 0;
    ULONG NextOffset = 0;
    PVOID CurrentEntry = Buffer;
    PVOID PreviousEntry = NULL;
    BOOLEAN Modified = FALSE;

    do {
        WCHAR* FileName = NULL;
        ULONG FileNameLength = 0;
        ULONG* pNextEntryOffset = NULL;

        switch (FileInformationClass) {
            case FileIdBothDirectoryInformation: {
                PFILE_ID_BOTH_DIR_INFORMATION info = (PFILE_ID_BOTH_DIR_INFORMATION)CurrentEntry;
                FileName = info->FileName;
                FileNameLength = info->FileNameLength;
                pNextEntryOffset = &info->NextEntryOffset;
                break;
            }
            case FileBothDirectoryInformation: {
                PFILE_BOTH_DIR_INFORMATION info = (PFILE_BOTH_DIR_INFORMATION)CurrentEntry;
                FileName = info->FileName;
                FileNameLength = info->FileNameLength;
                pNextEntryOffset = &info->NextEntryOffset;
                break;
            }
            case FileDirectoryInformation: {
                PFILE_DIRECTORY_INFORMATION info = (PFILE_DIRECTORY_INFORMATION)CurrentEntry;
                FileName = info->FileName;
                FileNameLength = info->FileNameLength;
                pNextEntryOffset = &info->NextEntryOffset;
                break;
            }
            case FileFullDirectoryInformation: {
                PFILE_FULL_DIR_INFORMATION info = (PFILE_FULL_DIR_INFORMATION)CurrentEntry;
                FileName = info->FileName;
                FileNameLength = info->FileNameLength;
                pNextEntryOffset = &info->NextEntryOffset;
                break;
            }
            case FileIdFullDirectoryInformation: {
                PFILE_ID_FULL_DIR_INFORMATION info = (PFILE_ID_FULL_DIR_INFORMATION)CurrentEntry;
                FileName = info->FileName;
                FileNameLength = info->FileNameLength;
                pNextEntryOffset = &info->NextEntryOffset;
                break;
            }
            case FileNamesInformation: {
                PFILE_NAMES_INFORMATION info = (PFILE_NAMES_INFORMATION)CurrentEntry;
                FileName = info->FileName;
                FileNameLength = info->FileNameLength;
                pNextEntryOffset = &info->NextEntryOffset;
                break;
            }
            default:
                break;
        }

        if (FileName && ShouldHideFile(FileName, FileNameLength)) {
            // Hide this entry
            if (PreviousEntry) {
                // Not the first entry, just skip it
                ULONG* pPrevNext = NULL;
                // Need to get pNextEntryOffset of PreviousEntry... annoying because we cast it void
                // Re-cast PreviousEntry based on Class
                 switch (FileInformationClass) {
                    case FileIdBothDirectoryInformation: pPrevNext = &((PFILE_ID_BOTH_DIR_INFORMATION)PreviousEntry)->NextEntryOffset; break;
                    case FileBothDirectoryInformation: pPrevNext = &((PFILE_BOTH_DIR_INFORMATION)PreviousEntry)->NextEntryOffset; break;
                    case FileDirectoryInformation: pPrevNext = &((PFILE_DIRECTORY_INFORMATION)PreviousEntry)->NextEntryOffset; break;
                    case FileFullDirectoryInformation: pPrevNext = &((PFILE_FULL_DIR_INFORMATION)PreviousEntry)->NextEntryOffset; break;
                    case FileIdFullDirectoryInformation: pPrevNext = &((PFILE_ID_FULL_DIR_INFORMATION)PreviousEntry)->NextEntryOffset; break;
                    case FileNamesInformation: pPrevNext = &((PFILE_NAMES_INFORMATION)PreviousEntry)->NextEntryOffset; break;
                }

                if (*pNextEntryOffset == 0) {
                    *pPrevNext = 0; // Last entry hidden
                } else {
                    *pPrevNext += *pNextEntryOffset; // Skip
                }
                Modified = TRUE;
                // Do NOT update PreviousEntry, as CurrentEntry is effectively removed
            } else {
                // First entry hidden.
                if (*pNextEntryOffset == 0) {
                    // Only entry?
                    Data->IoStatus.Status = STATUS_NO_MORE_FILES;
                    return FLT_POSTOP_FINISHED_PROCESSING;
                } else {
                    // Move memory to overwrite first entry with second entry
                    // We can't easily move memory safely here if buffer size is tight, 
                    // but usually we just advance the buffer pointer? 
                    // No, FltMgr expects Buffer to start at the beginning.
                    // We must memmove.
                    ULONG BytesToMove = 0;
                    // Calculate remaining bytes... complex without buffer size.
                    // But we know NextEntryOffset.
                    // Let's just zero it out? No.
                    // Safe strategy: Mark as "skipped" by modifying buffer? 
                    // Standard way: Memmove rest of buffer to start.
                    // But we don't know total buffer size easily here without IoStatus.Information?
                    // IoStatus.Information contains number of bytes transferred.
                    
                    ULONG TotalBytes = (ULONG)Data->IoStatus.Information;
                    ULONG EntrySize = *pNextEntryOffset; // Offset to next
                    // Actually, if we are at start (Offset 0), and we want to hide it:
                    PVOID NextEntryAddr = (PCHAR)CurrentEntry + *pNextEntryOffset;
                    ULONG BytesRemaining = TotalBytes - *pNextEntryOffset;
                    
                    RtlMoveMemory(CurrentEntry, NextEntryAddr, BytesRemaining);
                    Data->IoStatus.Information -= *pNextEntryOffset; // Reduce count
                    
                    // Re-process this "new" first entry
                    continue; 
                }
            }
        } else {
            PreviousEntry = CurrentEntry;
        }

        if (pNextEntryOffset && *pNextEntryOffset != 0) {
            CurrentEntry = (PCHAR)CurrentEntry + *pNextEntryOffset;
        } else {
            break;
        }

    } while (TRUE);

    return FLT_POSTOP_FINISHED_PROCESSING;
}
