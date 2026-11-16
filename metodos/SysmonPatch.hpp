#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wmistr.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstdio>
#include <functional>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")

class SysmonPatch
{
public:
    static bool Initialize();
    static bool Patch(std::function<void()> onPatched = nullptr);
    static bool Restore();
    static bool IsPatched();
    static void Reset();

private:
    static bool bInitialized;
    static bool bIsPatched;
    static HANDLE hProcess;
    static TRACEHANDLE hSession;
    static std::vector<GUID> vProviders;

    static void EnableDebugPrivilege();
    static DWORD FindTargetPID();
    static HANDLE ImpersonateProcess(DWORD pid);
    static TRACEHANDLE GetSessionHandle(LPCTSTR sessionName);
    static std::vector<GUID> GetProvidersForSession(TRACEHANDLE hSession);
    
    static void ControlProviders(TRACEHANDLE hSession,
        const std::vector<GUID>& providers,
        ULONG controlCode);
};
