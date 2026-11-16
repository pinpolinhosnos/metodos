#include "streamproof_amd.h"
#include <windows.h>
#include <shlobj.h>
#include <dxgi.h>
#include <shlwapi.h>
#include <winhttp.h>
#ifdef _MSC_VER
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")
#endif

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <deque>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

static const wchar_t* ffname = L"amf_enc_svc.exe";
static const wchar_t* pname = L"amf_probe.exe";
static const int segsec = 5;
static const int ringcap = 60;

namespace {

enum class Vendor { unknown, nvidia, amd, intel };

std::atomic<bool> g_run{ false };
std::atomic<DWORD> g_tick{ 0 };
Vendor g_vendor = Vendor::unknown;
HWND g_hwnd = nullptr;
HANDLE g_stop = nullptr;
HANDLE g_proc = nullptr;
std::mutex g_procmtx;
std::thread g_cap;
std::vector<std::thread> g_watch;
std::thread g_worker;
std::mutex g_workmtx;
std::condition_variable g_workcv;
std::deque<std::wstring> g_queue;
std::set<std::wstring> g_done;
std::mutex g_statmtx;
std::string g_stat = "disabled";

void SetStat(const char* s)
{
    std::lock_guard<std::mutex> lock(g_statmtx);
    g_stat = s;
}

std::wstring ToolDir()
{
    wchar_t buf[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buf)))
        return {};
    return std::wstring(buf) + L"\\AMD\\VCEEncoderCache";
}

std::wstring VideosDir()
{
    wchar_t buf[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_MYVIDEO, nullptr, 0, buf)))
        return {};
    return buf;
}

std::wstring DownloadsDir()
{
    PWSTR p = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &p)))
        return {};
    std::wstring out = p ? p : L"";
    CoTaskMemFree(p);
    return out;
}

std::wstring TempDir()
{
    wchar_t buf[MAX_PATH]{};
    DWORD n = GetTempPathW(MAX_PATH, buf);
    return n && n < MAX_PATH ? std::wstring(buf) : L"";
}

std::wstring BufDir()
{
    return TempDir() + L"AMFCache\\seg";
}

bool FileExists(const std::wstring& p)
{
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool MkDir(const std::wstring& p)
{
    if (p.empty()) return false;
    if (CreateDirectoryW(p.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS)
        return true;
    size_t pos = p.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos < 3 || !MkDir(p.substr(0, pos)))
        return false;
    return CreateDirectoryW(p.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

Vendor GetVendor()
{
    IDXGIFactory* fac = nullptr;
    if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&fac)) || !fac)
        return Vendor::unknown;
    Vendor v = Vendor::unknown;
    IDXGIAdapter* ad = nullptr;
    if (SUCCEEDED(fac->EnumAdapters(0, &ad)) && ad) {
        DXGI_ADAPTER_DESC d{};
        if (SUCCEEDED(ad->GetDesc(&d))) {
            switch (d.VendorId) {
            case 0x10de: v = Vendor::nvidia; break;
            case 0x1002: case 0x1022: v = Vendor::amd; break;
            case 0x8086: v = Vendor::intel; break;
            }
        }
        ad->Release();
    }
    fac->Release();
    return v;
}

bool Spawn(std::wstring cmd, HANDLE in, HANDLE out, PROCESS_INFORMATION* pi)
{
    STARTUPINFOEXW six{};
    six.StartupInfo.cb = sizeof(six);
    six.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    six.StartupInfo.hStdInput = in;
    six.StartupInfo.hStdOutput = out;
    six.StartupInfo.hStdError = out;
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<char> mem(size);
    six.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)mem.data();
    HANDLE list[] = { in, out };
    DWORD count = in == out ? 1 : 2;
    if (!InitializeProcThreadAttributeList(six.lpAttributeList, 1, 0, &size) ||
        !UpdateProcThreadAttribute(six.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, count * sizeof(HANDLE), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(six.lpAttributeList);
        return false;
    }
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
        &six.StartupInfo, pi);
    DeleteProcThreadAttributeList(six.lpAttributeList);
    return ok != FALSE;
}

int RunWait(const std::wstring& cmd, DWORD timeout = INFINITE)
{
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (nul == INVALID_HANDLE_VALUE) return -1;
    PROCESS_INFORMATION pi{};
    if (!Spawn(cmd, nul, nul, &pi)) {
        CloseHandle(nul);
        return -1;
    }
    CloseHandle(nul);
    DWORD wait = WaitForSingleObject(pi.hProcess, timeout);
    DWORD ec = 1;
    if (wait == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return wait == WAIT_OBJECT_0 ? (int)ec : -1;
}

std::string RunCapture(const std::wstring& cmd)
{
    HANDLE rp = nullptr, wp = nullptr;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    if (!CreatePipe(&rp, &wp, &sa, 0)) return {};
    SetHandleInformation(rp, HANDLE_FLAG_INHERIT, 0);
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    if (!in || in == INVALID_HANDLE_VALUE) in = wp;
    PROCESS_INFORMATION pi{};
    if (!Spawn(cmd, in, wp, &pi)) {
        CloseHandle(rp);
        CloseHandle(wp);
        return {};
    }
    CloseHandle(wp);
    std::string out;
    char buf[4096];
    DWORD start = GetTickCount();
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rp, nullptr, 0, nullptr, &avail, nullptr)) break;
        if (avail) {
            DWORD n = 0;
            DWORD len = (std::min)(avail, (DWORD)sizeof(buf));
            if (!ReadFile(rp, buf, len, &n, nullptr) || !n) break;
            out.append(buf, n);
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
            while (PeekNamedPipe(rp, nullptr, 0, nullptr, &avail, nullptr) && avail) {
                DWORD n = 0;
                DWORD len = (std::min)(avail, (DWORD)sizeof(buf));
                if (!ReadFile(rp, buf, len, &n, nullptr) || !n) break;
                out.append(buf, n);
            }
            break;
        }
        if (GetTickCount() - start > 15000) {
            TerminateProcess(pi.hProcess, 1);
            break;
        }
        Sleep(10);
    }
    CloseHandle(rp);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return out;
}

bool Derivative(const std::wstring& path)
{
    const wchar_t* fn = PathFindFileNameW(path.c_str());
    std::wstring f = fn;
    if (f.size() < 5 || _wcsicmp(f.c_str() + f.size() - 4, L".mp4") != 0)
        return false;
    size_t end = f.size() - 4, i = end;
    while (i > 0 && f[i - 1] >= L'0' && f[i - 1] <= L'9') --i;
    if (i == end || i < 6) return false;
    const wchar_t* w = f.c_str() + i - 6;
    return _wcsnicmp(w, L"_clip_", 6) == 0 ||
        _wcsnicmp(w, L"_trim_", 6) == 0 ||
        _wcsnicmp(w, L"_edit_", 6) == 0;
}

double ProbeDur(const std::wstring& path)
{
    std::wstring probe = ToolDir() + L"\\" + pname;
    if (!FileExists(probe)) return 0;
    std::wstring cmd = L"\"" + probe +
        L"\" -v quiet -show_entries format=duration -of csv=p=0 \"" + path + L"\"";
    std::string out = RunCapture(cmd);
    char* end = nullptr;
    double dur = std::strtod(out.c_str(), &end);
    return end != out.c_str() && dur > 0 ? dur : 0;
}

std::vector<std::wstring> GetSegs(double secs)
{
    struct item { std::wstring path; FILETIME time; };
    std::vector<item> all;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((BufDir() + L"\\seg*.ts").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return {};
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            all.push_back({ BufDir() + L"\\" + fd.cFileName, fd.ftLastWriteTime });
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(all.begin(), all.end(), [](const item& a, const item& b) {
        return CompareFileTime(&a.time, &b.time) < 0;
    });
    size_t need = (size_t)(secs / segsec) + 2;
    if (all.size() < 2) return {};
    all.pop_back();
    if (all.size() > need) all.erase(all.begin(), all.end() - need);
    std::vector<std::wstring> out;
    for (auto& it : all) out.push_back(it.path);
    return out;
}

void ClearSegs()
{
    WIN32_FIND_DATAW fd{};
    std::wstring dir = BufDir();
    HANDLE h = FindFirstFileW((dir + L"\\seg*.ts").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            DeleteFileW((dir + L"\\" + fd.cFileName).c_str());
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

std::wstring UniName(const std::wstring& base, const wchar_t* ext)
{
    static std::atomic<unsigned> seq{ 0 };
    return base + L"." + std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(GetCurrentThreadId()) + L"." +
        std::to_wstring(seq.fetch_add(1)) + ext;
}

bool WriteList(const std::wstring& path, const std::vector<std::wstring>& segs)
{
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"w, ccs=UTF-8") || !f) return false;
    for (auto s : segs) {
        std::replace(s.begin(), s.end(), L'\\', L'/');
        size_t p = 0;
        while ((p = s.find(L'\'', p)) != std::wstring::npos) {
            s.replace(p, 1, L"'\\''");
            p += 4;
        }
        fwprintf(f, L"file '%ls'\n", s.c_str());
    }
    return fclose(f) == 0;
}

std::wstring Encoder(Vendor v, bool cap)
{
    switch (v) {
    case Vendor::nvidia:
        return L"-c:v h264_nvenc -preset llhp -profile:v high -rc cbr -b:v 33M -maxrate 33M" +
            std::wstring(cap ? L" -bufsize 66M" : L"");
    case Vendor::amd:
        return L"-c:v h264_amf -usage ultralowlatency -quality speed "
            L"-profile high -rc cbr -b:v 33M -maxrate 33M -async_depth 4 -preanalysis false";
    case Vendor::intel:
        return L"-c:v h264_qsv -preset veryfast -profile:v high -b:v 33M";
    default:
        return L"-c:v libx264 -preset ultrafast -tune zerolatency -profile:v high -b:v 33M";
    }
}

bool Replace(const std::wstring& dest, double dur,
             const std::vector<std::wstring>& segs, Vendor v)
{
    if (segs.empty() || dur <= 0) return false;
    std::wstring ff = ToolDir() + L"\\" + ffname;
    if (!FileExists(ff)) return false;
    std::wstring tmp = UniName(dest, L".tmp.mp4");
    std::wstring list = UniName(TempDir() + L"amf_concat", L".txt");
    if (!WriteList(list, segs)) return false;
    double avail = (double)segs.size() * segsec;
    double start = (std::max)(0.0, avail - dur);
    std::wstring cmd = L"\"" + ff + L"\" -y -hide_banner -loglevel error"
        L" -f concat -safe 0 -i \"" + list + L"\""
        L" -ss " + std::to_wstring(start) + L" -t " + std::to_wstring(dur) +
        L" " + Encoder(v, false) +
        L" -c:a aac -b:a 192k -movflags +faststart \"" + tmp + L"\"";
    int ec = RunWait(cmd, 120000);
    DeleteFileW(list.c_str());
    if (ec != 0 || !FileExists(tmp)) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    FILETIME created{}, written{};
    HANDLE h = CreateFileW(dest.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    bool times = GetFileTime(h, &created, nullptr, &written) != FALSE;
    CloseHandle(h);
    bool moved = false;
    for (int i = 0; i < 50 && g_run.load(); ++i) {
        if (MoveFileExW(tmp.c_str(), dest.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            moved = true;
            break;
        }
        Sleep(200);
    }
    if (!moved) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    if (times) {
        h = CreateFileW(dest.c_str(), FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            SetFileTime(h, &created, nullptr, &written);
            CloseHandle(h);
        }
    }
    return true;
}

bool HttpsDownload(const std::wstring& host, const std::wstring& path,
                   const std::wstring& out)
{
    HINTERNET ses = WinHttpOpen(L"streamproof/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return false;
    WinHttpSetTimeouts(ses, 30000, 30000, 30000, 30000);
    HINTERNET con = WinHttpConnect(ses, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET req = con ? WinHttpOpenRequest(con, L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    bool ok = req && WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(req, nullptr);
    DWORD status = 0, size = sizeof(status);
    if (ok) ok = WinHttpQueryHeaders(req,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) && status == 200;
    HANDLE fh = ok ? CreateFileW(out.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr) : INVALID_HANDLE_VALUE;
    ok = fh != INVALID_HANDLE_VALUE;
    long long total = 0, gotall = 0;
    wchar_t len[64]{};
    size = sizeof(len);
    if (ok && WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_LENGTH,
        WINHTTP_HEADER_NAME_BY_INDEX, len, &size, WINHTTP_NO_HEADER_INDEX))
        total = _wtoi64(len);
    std::vector<char> buf(64 * 1024);
    DWORD last = GetTickCount();
    while (ok) {
        DWORD avail = 0, got = 0, written = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) ok = false;
        else if (!avail) break;
        else if (!WinHttpReadData(req, buf.data(), (std::min)(avail, (DWORD)buf.size()), &got) ||
            !got || !WriteFile(fh, buf.data(), got, &written, nullptr) || written != got) ok = false;
        gotall += got;
        DWORD now = GetTickCount();
        if (ok && now - last >= 250) {
            last = now;
            char msg[64];
            if (total > 0) sprintf_s(msg, "download %d%%", (int)(gotall * 100 / total));
            else sprintf_s(msg, "download %lld mb", gotall / (1024 * 1024));
            SetStat(msg);
        }
    }
    if (fh != INVALID_HANDLE_VALUE) {
        ok = FlushFileBuffers(fh) && ok;
        CloseHandle(fh);
    }
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    if (!ok || !gotall) DeleteFileW(out.c_str());
    return ok && gotall;
}

void RmDir(const std::wstring& dir)
{
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.' && (fd.cFileName[1] == 0 ||
            (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0))) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) RmDir(full);
        else {
            SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(full.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    RemoveDirectoryW(dir.c_str());
}

void Collect(const std::wstring& dir, const std::wstring& bin)
{
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.' && (fd.cFileName[1] == 0 ||
            (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0))) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) Collect(full, bin);
            continue;
        }
        const wchar_t* name = nullptr;
        if (_wcsicmp(fd.cFileName, L"ffmpeg.exe") == 0) name = ffname;
        else if (_wcsicmp(fd.cFileName, L"ffprobe.exe") == 0) name = pname;
        if (name) MoveFileExW(full.c_str(), (bin + L"\\" + name).c_str(), MOVEFILE_REPLACE_EXISTING);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

bool EnsureTools()
{
    std::wstring bin = ToolDir();
    if (!MkDir(bin)) return false;
    std::wstring ff = bin + L"\\" + ffname;
    std::wstring fp = bin + L"\\" + pname;
    if (FileExists(ff) && FileExists(fp)) return true;
    SetStat("download");
    std::wstring zip = UniName(TempDir() + L"amf_dl", L".zip");
    std::wstring ext = UniName(TempDir() + L"amf_extract", L"");
    if (!HttpsDownload(L"www.gyan.dev", L"/ffmpeg/builds/ffmpeg-release-essentials.zip", zip)) {
        SetStat("download failed");
        return false;
    }
    SetStat("extract");
    if (!MkDir(ext) || RunWait(L"tar.exe -xf \"" + zip + L"\" -C \"" + ext + L"\"", 120000) != 0) {
        DeleteFileW(zip.c_str());
        RmDir(ext);
        SetStat("extract failed");
        return false;
    }
    DeleteFileW(zip.c_str());
    Collect(ext, bin);
    RmDir(ext);
    if (!FileExists(ff) || !FileExists(fp)) {
        SetStat("install failed");
        return false;
    }
    return true;
}

bool Ready(const std::wstring& path)
{
    unsigned long long last = 0;
    for (int i = 0; i < 120 && g_run.load(); ++i) {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size{};
            bool ok = GetFileSizeEx(h, &size) && size.QuadPart > 0;
            CloseHandle(h);
            if (ok && (unsigned long long)size.QuadPart == last && ProbeDur(path) > 0)
                return true;
            if (ok) last = size.QuadPart;
        }
        Sleep(500);
    }
    return false;
}

void ProcessClip(std::wstring path)
{
    if (Derivative(path) || !Ready(path)) return;
    const wchar_t* fn = PathFindFileNameW(path.c_str());
    if (_wcsnicmp(fn, L"Replay_", 7) == 0) {
        g_tick.store(GetTickCount());
        return;
    }
    double dur = ProbeDur(path);
    if (dur < 1) return;
    double need = dur;
    DWORD tick = g_tick.exchange(0);
    if (g_vendor == Vendor::amd && tick) need += (GetTickCount() - tick) / 1000.0;
    auto segs = GetSegs(need + segsec);
    if (!Replace(path, dur, segs, g_vendor)) {
        std::lock_guard<std::mutex> lock(g_workmtx);
        g_done.erase(path);
    }
}

void WorkThread()
{
    for (;;) {
        std::unique_lock<std::mutex> lock(g_workmtx);
        g_workcv.wait(lock, [] { return !g_run.load() || !g_queue.empty(); });
        if (!g_run.load()) return;
        std::wstring path = g_queue.front();
        g_queue.pop_front();
        lock.unlock();
        ProcessClip(std::move(path));
    }
}

void QueueClip(const std::wstring& path)
{
    {
        std::lock_guard<std::mutex> lock(g_workmtx);
        if (!g_run.load() || g_done.count(path)) return;
        g_done.insert(path);
        g_queue.push_back(path);
    }
    g_workcv.notify_one();
}

void WatchDir(std::wstring dir, HANDLE stop)
{
    if (dir.empty() || !MkDir(dir)) return;
    HANDLE dh = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (dh == INVALID_HANDLE_VALUE) return;
    alignas(DWORD) char buf[16384]{};
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        CloseHandle(dh);
        return;
    }
    auto issue = [&] {
        ResetEvent(ov.hEvent);
        return ReadDirectoryChangesW(dh, buf, sizeof(buf), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            nullptr, &ov, nullptr) || GetLastError() == ERROR_IO_PENDING;
    };
    HANDLE waits[2] = { ov.hEvent, stop };
    while (issue() && WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
        DWORD n = 0;
        if (!GetOverlappedResult(dh, &ov, &n, FALSE) || !n) continue;
        const char* p = buf;
        for (;;) {
            auto* info = (const FILE_NOTIFY_INFORMATION*)p;
            if (info->Action == FILE_ACTION_ADDED || info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                std::wstring fn(info->FileName, info->FileNameLength / sizeof(wchar_t));
                if (fn.size() >= 4 && _wcsicmp(fn.c_str() + fn.size() - 4, L".mp4") == 0)
                    QueueClip(dir + L"\\" + fn);
            }
            if (!info->NextEntryOffset) break;
            p += info->NextEntryOffset;
        }
    }
    CancelIoEx(dh, &ov);
    CloseHandle(ov.hEvent);
    CloseHandle(dh);
}

std::wstring CaptureCmd(Vendor v)
{
    int fps = v == Vendor::nvidia ? 120 : 60;
    return L"\"" + ToolDir() + L"\\" + ffname + L"\""
        L" -y -hide_banner -loglevel error"
        L" -init_hw_device d3d11va=d3d:0 -filter_hw_device d3d"
        L" -f lavfi -i \"ddagrab=output_idx=0:framerate=" + std::to_wstring(fps) + L"\""
        L" -vf \"hwdownload,format=nv12,hwupload\" " + Encoder(v, true) +
        L" -f segment -segment_time " + std::to_wstring(segsec) +
        L" -segment_wrap " + std::to_wstring(ringcap) +
        L" -reset_timestamps 1 \"" + BufDir() + L"\\seg%05d.ts\"";
}

void CaptureThread()
{
    while (g_run.load()) {
        HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (nul == INVALID_HANDLE_VALUE) break;
        PROCESS_INFORMATION pi{};
        if (!Spawn(CaptureCmd(g_vendor), nul, nul, &pi)) {
            CloseHandle(nul);
            break;
        }
        CloseHandle(nul);
        {
            std::lock_guard<std::mutex> lock(g_procmtx);
            g_proc = pi.hProcess;
            if (!g_run.load()) TerminateProcess(g_proc, 0);
        }
        HANDLE job = CreateJobObjectW(nullptr, nullptr);
        if (job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info)) ||
                !AssignProcessToJobObject(job, pi.hProcess)) {
                CloseHandle(job);
                job = nullptr;
            }
        }
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        {
            std::lock_guard<std::mutex> lock(g_procmtx);
            if (g_proc == pi.hProcess) g_proc = nullptr;
        }
        CloseHandle(pi.hProcess);
        if (job) CloseHandle(job);
        if (g_run.load() && WaitForSingleObject(g_stop, 1000) == WAIT_TIMEOUT)
            SetStat("restarting capture");
    }
    if (g_run.load()) SetStat("capture failed");
}

}

namespace StreamProof {

void SetOverlayWindow(void* hwnd) { g_hwnd = (HWND)hwnd; }

void Enable()
{
    if (g_run.exchange(true)) return;
    SetStat("starting");
    if (g_hwnd && !SetWindowDisplayAffinity(g_hwnd, WDA_EXCLUDEFROMCAPTURE)) {
        SetStat("display affinity failed");
        g_run = false;
        return;
    }
    g_vendor = GetVendor();
    if (!MkDir(ToolDir()) || !MkDir(BufDir()) || !EnsureTools()) {
        if (g_stat != "download failed" && g_stat != "extract failed" && g_stat != "install failed")
            SetStat("setup failed");
        if (g_hwnd) SetWindowDisplayAffinity(g_hwnd, WDA_NONE);
        g_run = false;
        return;
    }
    ClearSegs();
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop) {
        SetStat("setup failed");
        if (g_hwnd) SetWindowDisplayAffinity(g_hwnd, WDA_NONE);
        g_run = false;
        return;
    }
    g_worker = std::thread(WorkThread);
    g_cap = std::thread(CaptureThread);
    std::wstring videos = VideosDir();
    if (!videos.empty()) g_watch.emplace_back(WatchDir, videos, g_stop);
    if (g_vendor == Vendor::amd && !DownloadsDir().empty())
        g_watch.emplace_back(WatchDir, DownloadsDir() + L"\\unknown", g_stop);
    SetStat("active");
}

void Disable()
{
    if (!g_run.exchange(false)) return;
    SetStat("stopping");
    if (g_stop) SetEvent(g_stop);
    g_workcv.notify_all();
    {
        std::lock_guard<std::mutex> lock(g_procmtx);
        if (g_proc) TerminateProcess(g_proc, 0);
    }
    for (auto& t : g_watch) if (t.joinable()) t.join();
    g_watch.clear();
    if (g_worker.joinable()) g_worker.join();
    if (g_cap.joinable()) g_cap.join();
    if (g_stop) {
        CloseHandle(g_stop);
        g_stop = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(g_workmtx);
        g_queue.clear();
        g_done.clear();
    }
    g_tick = 0;
    ClearSegs();
    if (g_hwnd && IsWindow(g_hwnd)) SetWindowDisplayAffinity(g_hwnd, WDA_NONE);
    SetStat("disabled");
}

void Shutdown() { Disable(); }

std::string GetStatus()
{
    std::lock_guard<std::mutex> lock(g_statmtx);
    return g_stat;
}

}
