"""剪映进程只读内存探针：模块枚举 + 内存读取 + 特征串扫描（不注入、不写）。"""
import ctypes, ctypes.wintypes as w, struct, sys

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD), ("th32ProcessID", w.DWORD),
                ("GlblcntUsage", w.DWORD), ("ProccntUsage", w.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", w.DWORD), ("hModule", w.HMODULE), ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260)]

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

def modules(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == -1 or snap is None:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    me = MODULEENTRY32W(); me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    out = []
    ok = k32.Module32FirstW(snap, ctypes.byref(me))
    while ok:
        base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
        out.append((me.szModule, base, me.modBaseSize, me.szExePath))
        ok = k32.Module32NextW(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return out

def open_proc(pid, write=False):
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    if write:
        access |= 0x0020 | 0x0008  # PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    h = k32.OpenProcess(access, False, pid)
    if not h:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    return h

def read(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
        raise OSError(ctypes.get_last_error(), f"ReadProcessMemory 0x{addr:x}")
    return buf.raw[:n.value]

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", w.DWORD), ("__alignment1", w.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", w.DWORD), ("Protect", w.DWORD),
                ("Type", w.DWORD), ("__alignment2", w.DWORD)]

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

def regions(h):
    addr = 0x10000
    mbi = MEMORY_BASIC_INFORMATION64()
    while addr < 0x7FFFFFFF0000:
        r = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not r:
            break
        size = mbi.RegionSize
        if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS:
            yield mbi.BaseAddress, size, mbi.Protect, mbi.Type
        addr = mbi.BaseAddress + size
        if size == 0:
            addr += 0x1000

if __name__ == "__main__":
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    if not pid:
        print("usage: jy_mem.py <pid>"); sys.exit(1)
    h = open_proc(pid)
    mods = modules(pid)
    print(f"modules={len(mods)}")
    for n, b, s, p in mods:
        if any(k in n.lower() for k in ("videoeditor", "vecreator", "cccrator", "gp", "vm_sdk", "lynx")):
            print(f"  {n:28s} base=0x{b:012x} size={s/1048576:8.1f}M")
    print("regions:", sum(1 for _ in regions(h)))
    k32.CloseHandle(h)
