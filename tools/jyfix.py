"""剪映导出限制工具（纯外部进程，只读探测 + 定点改写）。

不注入、不加载 DLL、不修改客户端文件。全部通过 ReadProcessMemory /
WriteProcessMemory 完成，符合"外部小工具"形态。

用法：
    python jyfix.py probe            # 定位 ExportHomeBottomViewModel 实例并 dump
    python jyfix.py watch            # 观察实例内存变化
    python jyfix.py patch --off N    # 把指定偏移的 bool 置 0
"""
import ctypes, sys, os, struct, argparse, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jy_mem import open_proc, read, regions, k32

# 静态分析得到（VECreator.dll RVA，见 rtti.txt）
VTABLE_EXPORT_HOME_BOTTOM = 0xC29ADA8
VTABLE_EXPORT_VIP_RIGHTS   = 0xD3485C0
VTABLE_EXPORT_WINDOW       = 0xC290DF0

PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008


def find_pid():
    import subprocess, re
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq JianyingPro.exe", "/FO", "CSV"],
                         capture_output=True, text=True, encoding="gbk", errors="ignore").stdout
    rows = []
    for line in out.strip().split("\n")[1:]:
        parts = line.split('","')
        if len(parts) > 4:
            try:
                pid = int(re.sub(r"[^0-9]", "", parts[1]))
                mem = int(re.sub(r"[^0-9]", "", parts[4]))
                rows.append((mem, pid))
            except Exception:
                pass
    if not rows:
        return None
    rows.sort(reverse=True)
    return rows[0][1]


def module_base(pid, name):
    from jy_mem import modules
    for n, b, s, p in modules(pid):
        if n.lower() == name.lower():
            return b, s
    return None, None


def scan_for_vtable(h, vtable_va, limit=32):
    """在私有堆里找首 qword == vtable 的对象。"""
    hits = []
    for base, size, prot, typ in regions(h):
        off = 0
        while off < size:
            chunk = min(4 * 1024 * 1024, size - off)
            try:
                data = read(h, base + off, chunk)
            except OSError:
                off += chunk
                continue
            needle = struct.pack("<Q", vtable_va)
            s = 0
            while True:
                i = data.find(needle, s)
                if i < 0:
                    break
                if i % 8 == 0:
                    hits.append(base + off + i)
                    if len(hits) >= limit:
                        return hits
                s = i + 1
            off += chunk
    return hits


def dump_object(h, addr, size=512):
    d = read(h, addr, size)
    print(f"\n=== object @ 0x{addr:x} (first {size} bytes) ===")
    for off in range(0, size, 16):
        row = d[off:off + 16]
        if len(row) < 16:
            break
        q1, q2 = struct.unpack("<QQ", row)
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print(f"  +0x{off:03x}: {q1:016x} {q2:016x}  {printable}")
    return d


def probe(pid):
    h = open_proc(pid)
    vbase, vsize = module_base(pid, "VECreator.dll")
    if not vbase:
        print("VECreator.dll not loaded"); k32.CloseHandle(h); return
    print(f"VECreator base=0x{vbase:x} size=0x{vsize:x}")
    for label, rva in [("ExportHomeBottomViewModel", VTABLE_EXPORT_HOME_BOTTOM),
                       ("ExportVipRightsViewModel", VTABLE_EXPORT_VIP_RIGHTS),
                       ("ExportWindowViewModel", VTABLE_EXPORT_WINDOW)]:
        vt = vbase + rva
        hits = scan_for_vtable(h, vt)
        print(f"\n[{label}] vtable=0x{vt:x} -> {len(hits)} instance(s)")
        for a in hits[:6]:
            print(f"   0x{a:x}")
    k32.CloseHandle(h)


def probe_detail(pid):
    h = open_proc(pid)
    vbase, _ = module_base(pid, "VECreator.dll")
    vt = vbase + VTABLE_EXPORT_HOME_BOTTOM
    hits = scan_for_vtable(h, vt)
    print(f"instances: {len(hits)}")
    for a in hits[:4]:
        dump_object(h, a, 384)
    k32.CloseHandle(h)


def patch(pid, offset, value=0, which=0):
    """把第 which 个 ExportHomeBottomViewModel 实例 +offset 处的字节写成 value。"""
    h = open_proc(pid)
    vbase, _ = module_base(pid, "VECreator.dll")
    vt = vbase + VTABLE_EXPORT_HOME_BOTTOM
    hits = scan_for_vtable(h, vt)
    if len(hits) <= which:
        print(f"no instance #{which} (found {len(hits)})")
        k32.CloseHandle(h); return
    addr = hits[which] + offset
    old = read(h, addr, 1)[0]
    buf = ctypes.create_string_buffer(bytes([value]), 1)
    n = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, 1, ctypes.byref(n))
    new = read(h, addr, 1)[0] if ok else None
    print(f"instance#{which} @0x{hits[which]:x}  addr=0x{addr:x}  {old} -> {new}  ok={bool(ok)}")
    k32.CloseHandle(h)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["probe", "detail", "patch"])
    ap.add_argument("--pid", type=int)
    ap.add_argument("--off", type=lambda x: int(x, 0))
    ap.add_argument("--val", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--which", type=int, default=0)
    a = ap.parse_args()
    pid = a.pid or find_pid()
    if not pid:
        print("JianyingPro.exe 未运行"); sys.exit(1)
    print(f"pid={pid}")
    if a.cmd == "probe":
        probe(pid)
    elif a.cmd == "detail":
        probe_detail(pid)
    else:
        if a.off is None:
            print("patch 需要 --off"); sys.exit(1)
        patch(pid, a.off, a.val, a.which)