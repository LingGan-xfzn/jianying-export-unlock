"""剪映导出限制解除器 —— 纯外部进程工具。

不注入、不修改客户端文件、不联网。只做三件事：
  1. 找到 JianyingPro.exe 主进程
  2. 扫出 ExportVipRightsViewModel 实例
  3. 把 +0x18 处的拦截标志清零

用法：双击运行，在剪映打开"导出"面板后点【解除限制】，
然后正常点剪映里的导出按钮即可。
"""
import ctypes
import ctypes.wintypes as w
import io
import os
import queue
import re
import struct
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk

# ---------- 静态分析得到的常量（VECreator.dll） ----------
# ExportVipRightsViewModel 虚表偏移，多版本兼容（新 -> 旧）
#   11.8.0.14778 : 0xE8BBED0
#   11.7.0.14652 : 0xE0A19A0
#   11.6.0.14552 : 0xD3485C0
VTABLE_CANDIDATES = (0xE8BBED0, 0xE0A19A0, 0xD3485C0)
VIP_BLOCK_OFFSET = 0x18
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD), ("th32ProcessID", w.DWORD),
                ("GlblcntUsage", w.DWORD), ("ProccntUsage", w.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)), ("modBaseSize", w.DWORD),
                ("hModule", w.HMODULE), ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260)]


class MBI64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", w.DWORD), ("__a1", w.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", w.DWORD), ("Protect", w.DWORD),
                ("Type", w.DWORD), ("__a2", w.DWORD)]


def find_candidates():
    """返回所有 JianyingPro.exe 进程 [(内存KB, PID)]，按内存降序。

    剪映是多进程架构（主进程 + CEF 渲染/GPU 子进程同名），
    不能只看内存大小，必须逐个验证是否加载了 VECreator.dll。
    """
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq JianyingPro.exe", "/FO", "CSV"],
                             capture_output=True, text=True, encoding="gbk",
                             errors="ignore", creationflags=0x08000000).stdout
    except Exception:
        return []
    rows = []
    for line in out.strip().split("\n")[1:]:
        p = line.split('","')
        if len(p) > 4:
            try:
                pid = int(re.sub(r"[^0-9]", "", p[1]))
                mem = int(re.sub(r"[^0-9]", "", p[4]))
            except Exception:
                continue
            rows.append((mem, pid))
    rows.sort(reverse=True)
    return rows


def module_base(pid, name):
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)
    if snap in (-1, None):
        return None
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    base = None
    ok = k32.Module32FirstW(snap, ctypes.byref(me))
    while ok:
        if me.szModule.lower() == name.lower():
            base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
            break
        ok = k32.Module32NextW(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return base


def enum_regions(h):
    addr = 0x10000
    mbi = MBI64()
    while addr < 0x7FFFFFFF0000:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize
        if mbi.State == 0x1000 and not (mbi.Protect & 0x100) and mbi.Protect != 0x01:
            yield mbi.BaseAddress, size
        addr = mbi.BaseAddress + size
        if size == 0:
            addr += 0x1000


def read_mem(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
        raise OSError(ctypes.get_last_error(), "read")
    return buf.raw[:n.value]


def write_mem(h, addr, data):
    buf = ctypes.create_string_buffer(data, len(data))
    n = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(n)))


def scan_instances(h, vtable_vas, limit=8, progress=None):
    """扫描堆，找首 qword 等于任一候选虚表的对象。

    vtable_vas 可以是单个整数或整数序列：一次扫描同时匹配多个版本，
    不必为兼容不同剪映版本重复扫内存。progress(0..1) 用于进度条。
    """
    if isinstance(vtable_vas, int):
        vtable_vas = (vtable_vas,)
    needles = [struct.pack("<Q", vt) for vt in vtable_vas]
    regions_list = list(enum_regions(h))
    total = sum(s for _, s in regions_list) or 1
    done = 0
    last_pct = -1
    hits = []
    for base, size in regions_list:
        off = 0
        while off < size:
            chunk = min(4 * 1024 * 1024, size - off)
            try:
                data = read_mem(h, base + off, chunk)
            except OSError:
                off += chunk
                continue
            for needle in needles:
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
        done += size
        if progress:
            pct = int(done * 100 / total)
            if pct != last_pct:
                last_pct = pct
                progress(done / total)
    return hits


def unlock(log, progress=None):
    """执行一次解除。log(str) 输出消息，progress(0..1) 更新进度。"""
    def stage(p, msg=None):
        if progress:
            progress(p)
        if msg:
            log(msg)

    stage(0.02, "查找剪映进程…")
    cands = find_candidates()
    if not cands:
        log("未找到 JianyingPro.exe，请先启动剪映。")
        return False
    stage(0.06, f"发现 {len(cands)} 个剪映进程，正在定位主进程…")

    targets = []
    for mem, cand_pid in cands:
        vb = module_base(cand_pid, "VECreator.dll")
        if vb:
            targets.append((cand_pid, vb))
    if not targets:
        log("没有找到加载了 VECreator.dll 的剪映进程。")
        log("请先在剪映里打开【导出】面板，再点本按钮。")
        return False

    stage(0.08, f"{len(targets)} 个进程加载了核心模块，开始定位…")
    vt = None
    hits = []
    used_pid = None
    h = None
    span = 0.82 / len(targets)
    for idx, (pid, vbase) in enumerate(targets):
        lo = 0.10 + idx * span
        hh = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                             PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
        if not hh:
            continue
        stage(lo, f"PID {pid}  VECreator 基址 0x{vbase:x}")
        vts = [vbase + r for r in VTABLE_CANDIDATES]
        hits = scan_instances(hh, vts, progress=lambda p, l=lo, s=span: stage(l + p * s))
        if hits:
            h, used_pid = hh, pid
            break
        k32.CloseHandle(hh)

    if not hits or not h:
        stage(0.94, "未找到权益模型实例。请在剪映里打开【导出】面板后再点本按钮。")
        return False

    try:
        stage(0.94, f"PID {used_pid} 上找到 {len(hits)} 个权益模型实例")
        changed = 0
        for a in hits:
            target = a + VIP_BLOCK_OFFSET
            try:
                before = read_mem(h, target, 8)
            except OSError:
                continue
            if before == b"\x00" * 8:
                log(f"  0x{a:x} 已是解除状态，跳过")
                continue
            if write_mem(h, target, b"\x00" * 8):
                after = read_mem(h, target, 8)
                log(f"  0x{a:x}  {before.hex()} -> {after.hex()}")
                changed += 1
            else:
                log(f"  0x{a:x} 写入失败（错误码 {ctypes.get_last_error()}）")
        stage(1.0)
        if changed:
            log("")
            log("✔ 已解除。现在回到剪映，点导出按钮即可。")
            return True
        log("")
        log("没有需要修改的实例，当前已是解除状态。")
        return False
    finally:
        k32.CloseHandle(h)


def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


class App:
    def __init__(self, root):
        self.root = root
        self.busy = False
        self.q = None
        root.title("剪映导出限制解除器")
        root.geometry("580x470")
        root.resizable(False, False)
        try:
            root.iconbitmap(default=resource_path("app.ico"))
        except Exception:
            pass

        frm = ttk.Frame(root, padding=14)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="剪映导出限制解除器",
                  font=("Microsoft YaHei UI", 14, "bold")).pack(anchor="w")

        ttk.Label(frm, text="用途：让已在时间线使用的会员功能（如人声&背景音分离）不再拦截导出。\n"
                            "不修改客户端文件、不注入、不联网，只改运行时的一个拦截标志。",
                  font=("Microsoft YaHei UI", 9), foreground="#666").pack(anchor="w", pady=(4, 10))

        self.btn = ttk.Button(frm, text="解除限制", command=self.on_click)
        self.btn.pack(fill="x", ipady=8)

        self.bar = ttk.Progressbar(frm, mode="determinate", maximum=100)
        self.bar.pack(fill="x", pady=(10, 2))

        self.status = ttk.Label(frm, text="准备就绪", font=("Microsoft YaHei UI", 9),
                                foreground="#0a7d8c")
        self.status.pack(anchor="w")

        self.txt = tk.Text(frm, height=10, font=("Consolas", 9), bg="#111", fg="#0f0",
                           insertbackground="#0f0", relief="flat", wrap="word")
        self.txt.pack(fill="both", expand=True, pady=(8, 0))
        self.log("请在剪映里打开【导出】面板，然后点上面的按钮。")

    def log(self, msg):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")
        self.txt.update_idletasks()

    def on_click(self):
        if self.busy:
            return
        self.busy = True
        self.btn.config(state="disabled", text="处理中…")
        self.bar["value"] = 0
        self.txt.delete("1.0", "end")
        self.status.config(text="开始执行…")
        self.q = queue.Queue()
        threading.Thread(target=self._worker, daemon=True).start()
        self.root.after(60, self._poll)

    def _worker(self):
        try:
            unlock(lambda m: self.q.put(("log", m)),
                   lambda p: self.q.put(("prog", p)))
        except Exception as e:
            self.q.put(("log", f"异常：{e}"))
        finally:
            self.q.put(("done", None))

    def _poll(self):
        finished = False
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "log":
                    self.log(val)
                    if val.startswith("未找到") or val.startswith("VECreator"):
                        self.status.config(text=val.split("。")[0])
                elif kind == "prog":
                    self.bar["value"] = max(0.0, min(100.0, val * 100))
                    self.status.config(text=f"扫描中… {val * 100:.0f}%")
                elif kind == "done":
                    finished = True
                    break
        except queue.Empty:
            pass
        if finished:
            self.busy = False
            self.btn.config(state="normal", text="解除限制")
            self.bar["value"] = 100
            self.status.config(text="完成")
        else:
            self.root.after(60, self._poll)


def cli_main():
    """命令行模式：执行一次解锁并把结果写入同目录 unlock_log.txt。"""
    logs = []
    try:
        ok = unlock(lambda m: logs.append(str(m)))
    except Exception as e:
        logs.append(f"异常：{e}")
        ok = False
    target = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "unlock_log.txt")
    try:
        with io.open(target, "w", encoding="utf-8") as f:
            f.write("\n".join(logs))
    except Exception:
        pass
    return 0 if ok else 1


if __name__ == "__main__":
    if "--cli" in sys.argv:
        sys.exit(cli_main())
    root = tk.Tk()
    App(root)
    root.mainloop()