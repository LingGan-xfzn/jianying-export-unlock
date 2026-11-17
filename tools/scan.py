"""在剪映进程中扫描 UTF-16 字符串实例（只读）。"""
import ctypes, sys, time
sys.path.insert(0, r"G:\项目\解除剪映限制\tools")
from jy_mem import open_proc, read, regions, k32, MEM_COMMIT

def scan(pid, needles, max_hits=12, label=""):
    h = open_proc(pid)
    hits = {n: [] for n in needles}
    buf_size = 4 * 1024 * 1024
    t0 = time.time(); total = 0
    for base, size, prot, typ in regions(h):
        off = 0
        while off < size:
            chunk = min(buf_size, size - off)
            try:
                data = read(h, base + off, chunk)
            except OSError:
                off += chunk; continue
            total += len(data)
            for n in needles:
                if len(hits[n]) >= max_hits: continue
                start = 0
                while True:
                    i = data.find(n, start)
                    if i < 0: break
                    hits[n].append(base + off + i)
                    start = i + 1
                    if len(hits[n]) >= max_hits: break
            off += chunk
    k32.CloseHandle(h)
    print(f"[{label}] scanned {total/1048576:.0f}MB in {time.time()-t0:.1f}s")
    for n, addrs in hits.items():
        try: name = n.decode('utf-16le')
        except Exception: name = repr(n)
        print(f"\n  {name!r}: {len(addrs)} hit(s)")
        for a in addrs[:max_hits]:
            print(f"    0x{a:x}")
    return hits

if __name__ == "__main__":
    pid = int(sys.argv[1])
    needles = ["会员权益".encode('utf-16le'), "开通会员并导出".encode('utf-16le')]
    scan(pid, needles, label="jyan")
