"""剪映内存快照/差分工具（只读）。

用途：在两种业务状态下各拍一次快照，对比出"权益状态"落在哪个地址。
全部操作只读，不注入、不改目标。
"""
import ctypes, sys, os, struct, hashlib, json, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jy_mem import open_proc, read, regions, k32

CHUNK = 4096
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000


def snapshot(pid, out_path, include_image=False, min_size=4096):
    h = open_proc(pid)
    parts = []
    total = 0
    for base, size, prot, typ in regions(h):
        # 只取私有堆/匿名映射，跳过模块映像（代码与只读数据不随业务状态变化）
        if not include_image and typ == MEM_MAPPED:
            continue
        if size < min_size:
            continue
        off = 0
        while off < size:
            n = min(CHUNK, size - off)
            try:
                data = read(h, base + off, n)
            except OSError:
                off += n
                continue
            if len(data) == CHUNK:
                digest = hashlib.blake2b(data, digest_size=8).digest()
                parts.append((base + off, digest, data))
            off += n
            total += n
    k32.CloseHandle(h)
    with open(out_path, "wb") as f:
        f.write(struct.pack("<I", len(parts)))
        for addr, digest, data in parts:
            f.write(struct.pack("<Q", addr))
            f.write(digest)
            f.write(data)
    print(f"snapshot: {len(parts)} chunks, {total/1048576:.0f}MB -> {out_path}")
    return len(parts)


def load(path):
    with open(path, "rb") as f:
        n = struct.unpack("<I", f.read(4))[0]
        for _ in range(n):
            addr = struct.unpack("<Q", f.read(8))[0]
            digest = f.read(8)
            data = f.read(CHUNK)
            yield addr, digest, data


def diff(path_a, path_b, out_path, max_report=400):
    a = {addr: (d, data) for addr, d, data in load(path_a)}
    b = {addr: (d, data) for addr, d, data in load(path_b)}
    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    changed = []
    for addr in sorted(set(a) & set(b)):
        if a[addr][0] != b[addr][0]:
            changed.append(addr)
    lines = []
    lines.append(f"chunks: a={len(a)} b={len(b)}")
    lines.append(f"only_in_a={len(only_a)} only_in_b={len(only_b)} changed={len(changed)}")
    lines.append("")
    lines.append("== changed chunks ==")
    for addr in changed[:max_report]:
        da, db = a[addr][1], b[addr][1]
        deltas = []
        for i in range(0, CHUNK - 4 + 1, 4):
            va = struct.unpack("<I", da[i:i + 4])[0]
            vb = struct.unpack("<I", db[i:i + 4])[0]
            if va != vb and (va in (0, 1, 2, 3) or vb in (0, 1, 2, 3)):
                deltas.append((i, va, vb))
        if deltas:
            lines.append(f"0x{addr:x}: " + ", ".join(f"+{o}:{x}->{y}" for o, x, y in deltas[:8]))
    lines.append("")
    lines.append("== new chunks (b only) ==")
    for addr in only_b[:max_report]:
        lines.append(f"0x{addr:x}")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("\n".join(lines[:20]))
    print(f"... full report -> {out_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["snap", "diff"])
    ap.add_argument("pid", nargs="?", type=int)
    ap.add_argument("a")
    ap.add_argument("b", nargs="?")
    ap.add_argument("--all", action="store_true", help="include file-mapped regions")
    args = ap.parse_args()
    if args.cmd == "snap":
        snapshot(args.pid, args.a, include_image=args.all)
    else:
        diff(args.a, args.b, args.b + ".diff.txt")