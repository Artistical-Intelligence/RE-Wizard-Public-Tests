"""Write a loaded Program as a plain ELF with a symbol table.

Used to hand any supported format (PS-X EXE, relocated PSP PRX, NSO, 3DSX, code.bin, ...)
to tools that read ELF, such as Ghidra, with the discovered function names included.
"""
from __future__ import annotations

import struct
from pathlib import Path

from .model import Program

_MACHINE = {"mips": 8, "arm": 40, "arm64": 183, "ppc64": 21, "ppc": 20, "x86": 3, "x86-64": 62, "sh": 42}


def write_elf(prog: Program, path: Path, functions: dict | None = None) -> Path:
    machine = _MACHINE.get(prog.arch)
    if machine is None:
        raise ValueError(f"No ELF machine for {prog.arch}")
    is64 = prog.arch in ("arm64", "ppc64", "x86-64")
    e = ">" if prog.big_endian else "<"
    flags = {"r5900": 0x00920000, "allegrex": 0x00A20000}.get(prog.variant, 0) if machine == 8 else 0
    if machine == 40:
        flags = 0x05000000            # EABI5
    segs = [s for s in prog.segments if s.size]
    # symbols: (name, value, size, type, binding). ARM EABI: a Thumb function's value has bit 0
    # set, and local mapping symbols $a/$t mark where ARM and Thumb code start. Locals first.
    syms = []
    mapping = []
    for addr, f in sorted((functions or {}).items()):
        mode = getattr(f, "mode", "")
        thumb = machine == 40 and mode == "thumb"
        syms.append((f.name, addr | 1 if thumb else addr, max(f.size, 0), 2, 1))
        if machine == 40 and mode:
            mapping.append(("$t" if thumb else "$a", addr, 0, 0, 0))
    for s in prog.symbols.values():
        if not functions or s.addr not in functions:
            syms.append((s.name, s.addr, s.size, 2 if s.kind in ("function", "export") else 1, 1))
    syms = mapping + syms
    strtab = bytearray(b"\0")
    names = []
    for name, *_rest in syms:
        names.append(len(strtab))
        strtab += name.encode("latin-1", "replace")[:500] + b"\0"
    shstr = bytearray(b"\0")
    sec_names = []
    for k, s in enumerate(segs):
        sec_names.append(len(shstr))
        shstr += (f".text{k}" if s.executable else f".data{k}").encode() + b"\0"
    symtab_name = len(shstr)
    shstr += b".symtab\0"
    strtab_name = len(shstr)
    shstr += b".strtab\0"
    shstrtab_name = len(shstr)
    shstr += b".shstrtab\0"

    ehsize, phsize, shsize, symsize = (64, 56, 64, 24) if is64 else (52, 32, 40, 16)
    pos = ehsize + phsize * len(segs)
    blobs = []
    for s in segs:
        pos = (pos + 15) & ~15
        blobs.append(pos)
        pos += len(s.data)
    sym_off = (pos + 7) & ~7
    symbytes = bytearray(symsize)   # null symbol
    for (name, addr, size, kind, bind), name_i in zip(syms, names):
        shndx = next((k + 1 for k, s in enumerate(segs) if s.contains(addr & ~1 if machine == 40 else addr)), 0xFFF1)
        info = (bind << 4) | kind     # LOCAL mapping symbols, GLOBAL names
        if is64:
            symbytes += struct.pack(e + "IBBHQQ", name_i, info, 0, shndx, addr, size)
        else:
            symbytes += struct.pack(e + "IIIBBH", name_i, addr, size, info, 0, shndx)
    str_off = sym_off + len(symbytes)
    shstr_off = str_off + len(strtab)
    shoff = (shstr_off + len(shstr) + 7) & ~7
    nsec = 1 + len(segs) + 3
    out = bytearray(shoff + shsize * nsec)
    out[:16] = b"\x7fELF" + bytes((2 if is64 else 1, 2 if prog.big_endian else 1, 1)) + bytes(9)
    entry = prog.entry or 0
    if is64:
        struct.pack_into(e + "HHIQQQIHHHHHH", out, 16, 2, machine, 1, entry, ehsize, shoff, flags, ehsize,
                         phsize, len(segs), shsize, nsec, nsec - 1)
    else:
        struct.pack_into(e + "HHIIIIIHHHHHH", out, 16, 2, machine, 1, entry & 0xFFFFFFFF, ehsize, shoff, flags,
                         ehsize, phsize, len(segs), shsize, nsec, nsec - 1)
    for k, (s, off) in enumerate(zip(segs, blobs)):
        pflags = 4 | (1 if s.executable else 0) | (2 if s.writable else 0)
        if is64:
            struct.pack_into(e + "IIQQQQQQ", out, ehsize + k * phsize, 1, pflags, off, s.vaddr, s.vaddr,
                             len(s.data), s.size, 16)
        else:
            struct.pack_into(e + "IIIIIIII", out, ehsize + k * phsize, 1, off, s.vaddr, s.vaddr, len(s.data),
                             s.size, pflags, 16)
        out[off:off + len(s.data)] = s.data
    out[sym_off:sym_off + len(symbytes)] = symbytes
    out[str_off:str_off + len(strtab)] = strtab
    out[shstr_off:shstr_off + len(shstr)] = shstr

    def section(index, name, kind, sflags, addr, offset, size, link=0, info=0, align=4, entsize=0):
        at = shoff + index * shsize
        if is64:
            struct.pack_into(e + "IIQQQQIIQQ", out, at, name, kind, sflags, addr, offset, size, link, info, align, entsize)
        else:
            struct.pack_into(e + "IIIIIIIIII", out, at, name, kind, sflags, addr, offset, size, link, info, align, entsize)

    for k, (s, off) in enumerate(zip(segs, blobs)):
        sflags = 2 | (4 if s.executable else 0) | (1 if s.writable else 0)
        section(k + 1, sec_names[k], 1, sflags, s.vaddr, off, len(s.data), align=16)
    base = 1 + len(segs)
    section(base, symtab_name, 2, 0, 0, sym_off, len(symbytes), link=base + 1, info=1 + len(mapping), align=8,
            entsize=symsize)
    section(base + 1, strtab_name, 3, 0, 0, str_off, len(strtab), align=1)
    section(base + 2, shstrtab_name, 3, 0, 0, shstr_off, len(shstr), align=1)
    path = Path(path)
    path.write_bytes(bytes(out))
    return path
