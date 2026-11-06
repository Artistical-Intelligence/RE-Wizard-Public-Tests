"""Common in-memory model for a loaded executable. Nothing here executes code."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Segment:
    name: str
    vaddr: int
    data: bytes                 # initialized bytes (may be shorter than size)
    size: int                   # mapped size; bytes past len(data) are zero-filled
    executable: bool = False
    writable: bool = False
    file_offset: int | None = None

    @property
    def end(self) -> int:
        return self.vaddr + self.size

    def contains(self, addr: int, length: int = 1) -> bool:
        return self.vaddr <= addr and addr + length <= self.end


@dataclass
class Symbol:
    addr: int
    name: str
    kind: str = "function"       # function | object | import | export | label
    size: int = 0
    source: str = ""             # where the name came from (symtab, nid, export, ...)
    library: str = ""


@dataclass
class Program:
    """One executable image mapped at its load addresses."""
    name: str
    platform: str                # psp, ps2, ps1, ps2-iop, 3ds, switch, ps3, ps4, windows, unknown
    arch: str                    # mips, x86, x86-64, arm, arm64, ppc64
    variant: str = ""            # mips variant, or "thumb"/"arm" hints
    big_endian: bool = False
    entry: int | None = None
    segments: list[Segment] = field(default_factory=list)
    symbols: dict[int, Symbol] = field(default_factory=dict)
    imports: list[Symbol] = field(default_factory=list)
    exports: list[Symbol] = field(default_factory=list)
    gp: int | None = None
    notes: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def segment_at(self, addr: int, length: int = 1) -> Segment | None:
        for segment in self.segments:
            if segment.contains(addr, length):
                return segment
        return None

    def read(self, addr: int, length: int) -> bytes | None:
        segment = self.segment_at(addr, length)
        if segment is None:
            return None
        start = addr - segment.vaddr
        chunk = segment.data[start:start + length]
        if len(chunk) < length:
            chunk = chunk + bytes(length - len(chunk))
        return bytes(chunk)

    def read_u32(self, addr: int) -> int | None:
        raw = self.read(addr, 4)
        if raw is None:
            return None
        return int.from_bytes(raw, "big" if self.big_endian else "little")

    def read_cstring(self, addr: int, limit: int = 256) -> str | None:
        segment = self.segment_at(addr)
        if segment is None:
            return None
        start = addr - segment.vaddr
        raw = segment.data[start:start + limit]
        end = raw.find(b"\0")
        if end < 0:
            return None
        return raw[:end].decode("latin-1")

    def is_code(self, addr: int) -> bool:
        segment = self.segment_at(addr, 4)
        return bool(segment and segment.executable)

    def add_symbol(self, symbol: Symbol, replace: bool = False) -> None:
        existing = self.symbols.get(symbol.addr)
        if existing is None or replace or (existing.name.startswith(("func_", "sub_", "loc_"))
                                           and not symbol.name.startswith(("func_", "sub_"))):
            self.symbols[symbol.addr] = symbol

    def summary(self) -> dict:
        return {
            "name": self.name, "platform": self.platform, "arch": self.arch, "variant": self.variant,
            "big_endian": self.big_endian, "entry": self.entry, "gp": self.gp,
            "segments": [{"name": s.name, "vaddr": s.vaddr, "size": s.size, "file_size": len(s.data),
                          "executable": s.executable, "writable": s.writable,
                          "file_offset": s.file_offset} for s in self.segments],
            "symbols": len(self.symbols), "imports": len(self.imports), "exports": len(self.exports),
            "notes": list(self.notes), "metadata": self.metadata,
        }


class FormatError(ValueError):
    """The input is recognized but cannot be loaded as requested."""


class NeedsDecryption(FormatError):
    """The executable is encrypted/signed; a decrypted dump is required."""
