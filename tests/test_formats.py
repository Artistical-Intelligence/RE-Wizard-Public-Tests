"""Original synthetic tests for the two exported format utilities.

All bytes are invented here. Generated ELF files live only in temporary folders.
The parser below uses the published ELF field layouts, independent of the writer.
"""
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from rewizard.formats.elf_writer import write_elf
from rewizard.formats.model import FormatError, NeedsDecryption, Program, Segment, Symbol


def parse_elf(test, raw):
    """Read and bounds-check ELF metadata without using a project loader."""
    test.assertEqual(raw[:4], b"\x7fELF")
    bits = {1: 32, 2: 64}[raw[4]]
    order = {1: "<", 2: ">"}[raw[5]]
    test.assertEqual(raw[6], 1)
    header_format = order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    fields = struct.unpack_from(header_format, raw, 16)
    keys = ("type", "machine", "version", "entry", "phoff", "shoff", "flags",
            "ehsize", "phentsize", "phnum", "shentsize", "shnum", "shstrndx")
    header = dict(zip(keys, fields))
    test.assertEqual(header["ehsize"], 52 if bits == 32 else 64)
    test.assertEqual(header["phentsize"], 32 if bits == 32 else 56)
    test.assertEqual(header["shentsize"], 40 if bits == 32 else 64)
    test.assertEqual(header["type"], 2)
    test.assertEqual(header["version"], 1)
    test.assertLessEqual(header["phoff"] + header["phnum"] * header["phentsize"], len(raw))
    test.assertEqual(header["shoff"] + header["shnum"] * header["shentsize"], len(raw))

    segments = []
    for index in range(header["phnum"]):
        offset = header["phoff"] + index * header["phentsize"]
        if bits == 32:
            values = struct.unpack_from(order + "IIIIIIII", raw, offset)
            names = ("type", "offset", "vaddr", "paddr", "filesz", "memsz", "flags", "align")
        else:
            values = struct.unpack_from(order + "IIQQQQQQ", raw, offset)
            names = ("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align")
        segment = dict(zip(names, values))
        test.assertEqual(segment["type"], 1)
        test.assertLessEqual(segment["offset"] + segment["filesz"], header["shoff"])
        test.assertLessEqual(segment["filesz"], segment["memsz"])
        test.assertEqual(segment["align"], 16)
        test.assertEqual(segment["offset"] % 16, segment["vaddr"] % 16)
        segment["data"] = raw[segment["offset"]:segment["offset"] + segment["filesz"]]
        segments.append(segment)

    sections = []
    for index in range(header["shnum"]):
        values = struct.unpack_from(order + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"),
                                    raw, header["shoff"] + index * header["shentsize"])
        section = dict(zip(("name_offset", "type", "flags", "addr", "offset", "size",
                            "link", "info", "align", "entsize"), values))
        test.assertLessEqual(section["offset"] + section["size"], len(raw))
        sections.append(section)
    test.assertTrue(all(value == 0 for value in sections[0].values()))
    string_section = sections[header["shstrndx"]]
    strings = raw[string_section["offset"]:string_section["offset"] + string_section["size"]]

    def cstring(table, offset):
        test.assertLess(offset, len(table))
        end = table.find(b"\0", offset)
        test.assertGreaterEqual(end, offset)
        return table[offset:end].decode("latin-1")

    for section in sections:
        section["name"] = cstring(strings, section["name_offset"])
    by_name = {section["name"]: section for section in sections}
    symbol_section = by_name[".symtab"]
    test.assertEqual(symbol_section["type"], 2)
    test.assertEqual(symbol_section["entsize"], 16 if bits == 32 else 24)
    test.assertEqual(symbol_section["size"] % symbol_section["entsize"], 0)
    names_section = sections[symbol_section["link"]]
    test.assertEqual(names_section["name"], ".strtab")
    names = raw[names_section["offset"]:names_section["offset"] + names_section["size"]]
    symbols = []
    for at in range(symbol_section["offset"], symbol_section["offset"] + symbol_section["size"],
                    symbol_section["entsize"]):
        if bits == 32:
            name, value, size, info, other, shndx = struct.unpack_from(order + "IIIBBH", raw, at)
        else:
            name, info, other, shndx, value, size = struct.unpack_from(order + "IBBHQQ", raw, at)
        test.assertEqual(other, 0)
        symbols.append(dict(name=cstring(names, name), value=value, size=size,
                            binding=info >> 4, kind=info & 15, section=shndx))
    test.assertEqual(symbols[0], dict(name="", value=0, size=0, binding=0, kind=0, section=0))
    return header, segments, by_name, symbols


class ProgramTests(unittest.TestCase):
    def test_segment_bounds_and_empty_read(self):
        segment = Segment("sample", 0x1000, b"abcd", 8)
        program = Program("synthetic", "unknown", "mips", segments=[segment])
        self.assertEqual(segment.end, 0x1008)
        self.assertTrue(segment.contains(0x1000, 8))
        self.assertTrue(segment.contains(0x1007))
        self.assertFalse(segment.contains(0x0FFF))
        self.assertFalse(segment.contains(0x1007, 2))
        self.assertEqual(program.read(0x1008, 0), b"")
        self.assertIsNone(program.read(0x1008, 1))
        self.assertIsNone(program.read(0x0FFF, 1))

    def test_virtual_zero_fill_and_unmapped_address(self):
        program = Program("synthetic", "unknown", "mips", segments=[
            Segment("sample", 0x2000, b"abc", 8)])
        self.assertEqual(program.read(0x2001, 6), b"bc\0\0\0\0")
        self.assertEqual(program.read(0x2004, 4), bytes(4))
        self.assertIsNone(program.read(0x2007, 2))
        self.assertIsNone(program.segment_at(0x3000))

    def test_read_does_not_cross_adjacent_segments(self):
        program = Program("synthetic", "unknown", "mips", segments=[
            Segment("left", 0x1000, b"ab", 2), Segment("right", 0x1002, b"cd", 2)])
        self.assertIsNone(program.read(0x1001, 2))
        self.assertEqual(program.read(0x1002, 2), b"cd")

    def test_endian_u32_and_short_mapping(self):
        program = Program("synthetic", "unknown", "mips", segments=[
            Segment("sample", 0x1000, b"\x12\x34\x56\x78", 4)])
        self.assertEqual(program.read_u32(0x1000), 0x78563412)
        program.big_endian = True
        self.assertEqual(program.read_u32(0x1000), 0x12345678)
        self.assertIsNone(program.read_u32(0x1001))

    def test_strings_limits_latin1_and_unbacked_bytes(self):
        program = Program("synthetic", "unknown", "mips", segments=[
            Segment("sample", 0x1000, b"A\xff\0XYZ", 16)])
        self.assertEqual(program.read_cstring(0x1000), "A\xff")
        self.assertEqual(program.read_cstring(0x1002), "")
        self.assertIsNone(program.read_cstring(0x1000, 2))
        self.assertIsNone(program.read_cstring(0x1003))
        self.assertIsNone(program.read_cstring(0x1008))
        self.assertIsNone(program.read_cstring(0x2000))

    def test_is_code_requires_four_mapped_bytes(self):
        program = Program("synthetic", "unknown", "mips", segments=[
            Segment("code", 0x1000, b"abcd", 4, executable=True),
            Segment("data", 0x2000, b"abcd", 4)])
        self.assertTrue(program.is_code(0x1000))
        self.assertFalse(program.is_code(0x1001))
        self.assertFalse(program.is_code(0x2000))
        self.assertFalse(program.is_code(0x3000))

    def test_symbol_replacement_and_summary(self):
        program = Program("synthetic", "unknown", "mips")
        program.add_symbol(Symbol(0x1000, "sub_1000"))
        program.add_symbol(Symbol(0x1000, "invented_name"))
        program.add_symbol(Symbol(0x1000, "sub_other"))
        self.assertEqual(program.symbols[0x1000].name, "invented_name")
        program.add_symbol(Symbol(0x1000, "replacement"), replace=True)
        self.assertEqual(program.symbols[0x1000].name, "replacement")
        program.notes.append("synthetic note")
        summary = program.summary()
        self.assertEqual(summary["symbols"], 1)
        self.assertEqual(summary["notes"], ["synthetic note"])
        summary["notes"].append("copy only")
        self.assertEqual(program.notes, ["synthetic note"])

    def test_empty_program_defaults_are_independent(self):
        first = Program("one", "unknown", "mips")
        second = Program("two", "unknown", "mips")
        first.segments.append(Segment("sample", 0, b"", 0))
        first.metadata["synthetic"] = True
        self.assertEqual(second.segments, [])
        self.assertEqual(second.metadata, {})
        self.assertIsNone(second.read(0, 1))
        self.assertIsNone(second.read_u32(0))
        self.assertIsNone(second.read_cstring(0))
        self.assertFalse(second.is_code(0))
        self.assertTrue(issubclass(NeedsDecryption, FormatError))
        self.assertTrue(issubclass(FormatError, ValueError))


class ElfWriterTests(unittest.TestCase):
    def serialize(self, program, functions=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.elf"
            self.assertEqual(write_elf(program, path, functions), path)
            return parse_elf(self, path.read_bytes())

    def test_elf32_little_endian_segments_and_symbols(self):
        program = Program("synthetic", "unknown", "mips", variant="r5900", entry=0x1000,
                          segments=[Segment("code", 0x1000, b"ABCD", 16, executable=True),
                                    Segment("data", 0x2000, b"xyz", 8, writable=True)])
        program.add_symbol(Symbol(0x1000, "synthetic_entry", size=4))
        program.add_symbol(Symbol(0x2000, "synthetic_object", kind="object", size=3))
        program.add_symbol(Symbol(0x9000, "synthetic_absolute", kind="object"))
        header, segments, sections, symbols = self.serialize(program)
        self.assertEqual((header["machine"], header["entry"], header["flags"]), (8, 0x1000, 0x00920000))
        self.assertEqual((header["phnum"], header["shnum"]), (2, 6))
        self.assertEqual([s["data"] for s in segments], [b"ABCD", b"xyz"])
        self.assertEqual([s["memsz"] for s in segments], [16, 8])
        self.assertEqual([s["flags"] for s in segments], [5, 6])
        self.assertEqual(sections[".text0"]["flags"], 6)
        self.assertEqual(sections[".data1"]["flags"], 3)
        self.assertEqual(sections[".text0"]["size"], 4)
        names = {s["name"]: s for s in symbols}
        self.assertEqual(names["synthetic_entry"]["section"], 1)
        self.assertEqual(names["synthetic_object"]["kind"], 1)
        self.assertEqual(names["synthetic_absolute"]["section"], 0xFFF1)

    def test_elf64_big_endian_preserves_wide_addresses(self):
        address = 0x100002000
        program = Program("synthetic", "unknown", "ppc64", big_endian=True, entry=address,
                          segments=[Segment("code", address, b"\x91\x82\x73\x64", 32, executable=True),
                                    Segment("ignored", 0, b"", 0)])
        program.add_symbol(Symbol(address, "wide_entry", size=4))
        header, segments, sections, symbols = self.serialize(program)
        self.assertEqual((header["machine"], header["entry"], header["flags"]), (21, address, 0))
        self.assertEqual((header["phnum"], header["shnum"]), (1, 5))
        self.assertEqual(segments[0]["vaddr"], address)
        self.assertEqual(segments[0]["data"], b"\x91\x82\x73\x64")
        self.assertEqual(sections[".text0"]["addr"], address)
        self.assertEqual(symbols[1]["value"], address)
        self.assertEqual(symbols[1]["binding"], 1)

    def test_elf32_big_endian_layout_symbols_and_unbacked_memory(self):
        program = Program("synthetic", "unknown", "ppc", big_endian=True, entry=0x10203044,
                          segments=[Segment("code", 0x10203040, b"\x12\x34\x56\x78ABC", 32,
                                            executable=True),
                                    Segment("zero_area", 0x40506070, b"", 48, writable=True)])
        program.add_symbol(Symbol(0x10203044, "big_entry", size=3))
        program.add_symbol(Symbol(0x40506078, "big_zero", kind="object", size=8))
        program.add_symbol(Symbol(0x708090A0, "big_absolute", kind="object", size=2))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.elf"
            write_elf(program, path)
            raw = path.read_bytes()
        self.assertEqual(raw[:16], b"\x7fELF\x01\x02\x01" + bytes(9))
        header, segments, sections, symbols = parse_elf(self, raw)
        self.assertEqual(header, dict(type=2, machine=20, version=1, entry=0x10203044,
                                      phoff=52, shoff=header["shoff"], flags=0, ehsize=52,
                                      phentsize=32, phnum=2, shentsize=40, shnum=6, shstrndx=5))
        self.assertEqual(header["shoff"] % 8, 0)
        self.assertGreaterEqual(segments[0]["offset"], 52 + 2 * 32)
        self.assertLessEqual(segments[0]["offset"] + 7, segments[1]["offset"])
        self.assertLessEqual(segments[1]["offset"], sections[".symtab"]["offset"])
        self.assertEqual(struct.unpack_from(">IIIIIIII", raw, 52),
                         (1, segments[0]["offset"], 0x10203040, 0x10203040, 7, 32, 5, 16))
        self.assertEqual(struct.unpack_from(">IIIIIIII", raw, 84),
                         (1, segments[1]["offset"], 0x40506070, 0x40506070, 0, 48, 6, 16))
        self.assertEqual([segment["data"] for segment in segments], [b"\x12\x34\x56\x78ABC", b""])
        self.assertEqual(program.read(0x40506070, 48), bytes(48))
        self.assertEqual(set(sections), {"", ".text0", ".data1", ".symtab", ".strtab", ".shstrtab"})
        for name, address, size, flags, segment in (
                (".text0", 0x10203040, 7, 6, segments[0]),
                (".data1", 0x40506070, 0, 3, segments[1])):
            section = sections[name]
            self.assertEqual((section["type"], section["flags"], section["addr"], section["offset"],
                              section["size"], section["link"], section["info"], section["align"],
                              section["entsize"]),
                             (1, flags, address, segment["offset"], size, 0, 0, 16, 0))
        symtab, strtab, shstrtab = (sections[name] for name in (".symtab", ".strtab", ".shstrtab"))
        self.assertEqual((symtab["type"], symtab["size"], symtab["link"], symtab["info"],
                          symtab["align"], symtab["entsize"]), (2, 64, 4, 1, 8, 16))
        self.assertEqual(strtab["offset"], symtab["offset"] + 64)
        self.assertEqual(shstrtab["offset"], strtab["offset"] + strtab["size"])
        self.assertLessEqual(shstrtab["offset"] + shstrtab["size"], header["shoff"])
        self.assertEqual((strtab["type"], strtab["align"], shstrtab["type"], shstrtab["align"]),
                         (3, 1, 3, 1))
        self.assertEqual(raw[strtab["offset"]:strtab["offset"] + strtab["size"]],
                         b"\0big_entry\0big_zero\0big_absolute\0")
        self.assertEqual(symbols[1:], [
            dict(name="big_entry", value=0x10203044, size=3, binding=1, kind=2, section=1),
            dict(name="big_zero", value=0x40506078, size=8, binding=1, kind=1, section=2),
            dict(name="big_absolute", value=0x708090A0, size=2, binding=1, kind=1, section=0xFFF1)])

    def test_elf64_little_endian_layout_wide_addresses_and_symbols(self):
        program = Program("synthetic", "unknown", "x86-64", entry=0x1200002004,
                          segments=[Segment("code", 0x1200002000, b"CODE1234", 32, executable=True),
                                    Segment("data", 0x3400005000, b"\x89\xAB\xCD\xEF", 24, writable=True)])
        program.add_symbol(Symbol(0x1200002004, "wide_little_entry", size=4))
        program.add_symbol(Symbol(0x3400005000, "wide_little_object", kind="object", size=4))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.elf"
            write_elf(program, path)
            raw = path.read_bytes()
        self.assertEqual(raw[:16], b"\x7fELF\x02\x01\x01" + bytes(9))
        header, segments, sections, symbols = parse_elf(self, raw)
        self.assertEqual(header, dict(type=2, machine=62, version=1, entry=0x1200002004,
                                      phoff=64, shoff=header["shoff"], flags=0, ehsize=64,
                                      phentsize=56, phnum=2, shentsize=64, shnum=6, shstrndx=5))
        self.assertEqual(header["shoff"] % 8, 0)
        self.assertGreaterEqual(segments[0]["offset"], 64 + 2 * 56)
        self.assertLessEqual(segments[0]["offset"] + 8, segments[1]["offset"])
        self.assertLessEqual(segments[1]["offset"] + 4, sections[".symtab"]["offset"])
        self.assertEqual(struct.unpack_from("<IIQQQQQQ", raw, 64),
                         (1, 5, segments[0]["offset"], 0x1200002000, 0x1200002000, 8, 32, 16))
        self.assertEqual(struct.unpack_from("<IIQQQQQQ", raw, 120),
                         (1, 6, segments[1]["offset"], 0x3400005000, 0x3400005000, 4, 24, 16))
        self.assertEqual([segment["data"] for segment in segments], [b"CODE1234", b"\x89\xAB\xCD\xEF"])
        self.assertEqual(program.read(0x3400005000, 24), b"\x89\xAB\xCD\xEF" + bytes(20))
        self.assertEqual(set(sections), {"", ".text0", ".data1", ".symtab", ".strtab", ".shstrtab"})
        for name, address, size, flags, segment in (
                (".text0", 0x1200002000, 8, 6, segments[0]),
                (".data1", 0x3400005000, 4, 3, segments[1])):
            section = sections[name]
            self.assertEqual((section["type"], section["flags"], section["addr"], section["offset"],
                              section["size"], section["link"], section["info"], section["align"],
                              section["entsize"]),
                             (1, flags, address, segment["offset"], size, 0, 0, 16, 0))
        symtab, strtab, shstrtab = (sections[name] for name in (".symtab", ".strtab", ".shstrtab"))
        self.assertEqual((symtab["type"], symtab["size"], symtab["link"], symtab["info"],
                          symtab["align"], symtab["entsize"]), (2, 72, 4, 1, 8, 24))
        self.assertEqual(strtab["offset"], symtab["offset"] + 72)
        self.assertEqual(shstrtab["offset"], strtab["offset"] + strtab["size"])
        self.assertLessEqual(shstrtab["offset"] + shstrtab["size"], header["shoff"])
        self.assertEqual((strtab["type"], strtab["align"], shstrtab["type"], shstrtab["align"]),
                         (3, 1, 3, 1))
        self.assertEqual(raw[strtab["offset"]:strtab["offset"] + strtab["size"]],
                         b"\0wide_little_entry\0wide_little_object\0")
        self.assertEqual(symbols[1:], [
            dict(name="wide_little_entry", value=0x1200002004, size=4, binding=1, kind=2, section=1),
            dict(name="wide_little_object", value=0x3400005000, size=4, binding=1, kind=1, section=2)])

    def test_elf64_little_endian_declared_sizes_above_32_bits(self):
        # Huge *declared* memory and symbol spans; only three invented bytes
        # are initialized. Never call Program.read on the mapped span.
        base = 0x4200002000
        memsz = 0x100001200
        symbol_size = 0x100000080
        program = Program("synthetic", "unknown", "x86-64", entry=base,
                          segments=[Segment("sparse", base, b"\xA1\xBC\xCD",
                                            memsz, writable=True)])
        program.add_symbol(Symbol(base + 1, "wide_declared_object", kind="object",
                                  size=symbol_size))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sparse-le.elf"
            write_elf(program, path)
            raw = path.read_bytes()
        self.assertLess(len(raw), 1024)  # no 4-GiB allocation or materialization
        self.assertEqual(raw[:7], b"\x7fELF\x02\x01\x01")
        header, segments, sections, symbols = parse_elf(self, raw)
        self.assertEqual((header["machine"], header["phnum"], header["shnum"]), (62, 1, 5))
        self.assertEqual(struct.unpack_from("<IIQQQQQQ", raw, 64),
                         (1, 6, segments[0]["offset"], 0x4200002000, 0x4200002000,
                          3, 0x100001200, 16))
        self.assertEqual(segments[0]["data"], b"\xA1\xBC\xCD")
        self.assertEqual(segments[0]["filesz"], 3)
        self.assertEqual(segments[0]["memsz"], 0x100001200)
        self.assertEqual((sections[".data0"]["size"], sections[".data0"]["addr"]),
                         (3, 0x4200002000))
        self.assertEqual(symbols[1],
                         dict(name="wide_declared_object", value=0x4200002001,
                              size=0x100000080, binding=1, kind=1, section=1))

    def test_elf64_big_endian_declared_sizes_above_32_bits(self):
        base = 0x6200004000
        program = Program("synthetic", "unknown", "ppc64", big_endian=True,
                          entry=base,
                          segments=[Segment("sparse_code", base, b"\x99\x88",
                                            0x200000001, executable=True)])
        program.add_symbol(Symbol(base, "wide_be_function", size=0x100000ABC))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sparse-be.elf"
            write_elf(program, path)
            raw = path.read_bytes()
        self.assertLess(len(raw), 1024)
        self.assertEqual(raw[:7], b"\x7fELF\x02\x02\x01")
        header, segments, sections, symbols = parse_elf(self, raw)
        self.assertEqual((header["machine"], header["entry"], header["phnum"]),
                         (21, 0x6200004000, 1))
        self.assertEqual(struct.unpack_from(">IIQQQQQQ", raw, 64),
                         (1, 5, segments[0]["offset"], 0x6200004000, 0x6200004000,
                          2, 0x200000001, 16))
        self.assertEqual(segments[0]["data"], b"\x99\x88")
        self.assertEqual(sections[".text0"]["size"], 2)
        self.assertEqual(symbols[1],
                         dict(name="wide_be_function", value=0x6200004000,
                              size=0x100000ABC, binding=1, kind=2, section=1))

    def test_arm_thumb_symbols_override_program_names(self):
        program = Program("synthetic", "unknown", "arm", entry=0x1000,
                          segments=[Segment("code", 0x1000, bytes(32), 32, executable=True)])
        program.add_symbol(Symbol(0x1000, "superseded"))
        functions = {0x1010: SimpleNamespace(name="thumb_entry", size=6, mode="thumb"),
                     0x1000: SimpleNamespace(name="arm_entry", size=-1, mode="arm")}
        header, _, sections, symbols = self.serialize(program, functions)
        self.assertEqual((header["machine"], header["flags"]), (40, 0x05000000))
        self.assertEqual([s["name"] for s in symbols], ["", "$a", "$t", "arm_entry", "thumb_entry"])
        self.assertEqual([s["binding"] for s in symbols], [0, 0, 0, 1, 1])
        self.assertEqual(sections[".symtab"]["info"], 3)
        self.assertEqual(symbols[-1]["value"], 0x1011)
        self.assertEqual(symbols[-1]["section"], 1)
        self.assertEqual(symbols[-2]["size"], 0)

    def test_empty_program_has_empty_load_table_and_null_symbol(self):
        header, segments, sections, symbols = self.serialize(Program("synthetic", "unknown", "x86"))
        self.assertEqual((header["machine"], header["entry"], header["phnum"], header["shnum"]), (3, 0, 0, 4))
        self.assertEqual(segments, [])
        self.assertEqual(set(sections), {"", ".symtab", ".strtab", ".shstrtab"})
        self.assertEqual(len(symbols), 1)

    def test_unsupported_architecture_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsupported.elf"
            with self.assertRaisesRegex(ValueError, "No ELF machine for invented_cpu"):
                write_elf(Program("synthetic", "unknown", "invented_cpu"), path)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
