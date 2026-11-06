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
