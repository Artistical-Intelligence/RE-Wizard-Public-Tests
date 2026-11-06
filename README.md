# RE-Wizard Public Tests

A small companion project containing two original RE-Wizard implementation modules
and synthetic regression tests. The implementation files are exported without
behavioral changes; the full source-revision mapping is kept separately.

## Included components

| Component | Purpose | Exported source size |
| --- | --- | ---: |
| `rewizard/formats/model.py` | Program, segment and symbol model; mapped reads | 4,224 bytes |
| `rewizard/formats/elf_writer.py` | ELF32/ELF64 serialization with symbols | 5,452 bytes |

These files use the Python standard library. The package initializers are new,
minimal test-package plumbing; they do not load the full Workbench or its bundled
dependencies.

## Run locally

Use Python 3.10 or newer, from the repository root:

```sh
python -B tools/check_public_tree.py
python -B -m unittest discover -s tests -v
```

The 13 original tests use invented byte strings, addresses, names and structural
objects. Generated ELF files live only in temporary directories, and are not
executed. Tests independently inspect their headers, segment/section tables and
symbols using Python's standard-library `struct` module.

Covered cases include mapped bounds, unmapped/cross-segment reads, virtual
zero-fill, byte order, strings, symbol selection, empty programs, ELF32 little
endian, ELF64 big endian, ARM/Thumb symbol metadata and unsupported architecture
rejection.

## Scope and limits

Passing tests establish only the covered behavior of the exact exported
implementation hashes in `export-manifest.json`. They do not establish complete
Workbench integration, private-project builds, runtime parity, or behavior on
third-party software.

Inputs follow the existing modules' sane-input contracts. Negative lengths/sizes
and inconsistent segment metadata are not validated by these modules.
`read_cstring` searches initialized bytes only. The ELF writer does not preserve
arbitrary source metadata or produce relocation records.

## Publication boundary

Every committed file is intended to remain public permanently. This repository
contains no games, compiler archives or binaries, downloaded reference source,
real input dumps, credentials or private provenance records.

The workflow checks out only this public repository. It uses a standard hosted
Ubuntu runner, read-only repository permissions and no private-repository secrets.
It creates no uploaded build artifacts or caches.

`tools/check_public_tree.py` detects unexpected tracked files and source drift.
It is a regression guard; publication review happens before a push, because a
check after publication cannot retract already disclosed material.

Update only through the reviewed export process. Each source change must have
a matching reviewed content hash. Keep exact source provenance and test-run
mapping outside this public repository.
