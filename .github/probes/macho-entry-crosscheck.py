#!/usr/bin/env python3
"""The signer's typed Mach-O words against dyld_info's fixups, word by word.

  macho-entry-crosscheck.py <show.txt> <dyld_info.txt>

<show.txt> is `oxicrypt-integrity-sign --show` of a dylib (image base 0),
<dyld_info.txt> is `dyld_info -fixups` of the same dylib. For every word dyld
fixes up in `__DATA_CONST` or `__thread_data`, the signer must have a word at
the same address of the same kind: a `Relative` word for a rebase, and for a
bind a `Bind` word whose record names the same library, the same symbol (one
leading `_` removed) and the same addend. The signer must have no other word.

Three CONTROLS each change the `--show` text and run both parsers again; the
comparison must then fail:
  dropped    the first `Relative` entry line removed;
  swapped    the symbols of two records with different symbols exchanged;
  library    one record's library replaced.

Exit status: 0 equal and every control fired, 1 unequal or a control did not
fire, 2 nothing was read, 3 a crash.
"""
import os
import re
import sys

ENTRY = re.compile(
    r"^\s+\[\d+\] (Relative|Bind) rva (0x[0-9a-f]+) file 0x[0-9a-f]+ len (\d+) hole \d+"
    r"(?: record (\d+))?$", re.M)
RECORD = re.compile(r"^(\s+record \[(\d+)\] )(\S+) (\S+) addend (-?\d+) (weak|strong)$", re.M)
FIXUP = re.compile(
    r"^\s+(\S+)\s+(\S+)\s+0x([0-9A-Fa-f]+)\s+(rebase|bind)\s+(\S+)(?:\s*\+\s*(0x[0-9A-Fa-f]+|\d+))?",
    re.M)


def signer_words(text):
    records = {int(i): (lib, sym, int(add)) for _p, i, lib, sym, add, _w in RECORD.findall(text)}
    words = {}
    for kind, rva, length, record in ENTRY.findall(text):
        for k in range(int(length) // 8):
            addr = int(rva, 16) + 8 * k
            if kind == "Relative":
                words[addr] = ("rebase",)
            else:
                words[addr] = ("bind",) + records.get(int(record or -1), ("?", "?", 0))
    return words


def tool_words(text):
    words = {}
    for seg, sect, addr, kind, target, addend in FIXUP.findall(text):
        if seg != "__DATA_CONST" and sect != "__thread_data":
            continue
        if kind == "rebase":
            words[int(addr, 16)] = ("rebase",)
            continue
        lib, _, name = target.rpartition("/")
        name = name[1:] if name.startswith("_") else name
        words[int(addr, 16)] = ("bind", lib, name, int(addend, 0) if addend else 0)
    return words


def same_library(path, short):
    leaf = os.path.basename(path)
    return leaf == short or leaf.startswith(short + ".")


def differences(ours, theirs):
    out = []
    for addr in sorted(set(ours) | set(theirs)):
        a, b = ours.get(addr), theirs.get(addr)
        if a is None or b is None or a[0] != b[0]:
            out.append(f"{addr:#x}: signer {a}, dyld_info {b}")
        elif a[0] == "bind" and not (same_library(a[1], b[1]) and a[2] == b[2] and a[3] == b[3]):
            out.append(f"{addr:#x}: signer {a[1:]}, dyld_info {b[1:]}")
    return out


def controls(show):
    yield "dropped", _drop_first_relative(show)
    recs = RECORD.findall(show)
    pair = next(((x, y) for x in recs for y in recs if x[3] != y[3]), None)
    if pair:
        x, y = pair
        swapped = show.replace(f"{x[0]}{x[2]} {x[3]} ", "\0X").replace(f"{y[0]}{y[2]} {y[3]} ", "\0Y")
        swapped = swapped.replace("\0X", f"{x[0]}{x[2]} {y[3]} ").replace("\0Y", f"{y[0]}{y[2]} {x[3]} ")
        yield "swapped", swapped
    else:
        yield "swapped", None
    if recs:
        r = recs[0]
        yield "library", show.replace(f"{r[0]}{r[2]} ", f"{r[0]}/usr/lib/libwrong.dylib ", 1)
    else:
        yield "library", None


def _drop_first_relative(show):
    m = next((m for m in ENTRY.finditer(show) if m.group(1) == "Relative"), None)
    return None if m is None else show[:m.start()] + show[m.end():]


def main(argv, out=print):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    show, tool = open(argv[0]).read(), open(argv[1]).read()
    ours, theirs = signer_words(show), tool_words(tool)
    if not ours or not theirs:
        out(f"UNPARSED: {len(ours)} signer words, {len(theirs)} dyld_info fixups")
        return 2
    diff = differences(ours, theirs)
    binds = sum(1 for w in theirs.values() if w[0] == "bind")
    out(f"measurement: {len(theirs)} dyld_info fixups ({binds} binds) in __DATA_CONST and "
        f"__thread_data, {len(ours)} signer words, equal={'yes' if not diff else 'NO'}")
    for line in diff[:10]:
        out(f"  {line}")
    fired = True
    for name, text in controls(show):
        if text is None or text == show:
            out(f"control NOT RUN: {name}: the listing has nothing to change")
            fired = False
            continue
        if differences(signer_words(text), tool_words(tool)):
            out(f"control ok: {name} makes them unequal")
        else:
            out(f"control FAILED: {name} left them equal")
            fired = False
    return 0 if not diff and fired else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception:  # a crash must never read as a verdict
        import traceback
        traceback.print_exc()
        print("CRASHED: macho-entry-crosscheck.py")
        sys.exit(3)
