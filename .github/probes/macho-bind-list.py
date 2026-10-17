#!/usr/bin/env python3
"""Lists a dylib's bound words for macho-bind-report, from the signer's
`--show` listing: one line per word, `rva library symbol`.

  macho-bind-list.py <show.txt>

Exit status: 0 listed, 2 no bound word in the listing.
"""
import re
import sys

text = open(sys.argv[1]).read()
records = {int(i): (lib, sym) for i, lib, sym in
           re.findall(r"^\s+record \[(\d+)\] (\S+) (\S+) addend", text, re.M)}
n = 0
for rva, length, record in re.findall(
        r"\[\d+\] Bind rva (0x[0-9a-f]+) file 0x[0-9a-f]+ len (\d+) hole \d+ record (\d+)", text):
    lib, sym = records[int(record)]
    for k in range(int(length) // 8):
        print(f"{int(rva, 16) + 8 * k:x} {lib} {sym}")
        n += 1
sys.exit(0 if n else 2)
