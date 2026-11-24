#!/usr/bin/env bash
# Lists the call sites of the caller-entropy DRBG forms: instantiate, reseed
# and prediction-resistant generate with entropy the caller supplies.
#
#   list-caller-entropy-sites.sh [root]
#
# Prints `path:line: text` for every line of a `*.rs` file under root (the
# repository root by default) matching
#
#   \.(instantiate|reseed|generate_pr|instantiate_no_df|instantiate_df|
#      reseed_no_df|reseed_df|generate_no_df_pr|generate_df_pr)\(
#
# outside the places those forms are allowed:
#
#   - acvp-harness/, which drives the forms with the published test vectors;
#   - crates/oxicrypt-drbg/src/, where the forms are defined and tested;
#   - target/ directories;
#   - files under a crate's tests/ that its Cargo.toml lists as a [[test]]
#     with required-features;
#   - a call to the bare `instantiate` or `reseed` with fewer arguments than
#     the caller-entropy form takes (3 and 2), which is a module-seeded form of
#     the same name on another crate's handle type;
#   - code under #[cfg(test)]: the item the attribute applies to, found by
#     brace matching that skips comments, strings and character literals, a
#     file whose first attribute is #![cfg(test)], and the file a
#     `#[cfg(test)] mod name;` declaration loads.
#
# Paths are relative to root. Exits 0 whether or not anything is listed, and
# 2 when root is not a directory. Needs python3 3.11 or later.
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[ -d "$root" ] || { echo "list-caller-entropy-sites: $root is not a directory" >&2; exit 2; }

python3 -I - "$root" <<'PY'
import os
import re
import sys
import tomllib

ROOT = os.path.abspath(sys.argv[1])
PATTERN = re.compile(
    r"\.(instantiate|reseed|generate_pr|instantiate_no_df|instantiate_df"
    r"|reseed_no_df|reseed_df|generate_no_df_pr|generate_df_pr)\("
)
CFG_TEST = re.compile(r"#\[cfg\(test\)\]")
INNER_CFG_TEST = re.compile(r"#!\[cfg\(test\)\]")
EXCLUDED_DIRS = {
    os.path.join(ROOT, "acvp-harness"),
    os.path.join(ROOT, "crates", "oxicrypt-drbg", "src"),
}


def gated_tests(crate_dir):
    """Paths of the crate's [[test]] targets that declare required-features."""
    manifest = os.path.join(crate_dir, "Cargo.toml")
    try:
        with open(manifest, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    gated = set()
    for test in data.get("test", []):
        if not test.get("required-features"):
            continue
        path = test.get("path") or os.path.join("tests", test.get("name", "") + ".rs")
        gated.add(os.path.normpath(os.path.join(crate_dir, path)))
    return gated


def mask(src):
    """The source with comments, strings and character literals blanked.

    Newlines are kept, so offsets and line numbers are unchanged.
    """
    out = list(src)
    i, n = 0, len(src)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif (m := re.compile(r'b?r(#*)"').match(src, i)) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            close = '"' + m.group(1)
            j = src.find(close, m.end())
            j = n if j < 0 else j + len(close)
            blank(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
        elif c == "'":
            m = re.compile(r"'(\\.[^']*|[^\\'\n])'").match(src, i)
            if m:
                blank(i, m.end())
                i = m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def item_end(masked, start):
    """Offset just past the item that begins at `start`."""
    depth, nest, i, n = 0, 0, start, len(masked)
    while i < n:
        c = masked[i]
        if c in "([":
            nest += 1
        elif c in ")]":
            nest -= 1
        elif c == ";" and depth == 0 and nest == 0:
            return i + 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def module_files(path, name):
    """Files a `mod name;` in `path` may load."""
    stem = os.path.splitext(os.path.basename(path))[0]
    parent = os.path.dirname(path)
    base = parent if stem in ("lib", "main", "mod") else os.path.join(parent, stem)
    return {os.path.join(base, name + ".rs"), os.path.join(base, name, "mod.rs")}


def test_ranges(path, src):
    """Line ranges under #[cfg(test)], and the files they load."""
    masked = mask(src)
    head = masked.lstrip()
    if INNER_CFG_TEST.match(head):
        return [(1, src.count("\n") + 1)], set()
    ranges, loaded = [], set()
    for m in CFG_TEST.finditer(masked):
        end = item_end(masked, m.end())
        item = masked[m.end():end]
        decl = re.fullmatch(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", item)
        if decl:
            loaded |= module_files(path, decl.group(1))
        first = masked.count("\n", 0, m.start()) + 1
        last = masked.count("\n", 0, end) + 1
        ranges.append((first, last))
    return ranges, loaded


def rust_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in ("target", ".git") and os.path.join(dirpath, d) not in EXCLUDED_DIRS
        )
        for name in sorted(filenames):
            if name.endswith(".rs"):
                yield os.path.join(dirpath, name)


def crate_of(path):
    """The directory of the nearest Cargo.toml above `path`."""
    d = os.path.dirname(path)
    while d.startswith(ROOT):
        if os.path.isfile(os.path.join(d, "Cargo.toml")):
            return d
        d = os.path.dirname(d)
    return None


gated_cache = {}
files = list(rust_files())
scanned = {}
excluded = set()
for path in files:
    crate = crate_of(path)
    if crate is not None:
        if crate not in gated_cache:
            gated_cache[crate] = gated_tests(crate)
        if os.path.normpath(path) in gated_cache[crate]:
            continue
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
    except (OSError, UnicodeDecodeError):
        continue
    ranges, loaded = test_ranges(path, src)
    excluded |= {os.path.normpath(p) for p in loaded}
    scanned[path] = (src, ranges)

def argument_count(masked, open_paren):
    """The number of arguments in the call whose `(` is at `open_paren`."""
    depth, count, saw_text, i, n = 0, 0, False, open_paren, len(masked)
    while i < n:
        c = masked[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return count + 1 if saw_text else 0
        elif c == "," and depth == 1:
            count += 1
        elif depth >= 1 and not c.isspace():
            saw_text = True
        i += 1
    return 0


# The bare names `instantiate` and `reseed` are also the names of the
# one-argument module-seeded forms on other crates' handle types, so they
# count only at the caller-entropy arity: instantiate(entropy, nonce,
# personalization) and reseed(entropy, additional_input). The suffixed
# forms are matched by name.
MIN_ARGS = {"instantiate": 3, "reseed": 2}

for path, (src, ranges) in scanned.items():
    if os.path.normpath(path) in excluded:
        continue
    rel = os.path.relpath(path, ROOT)
    masked = mask(src)
    lines = src.splitlines()
    for m in PATTERN.finditer(masked):
        number = masked.count("\n", 0, m.start()) + 1
        if any(first <= number <= last for first, last in ranges):
            continue
        needed = MIN_ARGS.get(m.group(1))
        if needed is not None and argument_count(masked, m.end() - 1) < needed:
            continue
        print(f"{rel}:{number}: {lines[number - 1].strip()}")
PY
