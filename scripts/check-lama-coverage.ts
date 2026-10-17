#!/usr/bin/env bun
// check-lama-coverage — fails when a public item of a publishable crate is
// absent from the full LAMA manifest.
//
// Usage:
//     bun scripts/check-lama-coverage.ts [--list] [<repo-root>]
//     bun scripts/check-lama-coverage.ts --guard-sweep <dir> <expected-count>
//
// <repo-root> defaults to the current directory. It must contain the root
// `Cargo.toml` and every workspace member it lists,
// `docs/llm-api-manifest/llm-api.yaml` and the baseline file named below; the
// pre-push wrapper passes an extracted copy of the revision being pushed.
//
// `--list` prints every uncovered item, one per line in baseline format, and
// exits 0. It is a diagnostic. The baseline only shrinks, so a new item gets a
// manifest entry, never a baseline line; scripts/check-lama-manifests.sh fails
// when the baseline gains a line relative to its merge base with origin/main.
//
// Exit codes: 0 covered · 1 an item is missing, a baseline line is stale, or
// the scan could not be trusted · 2 usage error.
//
// The roster is every workspace member with a library target, wherever it
// sits in the tree, except members with `publish = false` and
// `oxicrypt-test-vectors`.
//
// What counts as public: an item declared `pub` (not `pub(crate)` or another
// restricted form) at module level, in a module reachable from the crate root
// through `pub mod` declarations, or re-exported by a `pub use` inside the
// crate, outside `#[cfg(test)]` code, `#[doc(hidden)]` or not. Kinds: fn,
// struct, enum, union, trait, type, const, static, and the `pub const` items
// of an inherent impl, named `Type::NAME`. Methods, and the items of a trait
// impl, are not items here; the manifest documents methods selectively by
// design.
//
// Excluded, exactly as the coverage rule in AGENTS.md states:
//   - `*_internal` functions without the service gates: a function named
//     `*_internal` whose body calls neither `require_operational` nor
//     `require_allowed`. Such functions call
//     `oxicrypt_module::require_self_test_started` instead, which is not a
//     service gate and is not in GATES;
//   - `*_self_test` functions (a name that is `self_test` or ends in
//     `_self_test`), which the crate's `KATS` slice already carries.
//
// Macros: a module-level invocation of a `macro_rules!` macro defined in the
// same crate is expanded approximately, by scanning every arm's body as if it
// were written at the invocation site. An item whose name comes from a macro
// argument (`pub fn $name`) or is assembled by another macro is not seen, so
// it can be absent from the manifest without this check noticing.
//
// A manifest entry covers an item when it names the same crate in `module:` and
// its `name:` is the item's full public path, or a `::`-joined suffix of it
// (`verify` for `ml_dsa_44::verify`) that no other public item of the crate
// shares. In `oxicrypt-integrity-sign`, where the crate root, `elf`, `macho`
// and `pe` each have a `classify`, an entry named `classify` therefore covers
// only the crate-root function.
//
// Guard sweep: before the coverage check, every `pub fn *_internal` under
// `crates/`, and every other function named in GUARDED_EXTRA, must have
// `require_self_test_started()?;` as the first statement of its body (or
// `let started = require_self_test_started_token()?;`, which runs that guard
// and keeps its proof), and
// the number of such functions must equal GUARDED_COUNT. The count stops the
// sweep passing because it found fewer functions than exist. `--guard-sweep`
// runs only this sweep over another directory with another expected count;
// `scripts/fixtures/guard-sweep` holds twelve functions the sweep must reject
// and seven it must not count; `unguarded.rs`, `qualified.rs`,
// `service_gate.rs`, `macro_*.rs` and `lexer_cases*.rs` each say what they
// exercise. `--guard-sweep scripts/fixtures/guard-sweep 12` must fail and
// name all twelve.
//
// The baseline file lists items that were already undocumented when this check
// was introduced. An item on it does not fail the check; a line that no longer
// names an uncovered item does, so the list can only shrink.

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { basename, dirname, join } from "path";

const MANIFEST = "docs/llm-api-manifest/llm-api.yaml";
const BASELINE = "docs/llm-api-manifest/coverage-baseline.txt";
const NO_MEMBERS = new Set(["oxicrypt-test-vectors"]);
const ITEM_KINDS = new Set(["fn", "struct", "enum", "union", "trait", "type", "const", "static"]);
// A call to either of these makes a function gated: it refuses service until
// the module is operational, or under a profile that does not admit it.
const GATES = new Set(["require_operational", "require_allowed"]);

// ── lexer ────────────────────────────────────────────────────────────────
// Produces identifiers, string placeholders and single punctuation tokens,
// with comments removed, so brace matching is not fooled by `{` in a string.

interface Tok {
  t: string;
  line: number;
}

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  let line = 1;
  const n = src.length;
  const push = (t: string) => out.push({ t, line });
  const advanceTo = (j: number) => {
    for (let k = i; k < j && k < n; k++) if (src[k] === "\n") line++;
    i = j;
  };
  while (i < n) {
    const c = src[i];
    if (c === "\n") {
      line++;
      i++;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      const e = src.indexOf("\n", i);
      i = e < 0 ? n : e;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (src[j] === "/" && src[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (src[j] === "*" && src[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      advanceTo(j);
      continue;
    }
    // raw strings: r"..", r#".."#, br#".."#
    const raw = /^(b?r)(#*)"/.exec(src.slice(i, i + 40));
    if (raw) {
      const close = '"' + raw[2];
      const start = i + raw[0].length;
      const e = src.indexOf(close, start);
      push("STR");
      advanceTo(e < 0 ? n : e + close.length);
      continue;
    }
    if (c === '"' || (c === "b" && src[i + 1] === '"') || (c === "c" && src[i + 1] === '"')) {
      let j = c === '"' ? i + 1 : i + 2;
      while (j < n && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      push("STR");
      advanceTo(j + 1);
      continue;
    }
    if (c === "'" || (c === "b" && src[i + 1] === "'")) {
      const s = c === "'" ? i + 1 : i + 2;
      // char literal: an escape, or one code point, then a closing quote
      const m = /^(\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'\n])'/u.exec(src.slice(s, s + 16));
      if (m) {
        push("CHR");
        advanceTo(s + m[0].length);
        continue;
      }
      // lifetime or label
      const l = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(s));
      push("LIFETIME");
      advanceTo(s + (l ? l[0].length : 0));
      continue;
    }
    const id = /^(r#)?[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i, i + 200));
    if (id) {
      push(id[0].replace(/^r#/, ""));
      i += id[0].length;
      continue;
    }
    const num = /^[0-9][0-9A-Za-z_.]*/.exec(src.slice(i, i + 80));
    if (num) {
      push("NUM");
      i += num[0].length;
      continue;
    }
    push(c);
    i++;
  }
  return out;
}

// ── parser ───────────────────────────────────────────────────────────────

interface Item {
  name: string;
  kind: string;
  file: string;
  line: number;
  gated: boolean; // a fn whose body calls require_operational or require_allowed
}
interface UseLeaf {
  path: string[]; // last segment is the imported name, or "*"
  alias: string;
}
interface Mod {
  name: string;
  isPub: boolean;
  parent: Mod | null;
  file: string;
  dir: string; // where this module's child module files live
  children: Map<string, Mod>;
  items: Item[]; // pub items declared here
  uses: UseLeaf[]; // pub use leaves declared here
}

const OPEN: Record<string, string> = { "{": "}", "(": ")", "[": "]" };

function skipBalanced(toks: Tok[], i: number): number {
  // toks[i] is an opener; returns the index after its matching closer
  const stack = [OPEN[toks[i].t]];
  i++;
  while (i < toks.length && stack.length) {
    const t = toks[i].t;
    if (OPEN[t]) stack.push(OPEN[t]);
    else if (t === stack[stack.length - 1]) stack.pop();
    i++;
  }
  return i;
}

// Skip to the end of an item: through the first `;` or the first `{...}` block
// at bracket depth zero (after which a `;` is not expected).
function skipItem(toks: Tok[], i: number, endAtBrace = true): number {
  while (i < toks.length) {
    const t = toks[i].t;
    if (t === ";") return i + 1;
    if (t === "{") {
      const j = skipBalanced(toks, i);
      if (endAtBrace) return j;
      i = j;
      continue;
    }
    if (t === "(" || t === "[") {
      i = skipBalanced(toks, i);
      continue;
    }
    if (t === "}") return i; // end of enclosing block
    i++;
  }
  return i;
}

function parseUseTree(toks: Tok[], i: number, prefix: string[], out: UseLeaf[]): number {
  const path = [...prefix];
  while (i < toks.length) {
    const t = toks[i].t;
    if (t === ":" && toks[i + 1]?.t === ":") {
      i += 2;
      continue;
    }
    if (t === "{") {
      i++;
      while (i < toks.length && toks[i].t !== "}") {
        if (toks[i].t === ",") {
          i++;
          continue;
        }
        i = parseUseTree(toks, i, path, out);
      }
      return i + 1;
    }
    if (t === "*") {
      out.push({ path: [...path, "*"], alias: "*" });
      return i + 1;
    }
    if (/^[A-Za-z_]/.test(t)) {
      path.push(t);
      i++;
      if (toks[i]?.t === "as") {
        out.push({ path, alias: toks[i + 1].t });
        return i + 2;
      }
      if (toks[i]?.t === ":" && toks[i + 1]?.t === ":") continue;
      out.push({ path, alias: t });
      return i;
    }
    return i + 1; // `,` `}` `;` handled by caller
  }
  return i;
}

function attrText(toks: Tok[], i: number, j: number): string {
  return toks
    .slice(i, j)
    .map((x) => x.t)
    .join(" ");
}

function parseModBody(toks: Tok[], i: number, mod: Mod, ctx: Ctx): number {
  let attrs: string[] = [];
  while (i < toks.length) {
    const t = toks[i].t;
    if (t === "}") return i + 1;
    if (t === "#") {
      let j = i + 1;
      if (toks[j]?.t === "!") j++;
      if (toks[j]?.t === "[") {
        const e = skipBalanced(toks, j);
        if (toks[i + 1].t !== "!") attrs.push(attrText(toks, j, e));
        i = e;
        continue;
      }
    }
    const a = attrs.join(" | ");
    attrs = [];
    const isTest = /\bcfg \( test \)/.test(a) || /\bcfg \( all \( test/.test(a);
    const pathAttr = /\bpath = STR/.test(a);

    // visibility
    let vis: "pub" | "restricted" | "private" = "private";
    if (t === "pub") {
      if (toks[i + 1]?.t === "(") {
        vis = "restricted";
        i = skipBalanced(toks, i + 1);
      } else {
        vis = "pub";
        i++;
      }
    }
    // qualifiers
    while (["unsafe", "async", "default", "extern", "STR"].includes(toks[i]?.t)) {
      if (toks[i].t === "extern" && toks[i + 1]?.t === "crate") break;
      if (toks[i].t === "extern" && (toks[i + 1]?.t === "{" || (toks[i + 1]?.t === "STR" && toks[i + 2]?.t === "{"))) break;
      i++;
    }
    const kw = toks[i]?.t;
    if (kw === undefined) return i;

    if (kw === "const" && toks[i + 1]?.t === "fn") i++; // const fn
    const k2 = toks[i].t;

    if (k2 === "mod") {
      const name = toks[i + 1].t;
      if (!/^[A-Za-z_]/.test(name)) {
        i = skipItem(toks, i + 2); // a module named by a macro argument
        continue;
      }
      const after = toks[i + 2]?.t;
      if (isTest || pathAttr) {
        i = skipItem(toks, i + 2);
        if (pathAttr && !isTest) ctx.warnings.push(`${mod.file}: #[path] module ${name} not followed`);
        continue;
      }
      const child: Mod = {
        name,
        isPub: vis === "pub",
        parent: mod,
        file: mod.file,
        dir: join(mod.dir, name),
        children: new Map(),
        items: [],
        uses: [],
      };
      if (after === "{") {
        mod.children.set(name, child);
        i = parseModBody(toks, i + 3, child, ctx);
        continue;
      }
      // external file
      const cand = [join(mod.dir, `${name}.rs`), join(mod.dir, name, "mod.rs")];
      const f = cand.find((p) => existsSync(p));
      if (!f) {
        ctx.warnings.push(`${mod.file}: module ${name} has no file (looked for ${cand.join(", ")})`);
        i = skipItem(toks, i + 2);
        continue;
      }
      child.file = f;
      child.dir = basename(f) === "mod.rs" ? dirname(f) : join(dirname(f), basename(f, ".rs"));
      mod.children.set(name, child);
      parseFile(f, child, ctx);
      i = skipItem(toks, i + 2);
      continue;
    }
    if (k2 === "use") {
      if (vis === "pub" && !isTest) parseUseTree(toks, i + 1, [], mod.uses);
      i = skipItem(toks, i + 1, false);
      continue;
    }
    if (k2 === "macro_rules") {
      i = skipItem(toks, i + 3);
      continue;
    }
    if (k2 === "impl") {
      // An inherent impl's `pub const` items are public constants of the
      // type, named `Type::NAME`. A trait impl's are the trait's, and
      // methods are documented selectively, so neither is collected.
      const end = skipItem(toks, i + 1);
      if (!isTest) collectAssocConsts(toks, i + 1, end, mod, ctx);
      i = end;
      continue;
    }
    if (k2 === "extern") {
      i = skipItem(toks, i + 1);
      continue;
    }
    if (ITEM_KINDS.has(k2)) {
      let j = i + 1;
      if (k2 === "static" && toks[j]?.t === "mut") j++;
      const nameTok = toks[j];
      // A const, static or type alias ends at its `;` even when its value
      // holds a brace block; the other kinds end at their body.
      const end = skipItem(toks, j, !["const", "static", "type"].includes(k2));
      if (vis === "pub" && !isTest && nameTok && /^[A-Za-z_]/.test(nameTok.t) && nameTok.t !== "_")
        mod.items.push({
          name: nameTok.t,
          kind: k2,
          file: ctx.at?.file ?? mod.file,
          line: ctx.at?.line ?? nameTok.line,
          gated: k2 === "fn" && toks.slice(j, end).some((x) => GATES.has(x.t)),
        });
      i = end;
      continue;
    }
    // macro invocation, possibly path-qualified: expand a crate-local
    // macro_rules macro in place, step over anything else
    let m = i;
    while (/^[A-Za-z_]/.test(toks[m]?.t) && toks[m + 1]?.t === ":" && toks[m + 2]?.t === ":") m += 3;
    if (/^[A-Za-z_]/.test(toks[m]?.t) && toks[m + 1]?.t === "!" && toks[m]?.t !== "macro_rules") {
      const name = toks[m].t;
      const arms = ctx.macros.get(name);
      if (arms && !isTest && !ctx.expanding.includes(name) && ctx.expanding.length < 4) {
        const sub: Ctx = {
          ...ctx,
          expanding: [...ctx.expanding, name],
          at: ctx.at ?? { file: mod.file, line: toks[m].line },
        };
        for (const body of arms) parseModBody([...body, { t: "}", line: 0 }], 0, mod, sub);
      }
      i = skipItem(toks, m + 2);
      continue;
    }
    i++; // a stray `;` or a token this scanner has no rule for
  }
  return i;
}

// The `pub const` items of an inherent impl spanning toks[start..end), the
// tokens after `impl`, recorded in `mod` as `Type::NAME`.
function collectAssocConsts(toks: Tok[], start: number, end: number, mod: Mod, ctx: Ctx) {
  let open = start;
  let angle = 0;
  const header: string[] = [];
  while (open < end) {
    const t = toks[open].t;
    if (t === "<") angle++;
    else if (t === ">" && toks[open - 1]?.t !== "-") angle--;
    else if (t === "{" && angle <= 0) break;
    if (angle <= 0) header.push(t);
    open++;
  }
  // A trait impl, or a self type named by a macro argument (`impl $name`),
  // which this scan cannot resolve (see "Macros" above).
  if (open >= end || header.includes("for") || header.includes("$")) return;
  // The self type is the last path segment before any `where` clause.
  const beforeWhere = header.includes("where") ? header.slice(0, header.indexOf("where")) : header;
  const idents = beforeWhere.filter((t) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(t) && t !== "dyn" && t !== "mut");
  const self = idents[idents.length - 1];
  if (!self) return;
  const close = skipBalanced(toks, open) - 1;
  let attrs: string[] = [];
  let k = open + 1;
  while (k < close) {
    const t = toks[k].t;
    if (t === "#" && toks[k + 1]?.t === "[") {
      const e = skipBalanced(toks, k + 1);
      attrs.push(attrText(toks, k + 1, e));
      k = e;
      continue;
    }
    const a = attrs.join(" | ");
    attrs = [];
    const isTest = /\bcfg \( test \)/.test(a) || /\bcfg \( all \( test/.test(a);
    if (t === "pub" && toks[k + 1]?.t === "const" && toks[k + 2]?.t !== "fn" && /^[A-Za-z_]/.test(toks[k + 2]?.t ?? "")) {
      if (!isTest && toks[k + 2].t !== "_")
        mod.items.push({
          name: `${self}::${toks[k + 2].t}`,
          kind: "const",
          file: ctx.at?.file ?? mod.file,
          line: ctx.at?.line ?? toks[k + 2].line,
          gated: false,
        });
      k = skipItem(toks, k + 2, false);
      continue;
    }
    k = skipItem(toks, k);
  }
}

interface Ctx {
  warnings: string[];
  macros: Map<string, Tok[][]>; // macro name → the token bodies of its arms
  expanding: string[]; // macros currently being expanded, to stop recursion
  at?: { file: string; line: number }; // invocation site while expanding
}

// Collect every `macro_rules!` definition in the crate's sources, keyed by
// name, as the token bodies of its arms.
function collectMacros(dir: string, out: Map<string, Tok[][]>) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      collectMacros(p, out);
      continue;
    }
    if (!p.endsWith(".rs")) continue;
    const toks = lex(readFileSync(p, "utf8"));
    for (let i = 0; i + 3 < toks.length; i++) {
      if (toks[i].t !== "macro_rules" || toks[i + 1].t !== "!" || !OPEN[toks[i + 3].t]) continue;
      const name = toks[i + 2].t;
      const end = skipBalanced(toks, i + 3) - 1;
      const arms: Tok[][] = [];
      let j = i + 4;
      while (j < end) {
        if (!OPEN[toks[j].t]) {
          j++;
          continue;
        }
        j = skipBalanced(toks, j); // the matcher
        if (toks[j]?.t !== "=" || toks[j + 1]?.t !== ">" || !OPEN[toks[j + 2]?.t]) break;
        const bEnd = skipBalanced(toks, j + 2);
        arms.push(toks.slice(j + 3, bEnd - 1));
        j = bEnd;
      }
      out.set(name, [...(out.get(name) ?? []), ...arms]);
    }
  }
}

function parseFile(file: string, mod: Mod, ctx: Ctx) {
  const toks = lex(readFileSync(file, "utf8"));
  parseModBody(toks, 0, mod, ctx);
}

// ── public surface ───────────────────────────────────────────────────────

interface PubItem {
  key: string; // file:line, identifies the definition
  item: Item;
  paths: string[][];
}

function collectCrate(srcLib: string, warnings: string[]): Map<string, PubItem> {
  const root: Mod = {
    name: "",
    isPub: true,
    parent: null,
    file: srcLib,
    dir: dirname(srcLib),
    children: new Map(),
    items: [],
    uses: [],
  };
  const macros = new Map<string, Tok[][]>();
  collectMacros(dirname(srcLib), macros);
  parseFile(srcLib, root, { warnings, macros, expanding: [] });

  const out = new Map<string, PubItem>();
  const add = (it: Item, path: string[]) => {
    const key = `${it.file}:${it.line}:${it.name}`;
    const e = out.get(key) ?? { key, item: it, paths: [] };
    e.paths.push(path);
    out.set(key, e);
  };
  const pathOf = (m: Mod): string[] => (m.parent ? [...pathOf(m.parent), m.name] : []);
  const reachable = (m: Mod): boolean => !m.parent || (m.isPub && reachable(m.parent));

  const all: Mod[] = [];
  const walk = (m: Mod) => {
    all.push(m);
    for (const c of m.children.values()) walk(c);
  };
  walk(root);

  // declared items in publicly reachable modules
  for (const m of all) if (reachable(m)) for (const it of m.items) add(it, [...pathOf(m), it.name]);

  // pub use re-exports, resolved inside the crate; iterate so a re-export of a
  // re-export resolves too
  const exportsOf = (m: Mod): Map<string, Item[]> => {
    const r = new Map<string, Item[]>();
    for (const it of m.items) r.set(it.name, [...(r.get(it.name) ?? []), it]);
    return r;
  };
  const reexports = new Map<Mod, Map<string, Item[]>>();
  for (const m of all) reexports.set(m, exportsOf(m));
  const resolveMod = (from: Mod, segs: string[]): Mod | null => {
    let cur: Mod | null = from;
    let k = 0;
    if (segs[0] === "crate") {
      cur = root;
      k = 1;
    } else if (segs[0] === "self") k = 1;
    while (segs[k] === "super") {
      cur = cur?.parent ?? null;
      k++;
    }
    for (; k < segs.length; k++) {
      cur = cur?.children.get(segs[k]) ?? null;
      if (!cur) return null;
    }
    return cur;
  };
  for (let pass = 0; pass < 4; pass++) {
    for (const m of all) {
      for (const u of m.uses) {
        const target = resolveMod(m, u.path.slice(0, -1));
        if (!target) continue; // external crate or unresolvable: not this crate's item
        const last = u.path[u.path.length - 1];
        const tgt = reexports.get(target)!;
        const mine = reexports.get(m)!;
        if (last === "*") {
          for (const [nm, its] of tgt) mine.set(nm, [...new Set([...(mine.get(nm) ?? []), ...its])]);
        } else if (tgt.has(last)) {
          mine.set(u.alias, [...new Set([...(mine.get(u.alias) ?? []), ...tgt.get(last)!])]);
        } else {
          // a module re-exported by name: its items become public under the alias
          const sub = target.children.get(last);
          if (sub) for (const it of sub.items) add(it, [...pathOf(m), u.alias, it.name]);
        }
      }
    }
  }
  for (const m of all) {
    if (!reachable(m)) continue;
    for (const [nm, its] of reexports.get(m)!) for (const it of its) add(it, [...pathOf(m), nm]);
  }
  return out;
}

// ── manifest ─────────────────────────────────────────────────────────────

function manifestNames(text: string): Map<string, Set<string>> {
  const byCrate = new Map<string, Set<string>>();
  let section = "";
  let name: string | null = null;
  for (const raw of text.split("\n")) {
    const top = /^([a-z_]+):/.exec(raw);
    if (top) {
      section = top[1];
      name = null;
      continue;
    }
    if (!["functions", "types", "constants", "error_types"].includes(section)) continue;
    const n = /^  - name:\s*"?([^"#]+?)"?\s*$/.exec(raw);
    if (n) {
      name = n[1].trim();
      continue;
    }
    const m = /^    module:\s*"?([^"#\s]+)"?/.exec(raw);
    if (m && name) {
      const s = byCrate.get(m[1]) ?? new Set();
      s.add(name);
      byCrate.set(m[1], s);
      name = null;
    }
  }
  return byCrate;
}

// ── guard sweep ──────────────────────────────────────────────────────────

/// Public `*_internal` functions plus the extra guarded functions below.
const GUARDED_COUNT = 165;

/// KDF service entry points. These are approved services, so they open with
/// the service gate `require_operational()?`. No other function in the sweep
/// may: an `*_internal` function and an output point a CAST uses must admit
/// `SelfTest`.
const SERVICE_GATED: [string, string][] = [
  ["oxicrypt-kdf/src/lib.rs", "extract"],
  ["oxicrypt-kdf/src/lib.rs", "expand"],
  ["oxicrypt-kdf/src/lib.rs", "derive"],
  ...[
    "tls12_prf",
    "tls12_master_secret",
    "tls12_extended_master_secret",
    "tls13_hkdf_expand_label",
    "tls13_derive_secret",
  ].map((n): [string, string] => ["oxicrypt-tls-kdf/src/lib.rs", n]),
];

/// Guarded functions not named `*_internal`: `[path suffix, name]`.
const GUARDED_EXTRA: [string, string][] = [
  // CSP and public-key accessors.
  ["oxicrypt-ecdsa/src/p256_ecdsa.rs", "private_scalar"],
  ["oxicrypt-ecdsa/src/p384_ecdsa.rs", "private_scalar"],
  ["oxicrypt-eddsa/src/ed25519.rs", "seed"],
  ["oxicrypt-kdf/src/lib.rs", "prk"],
  ["oxicrypt-ecdsa/src/p256_ecdsa.rs", "public_key"],
  ["oxicrypt-ecdsa/src/p384_ecdsa.rs", "public_key"],
  ["oxicrypt-eddsa/src/ed25519.rs", "public_key"],
  ["oxicrypt-rsa/src/lib.rs", "modulus_bytes"],
  ["oxicrypt-rsa/src/lib.rs", "public_exponent"],
  ["oxicrypt-rsa/src/rsa_wide_impl.rs", "modulus_bytes"],
  ["oxicrypt-rsa/src/rsa_wide_impl.rs", "public_exponent"],
  // Hash, XOF and MAC output points.
  ["oxicrypt-sha/src/sha1.rs", "finalize"],
  ["oxicrypt-sha/src/sha224.rs", "finalize"],
  ["oxicrypt-sha/src/sha256.rs", "finalize"],
  ["oxicrypt-sha/src/sha384.rs", "finalize"],
  ["oxicrypt-sha/src/sha512.rs", "finalize"],
  ["oxicrypt-sha/src/sha512_t.rs", "finalize"],
  ["oxicrypt-sha/src/sha3.rs", "finalize"],
  ["oxicrypt-lms/src/hash.rs", "finalize"],
  ["oxicrypt-hmac/src/lib.rs", "finalize"],
  ["oxicrypt-xof/src/lib.rs", "squeeze"],
  ["oxicrypt-xof/src/lib.rs", "finalize_into"],
  ["oxicrypt-cmac/src/cmac.rs", "cmac_tag"],
  // AES block and mode output points.
  ["oxicrypt-aes/src/block.rs", "encrypt_block"],
  ["oxicrypt-aes/src/block.rs", "decrypt_block"],
  ...["ecb_encrypt", "ecb_decrypt", "cbc_encrypt", "cbc_decrypt", "ctr_xor", "gcm_encrypt", "gcm_decrypt"].map(
    (n): [string, string] => ["oxicrypt-aes/src/modes.rs", n],
  ),
  ["oxicrypt-aes/src/ccm.rs", "ccm_encrypt"],
  ["oxicrypt-aes/src/ccm.rs", "ccm_decrypt"],
  ...["kw_wrap", "kw_unwrap", "kwp_wrap", "kwp_unwrap"].flatMap((n): [string, string][] => [
    ["oxicrypt-aes/src/kw.rs", n],
    ["oxicrypt-aes/src/kw.rs", `${n}_inverse_cipher`],
  ]),
  ...SERVICE_GATED,
];

/// Guarded functions a macro defines under a name its caller passes:
/// `[macro path suffix, macro name, metavariable, argument key]`. The
/// definition is the file with that suffix, or failing that the first file
/// holding `macro_rules! <macro>`. The body in the macro is checked once, and
/// each `<argument key> = <name>;` inside a real `<macro>! { ... }`
/// invocation counts as one guarded function, which must be named
/// `*_internal`.
const GUARDED_MACROS: [string, string, string, string][] = [
  ["oxicrypt-rsa/src/keygen_impl.rs", "define_keygen", "$gen", "generate"],
];

/// Returns `src` with every comment and every string, byte-string,
/// raw-string and char literal replaced by spaces, newlines kept, so that
/// offsets and line numbers are unchanged and the sweep reads code only.
///
/// Tracks line comments; block comments, which nest in Rust; `"…"`,
/// `b"…"` and `c"…"` strings with escapes; raw strings `r"…"`, `br"…"`
/// and `cr"…"` with any number of `#`; and char literals `'x'`, `'\n'`,
/// `'\''`, `b'x'`, telling them from lifetimes (`'a`), which stay as code.
function codeOnly(src: string): string {
  const out = src.split("");
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < out.length; k++) if (out[k] !== "\n") out[k] = " ";
  };
  const isIdent = (c: string | undefined) => c !== undefined && /[A-Za-z0-9_]/.test(c);
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      const end = src.indexOf("\n", i);
      const stop = end < 0 ? src.length : end;
      blank(i, stop);
      i = stop;
    } else if (c === "/" && n === "*") {
      let depth = 1;
      let k = i + 2;
      while (k < src.length && depth > 0) {
        if (src[k] === "/" && src[k + 1] === "*") {
          depth++;
          k += 2;
        } else if (src[k] === "*" && src[k + 1] === "/") {
          depth--;
          k += 2;
        } else k++;
      }
      blank(i, k);
      i = k;
    } else if ((c === "r" || ((c === "b" || c === "c") && n === "r")) && !isIdent(src[i - 1])) {
      // A raw string: `r`, optional `b` or `c` before it, then `#`*, then `"`.
      let k = c === "r" ? i + 1 : i + 2;
      let hashes = 0;
      while (src[k] === "#") {
        hashes++;
        k++;
      }
      if (src[k] === '"') {
        const close = '"' + "#".repeat(hashes);
        const end = src.indexOf(close, k + 1);
        const stop = end < 0 ? src.length : end + close.length;
        blank(i, stop);
        i = stop;
      } else i++;
    } else if (c === '"' || ((c === "b" || c === "c") && n === '"' && !isIdent(src[i - 1]))) {
      let k = c === '"' ? i + 1 : i + 2;
      while (k < src.length && src[k] !== '"') k += src[k] === "\\" ? 2 : 1;
      blank(i, k + 1);
      i = k + 1;
    } else if (c === "'" || (c === "b" && n === "'" && !isIdent(src[i - 1]))) {
      // A char literal closes within a few characters; a lifetime does not.
      const q = c === "b" ? i + 1 : i;
      let close = -1;
      if (src[q + 1] === "\\") {
        // Skip the backslash and the escaped character itself, which may
        // be a quote, before looking for the closing one.
        const end = src.indexOf("'", q + 3);
        if (end > 0 && end - q <= 12) close = end;
      } else if (src[q + 2] === "'") close = q + 2;
      else if (src[q + 3] === "'" && /[\uD800-\uDBFF]/.test(src[q + 1] ?? "")) close = q + 3;
      if (close > 0) {
        blank(i, close + 1);
        i = close + 1;
      } else i = q + 1;
    } else i++;
  }
  return out.join("");
}

/// The macro invocations `name! { … }`, `name!( … )` and `name![ … ]`
/// (whitespace allowed before the `!`) in
/// code-only text, each as `[offset of its body, body text]`.
function invocations(code: string, name: string): [number, string][] {
  const found: [number, string][] = [];
  const pairs: Record<string, string> = { "{": "}", "(": ")", "[": "]" };
  for (const m of code.matchAll(new RegExp(`\\b${name}\\s*!\\s*([{(\\[])`, "g"))) {
    const openCh = m[1];
    const closeCh = pairs[openCh];
    const open = m.index! + m[0].length - 1;
    let depth = 0;
    let close = open;
    for (; close < code.length; close++) {
      if (code[close] === openCh) depth++;
      else if (code[close] === closeCh && --depth === 0) break;
    }
    found.push([open + 1, code.slice(open + 1, close)]);
  }
  return found;
}

function rsFiles(dir: string, out: string[]) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) {
      if (e !== "tests" && e !== "target") rsFiles(p, out);
    } else if (e.endsWith(".rs")) out.push(p);
  }
}

/// Returns `[checked, failures]` for every guarded function under `dir`.
function guardSweep(dir: string): [number, string[]] {
  const files: string[] = [];
  rsFiles(dir, files);
  const failures: string[] = [];
  let checked = 0;
  // The SelfTest-admitting guard or its token form (bound by value or by
  // reference). A service entry point in SERVICE_GATED may instead open
  // with the service gate.
  const guard =
    /^(?:(?:oxicrypt_module::)?require_self_test_started\(\)\?;|let \w+ = &?(?:oxicrypt_module::)?require_self_test_started_token\(\)\?;)/;
  const serviceGate = /^(?:oxicrypt_module::)?require_operational\(\)\?;/;
  for (const f of files) {
    const src = codeOnly(readFileSync(f, "utf8"));
    const extra = GUARDED_EXTRA.filter(([suffix]) => f.endsWith(suffix)).map(([, n]) => n);
    const names = ["[a-z0-9_]*_internal", ...extra].join("|");
    // Any `pub` (not `pub(crate)`) function, whatever qualifiers follow and
    // however the declaration is broken across lines. The source is lexed,
    // so an `extern "C"` ABI string reads as whitespace after `extern`; a
    // raw identifier `r#name` is matched by its name.
    const re = new RegExp(
      `\\bpub\\s+(?:(?:const|unsafe|async|extern)\\s+)*fn\\s+(?:r#)?(${names})\\b`,
      "g",
    );
    for (const m of src.matchAll(re)) {
      // The body opens at the first `{` after the parameter list closes.
      let i = src.indexOf("(", m.index!);
      let depth = 0;
      for (; i < src.length; i++) {
        if (src[i] === "(") depth++;
        else if (src[i] === ")" && --depth === 0) break;
      }
      const open = src.indexOf("{", i);
      const body = src.slice(open + 1).replace(/^(?:\s|\/\/[^\n]*\n)*/, "");
      checked++;
      const isService = SERVICE_GATED.some(([suffix, n]) => f.endsWith(suffix) && n === m[1]);
      if (!guard.test(body) && !(isService && serviceGate.test(body))) {
        const line = src.slice(0, m.index!).split("\n").length;
        failures.push(`${f}:${line} ${m[1]}`);
      }
    }
  }
  // Macro-defined guarded functions. The source is read as code only (see
  // `codeOnly`), so text in a comment or a literal is neither a definition
  // nor an invocation; only the body of a real `<macro>!` invocation, with
  // any of its three delimiters, is searched for the argument.
  for (const [suffix, mac, metavar, key] of GUARDED_MACROS) {
    const defs = files.filter(
      (f) => f.endsWith(suffix) || codeOnly(readFileSync(f, "utf8")).includes(`macro_rules! ${mac}`),
    );
    const def = defs[0];
    let guarded = false;
    let found = false;
    if (def) {
      const src = codeOnly(readFileSync(def, "utf8"));
      const esc = metavar.replace(/\$/g, "\\$");
      const m = new RegExp(`\\bpub\\s+fn\\s+${esc}\\s*\\(`).exec(src);
      if (m) {
        found = true;
        let i = src.indexOf("(", m.index);
        let depth = 0;
        for (; i < src.length; i++) {
          if (src[i] === "(") depth++;
          else if (src[i] === ")" && --depth === 0) break;
        }
        const body = src.slice(src.indexOf("{", i) + 1).replace(/^\s*/, "");
        guarded = guard.test(body);
      }
    }
    for (const f of files) {
      const callSrc = codeOnly(readFileSync(f, "utf8"));
      for (const [bodyAt, body] of invocations(callSrc, mac)) {
        for (const inv of body.matchAll(new RegExp(`\\b${key}\\s*=\\s*(?:r#)?(\\w+)\\s*;`, "g"))) {
          checked++;
          if (!found || !guarded || !inv[1].endsWith("_internal")) {
            const line = callSrc.slice(0, bodyAt + inv.index!).split("\n").length;
            failures.push(`${f}:${line} ${inv[1]} (via ${mac}! in ${def ?? "no definition"})`);
          }
        }
      }
    }
  }
  return [checked, failures];
}

function runGuardSweep(dir: string, expected: number): void {
  const [checked, failures] = guardSweep(dir);
  for (const f of failures) console.log(`  ✗ no require_self_test_started()? first: ${f}`);
  if (failures.length || checked !== expected) {
    console.error(
      `check-lama-coverage: FAILED — guard sweep found ${checked} guarded function(s), ` +
        `expected ${expected}; ${failures.length} without the guard first.`,
    );
    process.exit(1);
  }
}

// ── main ─────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
if (args[0] === "--guard-sweep") {
  if (args.length !== 3 || !/^[0-9]+$/.test(args[2])) {
    console.error("usage: bun scripts/check-lama-coverage.ts --guard-sweep <dir> <expected-count>");
    process.exit(2);
  }
  runGuardSweep(args[1], Number(args[2]));
  console.log(`check-lama-coverage: guard sweep passed (${args[2]} guarded functions).`);
  process.exit(0);
}
const list = args.includes("--list");
const rest = args.filter((a) => a !== "--list");
if (rest.some((a) => a.startsWith("-")) || rest.length > 1) {
  console.error("usage: bun scripts/check-lama-coverage.ts [--list] [<repo-root>]");
  process.exit(2);
}
const repo = rest[0] ?? ".";
const fail = (msg: string): never => {
  console.error(`check-lama-coverage: FAILED — ${msg}`);
  process.exit(1);
};

runGuardSweep(join(repo, "crates"), GUARDED_COUNT);

const manifestPath = join(repo, MANIFEST);
if (!existsSync(manifestPath)) fail(`${MANIFEST} not found under ${repo}`);
const covered = manifestNames(readFileSync(manifestPath, "utf8"));
if (covered.size === 0) fail(`no functions/types/constants entries read from ${MANIFEST}; the manifest reader is broken`);

// The roster: every workspace member with a library target that is not
// `publish = false`, wherever it lives in the tree. Read from the root
// manifest's `members` list, so a crate outside `crates/` is not missed.
const rootManifest = join(repo, "Cargo.toml");
if (!existsSync(rootManifest)) fail(`Cargo.toml not found under ${repo}`);
const membersBlock = /^members\s*=\s*\[([^\]]*)\]/m.exec(readFileSync(rootManifest, "utf8"));
if (!membersBlock) fail("no `members = [...]` in the root Cargo.toml; the roster reader is broken");
const members = [...membersBlock![1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
if (members.length === 0) fail("the root Cargo.toml lists no members; the roster reader is broken");
const memberName = new Map<string, string>(); // crate name → member directory
for (const dir of members) {
  const manifest = join(repo, dir, "Cargo.toml");
  if (!existsSync(manifest)) fail(`workspace member ${dir} has no Cargo.toml under ${repo}`);
  const text = readFileSync(manifest, "utf8");
  const name = /^\[package\][^\[]*?^name\s*=\s*"([^"]+)"/ms.exec(text)?.[1];
  if (!name) fail(`no package name in ${dir}/Cargo.toml`);
  if (/^\s*publish\s*=\s*false\b/m.test(text)) continue;
  if (NO_MEMBERS.has(name!)) continue;
  if (!existsSync(join(repo, dir, "src", "lib.rs"))) continue;
  memberName.set(name!, dir);
}
const crates = [...memberName.keys()].sort();
if (crates.length === 0) fail("no publishable library crates found; the roster reader is broken");

const warnings: string[] = [];
const missing: string[] = [];
let scanned = 0;
for (const c of crates) {
  const items = collectCrate(join(repo, memberName.get(c)!, "src", "lib.rs"), warnings);
  // Positive control: every roster crate has a public surface. A crate that
  // yields nothing means the parser lost its place, not that it is empty.
  if (items.size === 0) fail(`found no public items in ${c}; the source scanner is broken`);
  scanned += items.size;
  const names = covered.get(c) ?? new Set<string>();
  const owners = new Map<string, Set<string>>(); // path suffix → items having it
  for (const p of items.values())
    for (const path of p.paths)
      for (let k = 0; k < path.length; k++) {
        const suf = path.slice(k).join("::");
        owners.set(suf, (owners.get(suf) ?? new Set()).add(p.key));
      }
  for (const p of items.values()) {
    const it = p.item;
    if (it.kind === "fn" && ((/_internal$/.test(it.name) && !it.gated) || /(^|_)self_test$/.test(it.name))) continue;
    const hit = p.paths.some((path) =>
      path.some((_, k) => {
        const suf = path.slice(k).join("::");
        return names.has(suf) && (k === 0 || owners.get(suf)!.size === 1);
      }),
    );
    if (!hit) {
      const shortest = p.paths.map((x) => x.join("::")).sort((a, b) => a.length - b.length || a.localeCompare(b))[0];
      missing.push(`${c} ${it.kind} ${shortest}`);
    }
  }
}
missing.sort();
const uniq = [...new Set(missing)];

for (const w of warnings) console.error(`check-lama-coverage: ${w}`);
if (warnings.length) fail(`${warnings.length} module(s) could not be followed; the scan is incomplete`);

if (list) {
  for (const m of uniq) console.log(m);
  process.exit(0);
}

const baselinePath = join(repo, BASELINE);
const baseline = existsSync(baselinePath)
  ? readFileSync(baselinePath, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
  : [];
const base = new Set(baseline);
const have = new Set(uniq);
const added = uniq.filter((m) => !base.has(m));
const stale = baseline.filter((b) => !have.has(b));

for (const m of added) console.log(`  ✗ not in ${MANIFEST}: ${m}`);
for (const s of stale) console.log(`  ✗ stale line in ${BASELINE} (now documented, or no longer public): ${s}`);
if (added.length || stale.length) {
  console.error(
    `check-lama-coverage: FAILED — ${added.length} public item(s) missing from the manifest, ` +
      `${stale.length} stale baseline line(s).`,
  );
  process.exit(1);
}
console.log(
  `check-lama-coverage: passed (${crates.length} crates, ${scanned} public items, ${baseline.length} baselined; ` +
    `${GUARDED_COUNT} guarded functions).`,
);
