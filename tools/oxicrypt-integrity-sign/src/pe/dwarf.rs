//! The part of an image's DWARF debug information the module-statics check
//! reads: each static's name, its location and its size.
//!
//! An image linked by a GNU toolchain carries its debug information in
//! sections of its own. `.debug_info` holds the compilation units, each one
//! tree of debugging information entries whose shape (a tag and a list of
//! attributes, each with a form) `.debug_abbrev` declares, and `.debug_str`
//! the strings an attribute of form `DW_FORM_strp` points into. A static is
//! a `DW_TAG_variable` entry. `DW_AT_name` names it, under the namespaces
//! and types it lies in, `DW_AT_linkage_name` gives its mangled symbol,
//! `DW_AT_location` locates it, and `DW_AT_type` names its type, whose
//! `DW_AT_byte_size` is its size once any typedef and `const`, `volatile`,
//! `restrict` or `_Atomic` qualifier is followed; an array with none is
//! its element's size times its subranges' counts. A definition that names
//! nothing itself takes its name, linkage name and type from the
//! declaration its `DW_AT_specification` or `DW_AT_abstract_origin` names,
//! a `DW_TAG_member` declaring a static member among them. A variable
//! marked `DW_AT_declaration` has no storage in the image. A variable with
//! no `DW_AT_location` is skipped as having none, on the assumption that
//! the compiler never leaves a static with storage unlocated. A variable under a function is a static like any other,
//! unless it is the function's local: located by anything but a lone
//! `DW_OP_addr`, with no linkage name and not external.
//!
//! Only version 4 units with 32-bit offsets and 8-byte addresses are read,
//! and only the forms in [`FORMS`]. Reading past an attribute needs its
//! size, which only its form gives, so a unit whose abbreviations use any
//! other form is refused (`DwarfForm`) rather than skipped. Any other
//! malformation, including a unit that is not exactly one closed tree, or a
//! unit of another version or shape, is refused as `NoDwarf`. Zero bytes
//! after the last unit are section padding.

use std::collections::BTreeMap;

/// `DW_TAG_variable`.
const TAG_VARIABLE: u64 = 0x34;
/// `DW_TAG_namespace`.
const TAG_NAMESPACE: u64 = 0x39;
/// The type tags a size is looked through to the type they name:
/// `DW_TAG_typedef`, `DW_TAG_const_type`, `DW_TAG_volatile_type`,
/// `DW_TAG_restrict_type` and `DW_TAG_atomic_type`.
const TYPE_ALIASES: [u64; 5] = [0x16, 0x26, 0x35, 0x37, 0x47];
/// How many aliases a size is looked through before the chain is taken to
/// give none.
const ALIAS_DEPTH: usize = 16;
/// `DW_TAG_member`, which declares a static member of a type.
const TAG_MEMBER: u64 = 0x0d;
/// `DW_TAG_array_type` and the `DW_TAG_subrange_type` entries under it.
const TAG_ARRAY: u64 = 0x01;
const TAG_SUBRANGE: u64 = 0x21;
/// The tags whose entries scope a static member: `DW_TAG_structure_type`,
/// `DW_TAG_class_type` and `DW_TAG_union_type`.
const TYPE_SCOPES: [u64; 3] = [0x13, 0x02, 0x17];
/// How many declarations a definition's identity is followed through.
const IDENTITY_DEPTH: usize = 16;
/// `DW_AT_specification` and `DW_AT_abstract_origin`, which point a
/// definition at the declaration it completes.
const AT_SPECIFICATION: u64 = 0x47;
const AT_ABSTRACT_ORIGIN: u64 = 0x31;
/// `DW_AT_declaration` and `DW_AT_external`.
const AT_DECLARATION: u64 = 0x3c;
const AT_EXTERNAL: u64 = 0x3f;
/// `DW_AT_count`, `DW_AT_lower_bound` and `DW_AT_upper_bound`.
const AT_COUNT: u64 = 0x37;
const AT_LOWER_BOUND: u64 = 0x22;
const AT_UPPER_BOUND: u64 = 0x2f;
/// `DW_AT_byte_size`.
const AT_BYTE_SIZE: u64 = 0x0b;
/// `DW_AT_type`.
const AT_TYPE: u64 = 0x49;
/// `DW_AT_location`.
const AT_LOCATION: u64 = 0x02;
/// `DW_AT_name`.
const AT_NAME: u64 = 0x03;
/// `DW_AT_linkage_name`.
const AT_LINKAGE_NAME: u64 = 0x6e;
/// `DW_OP_addr`, followed by an address.
pub(crate) const OP_ADDR: u8 = 0x03;

/// The forms the reader handles.
const FORM_ADDR: u64 = 0x01;
const FORM_DATA2: u64 = 0x05;
const FORM_DATA4: u64 = 0x06;
const FORM_DATA8: u64 = 0x07;
const FORM_STRING: u64 = 0x08;
const FORM_BLOCK1: u64 = 0x0a;
const FORM_DATA1: u64 = 0x0b;
const FORM_SDATA: u64 = 0x0d;
const FORM_STRP: u64 = 0x0e;
const FORM_UDATA: u64 = 0x0f;
const FORM_REF4: u64 = 0x13;
const FORM_SEC_OFFSET: u64 = 0x17;
const FORM_EXPRLOC: u64 = 0x18;
const FORM_FLAG_PRESENT: u64 = 0x19;
pub(crate) const FORMS: [u64; 14] = [
    FORM_ADDR,
    FORM_DATA2,
    FORM_DATA4,
    FORM_DATA8,
    FORM_STRING,
    FORM_BLOCK1,
    FORM_DATA1,
    FORM_SDATA,
    FORM_STRP,
    FORM_UDATA,
    FORM_REF4,
    FORM_SEC_OFFSET,
    FORM_EXPRLOC,
    FORM_FLAG_PRESENT,
];

/// The only unit version read.
const VERSION: u16 = 4;
/// The only address size read.
const ADDRESS_SIZE: u8 = 8;
/// Unit lengths from here up are reserved, or announce 64-bit DWARF.
const LENGTH_RESERVED: u32 = 0xffff_fff0;
/// The bytes of a version 4 unit header after its length.
const HEADER_AFTER_LENGTH: usize = 7;

/// The debug sections the reader takes, each the section's bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sections<'a> {
    /// `.debug_info`.
    pub(crate) info: &'a [u8],
    /// `.debug_abbrev`.
    pub(crate) abbrev: &'a [u8],
    /// `.debug_str`, when the image has one.
    pub(crate) str: Option<&'a [u8]>,
}

/// Where a variable's `DW_AT_location` puts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Location {
    /// The entry has no `DW_AT_location`, taken to mean no storage was
    /// emitted.
    Absent,
    /// A single `DW_OP_addr` and its address.
    Addr(u64),
    /// Anything else, described for a refusal: another expression, a
    /// location list or a block.
    Other(String),
}

/// A static the debug information describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Variable {
    /// Its path: the enclosing namespaces' names and its own, joined by
    /// `::`.
    pub(crate) path: String,
    /// Its mangled symbol, when the entry gives one.
    pub(crate) linkage: Option<String>,
    /// Where its location puts it.
    pub(crate) location: Location,
    /// Its type's size in bytes, when the type gives one.
    pub(crate) size: Option<u64>,
}

#[cfg(test)]
impl Variable {
    /// The address a lone `DW_OP_addr` gives, if that is its location.
    pub(crate) const fn addr(&self) -> Option<u64> {
        match self.location {
            Location::Addr(a) => Some(a),
            _ => None,
        }
    }
}

/// A position in one section.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .ok_or("NoDwarf: an offset in the debug information overflows")?;
        let out = self
            .bytes
            .get(self.at..end)
            .ok_or("NoDwarf: the debug information runs past the end of its section")?;
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| "NoDwarf: truncated debug information".to_owned())
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes(
            b.try_into().map_err(|_| "NoDwarf: truncated field")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(
            b.try_into().map_err(|_| "NoDwarf: truncated field")?,
        ))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(
            b.try_into().map_err(|_| "NoDwarf: truncated field")?,
        ))
    }

    /// An unsigned LEB128 number of at most 64 bits.
    fn uleb(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            let low = u64::from(b & 0x7f);
            if shift == 63 && low > 1 {
                return Err("NoDwarf: a LEB128 number exceeds 64 bits".to_owned());
            }
            value |= low << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("NoDwarf: a LEB128 number exceeds 64 bits".to_owned())
    }

    /// Steps over a LEB128 number of at most ten bytes, signed or not.
    fn skip_leb(&mut self) -> Result<(), String> {
        for _ in 0..10 {
            if self.u8()? & 0x80 == 0 {
                return Ok(());
            }
        }
        Err("NoDwarf: a LEB128 number exceeds 64 bits".to_owned())
    }

    /// A NUL-terminated string, without its terminator.
    fn cstr(&mut self) -> Result<&'a [u8], String> {
        let rest = self.bytes.get(self.at..).unwrap_or(&[]);
        let n = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or("NoDwarf: a string in the debug information is not terminated")?;
        let s = self.take(n)?;
        self.take(1)?;
        Ok(s)
    }
}

/// One abbreviation: the tag, whether entries have children, and each
/// attribute's name and form.
struct Abbrev {
    tag: u64,
    children: bool,
    attrs: Vec<(u64, u64)>,
}

/// One table of `.debug_abbrev`: where it ends, and each declaration by
/// code with the offset it starts at.
struct Table {
    end: usize,
    decls: BTreeMap<u64, (usize, Abbrev)>,
}

/// Every abbreviation table in `.debug_abbrev`, read once, start to end,
/// each keyed by the offset it starts at.
///
/// A unit names the offset its abbreviations start at: a table's start, or
/// a declaration inside one, which then begins the unit's table. Reading
/// the section once bounds the work and the memory by its length, whatever
/// offsets the units name.
struct Tables {
    tables: BTreeMap<usize, Table>,
    /// Each declaration's start, and the start of the table holding it.
    starts: BTreeMap<usize, usize>,
}

impl Tables {
    fn parse(section: &[u8]) -> Result<Self, String> {
        let mut cur = Cursor::new(section, 0);
        let mut tables = BTreeMap::new();
        let mut starts = BTreeMap::new();
        while cur.at < section.len() {
            let table_at = cur.at;
            let mut decls = BTreeMap::new();
            loop {
                let decl_at = cur.at;
                let code = cur.uleb()?;
                if code == 0 {
                    break;
                }
                let tag = cur.uleb()?;
                let children = match cur.u8()? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(format!(
                            "NoDwarf: abbreviation {code} has children flag {other}"
                        ));
                    }
                };
                let mut attrs = Vec::new();
                loop {
                    let name = cur.uleb()?;
                    let form = cur.uleb()?;
                    if name == 0 && form == 0 {
                        break;
                    }
                    if !FORMS.contains(&form) {
                        return Err(format!(
                            "DwarfForm: abbreviation {code} gives attribute {name:#x} form \
                             {form:#x}, which this reader does not handle"
                        ));
                    }
                    attrs.push((name, form));
                }
                let abbrev = Abbrev {
                    tag,
                    children,
                    attrs,
                };
                if decls.insert(code, (decl_at, abbrev)).is_some() {
                    return Err(format!("NoDwarf: abbreviation {code} is declared twice"));
                }
                starts.insert(decl_at, table_at);
            }
            tables.insert(table_at, Table { end: cur.at, decls });
        }
        Ok(Self { tables, starts })
    }

    /// The table a unit whose abbreviations start at `offset` reads, and
    /// that offset: the declarations of the table holding it from there on.
    fn at(&self, offset: usize) -> Result<(&Table, usize), String> {
        let table_at = if self.tables.contains_key(&offset) {
            offset
        } else {
            *self.starts.get(&offset).ok_or_else(|| {
                format!(
                    "NoDwarf: a unit's abbreviations start at {offset:#x}, where no table or \
                     declaration does"
                )
            })?
        };
        let table = self
            .tables
            .get(&table_at)
            .ok_or("NoDwarf: an abbreviation table was not kept")?;
        Ok((table, offset))
    }
}

/// The abbreviation a unit reading `table` from `from` declares as `code`.
fn declared(table: &Table, from: usize, code: u64) -> Option<&Abbrev> {
    table
        .decls
        .get(&code)
        .filter(|(at, _)| *at >= from && *at < table.end)
        .map(|(_, a)| a)
}

/// An attribute value the reader keeps.
enum Value<'a> {
    Str(&'a [u8]),
    Expr(&'a [u8]),
    /// A constant of a fixed-size or unsigned form.
    Num(u64),
    /// A `DW_FORM_ref4` offset from the unit's start.
    Ref(u64),
    Other,
}

/// Reads one attribute value of `form`.
fn value<'a>(
    cur: &mut Cursor<'a>,
    form: u64,
    strings: Option<&'a [u8]>,
) -> Result<Value<'a>, String> {
    let fixed = |cur: &mut Cursor<'a>, n: usize| cur.take(n).map(|_| Value::Other);
    match form {
        FORM_FLAG_PRESENT => Ok(Value::Other),
        FORM_DATA1 => cur.u8().map(|v| Value::Num(v.into())),
        FORM_DATA2 => cur.u16().map(|v| Value::Num(v.into())),
        FORM_DATA4 => cur.u32().map(|v| Value::Num(v.into())),
        FORM_REF4 => cur.u32().map(|v| Value::Ref(v.into())),
        FORM_SEC_OFFSET => fixed(cur, 4),
        FORM_DATA8 => cur.u64().map(Value::Num),
        FORM_ADDR => fixed(cur, 8),
        FORM_UDATA => cur.uleb().map(Value::Num),
        FORM_SDATA => cur.skip_leb().map(|()| Value::Other),
        FORM_STRING => cur.cstr().map(Value::Str),
        FORM_STRP => {
            let off = usize::try_from(cur.u32()?).map_err(|_| "NoDwarf: offset overflows")?;
            let strings = strings.ok_or(
                "NoDwarf: an attribute points into .debug_str, which the image does not carry",
            )?;
            Cursor::new(strings, off).cstr().map(Value::Str)
        }
        FORM_BLOCK1 => {
            let n = usize::from(cur.u8()?);
            fixed(cur, n)
        }
        FORM_EXPRLOC => {
            let n = usize::try_from(cur.uleb()?).map_err(|_| "NoDwarf: length overflows")?;
            cur.take(n).map(Value::Expr)
        }
        _ => Err(format!(
            "DwarfForm: form {form:#x} is not one this reader handles"
        )),
    }
}

/// An entry with children, as the path of the entries under it sees it,
/// and its offset from the unit's start.
struct Scope {
    kind: ScopeKind,
    offset: u64,
}

/// What an entry with children is to the entries under it.
enum ScopeKind {
    Unit,
    Namespace(String),
    /// A structure, class or union, which can declare static members.
    Type(String),
    Other,
}

/// The string an attribute names, refused when its form is not a string.
fn text(v: &Value<'_>, what: &str) -> Result<String, String> {
    match v {
        Value::Str(s) => String::from_utf8(s.to_vec())
            .map_err(|_| format!("NoDwarf: a {what} in the debug information is not UTF-8")),
        _ => Err(format!("NoDwarf: a {what} is not of a string form")),
    }
}

/// Every static the units in `sections` describe, in the order of their
/// entries.
///
/// # Errors
///
/// `DwarfForm` when an abbreviation uses a form the reader does not handle,
/// and `NoDwarf` when `.debug_info` holds no unit, any unit is malformed or
/// not a version 4 unit with 32-bit offsets and 8-byte addresses, or a
/// variable with a location has nothing to name it.
pub(crate) fn variables(sections: &Sections<'_>) -> Result<Vec<Variable>, String> {
    let mut out = Vec::new();
    let mut cur = Cursor::new(sections.info, 0);
    let mut units = 0usize;
    let tables = Tables::parse(sections.abbrev)?;
    while cur.at < sections.info.len() {
        if units > 0
            && sections
                .info
                .get(cur.at..)
                .is_some_and(|rest| rest.iter().all(|&b| b == 0))
        {
            break;
        }
        let start = cur.at;
        let length = cur.u32()?;
        if length >= LENGTH_RESERVED {
            return Err(format!(
                "NoDwarf: the unit at {start:#x} is 64-bit DWARF or has a reserved length"
            ));
        }
        let length = usize::try_from(length).map_err(|_| "NoDwarf: length overflows")?;
        if length < HEADER_AFTER_LENGTH {
            return Err(format!(
                "NoDwarf: the unit at {start:#x} is shorter than its header"
            ));
        }
        let end = cur
            .at
            .checked_add(length)
            .filter(|&e| e <= sections.info.len())
            .ok_or_else(|| format!("NoDwarf: the unit at {start:#x} runs past .debug_info"))?;
        let version = cur.u16()?;
        if version != VERSION {
            return Err(format!(
                "NoDwarf: the unit at {start:#x} is DWARF version {version}; only version \
                 {VERSION} is read"
            ));
        }
        let abbrev_off = usize::try_from(cur.u32()?).map_err(|_| "NoDwarf: offset overflows")?;
        let address_size = cur.u8()?;
        if address_size != ADDRESS_SIZE {
            return Err(format!(
                "NoDwarf: the unit at {start:#x} has {address_size}-byte addresses"
            ));
        }
        let (table, from) = tables.at(abbrev_off)?;
        let mut unit = Cursor::new(
            sections
                .info
                .get(..end)
                .ok_or("NoDwarf: the unit runs past .debug_info")?,
            cur.at,
        );
        entries(&mut unit, start, (table, from), sections.str, &mut out)?;
        cur.at = end;
        units = units.saturating_add(1);
    }
    if units == 0 {
        return Err("NoDwarf: .debug_info holds no unit".to_owned());
    }
    Ok(out)
}

/// What a type entry gives a size lookup: its tag, its `DW_AT_byte_size`,
/// the type its `DW_AT_type` names as an offset from the unit's start, and
/// for an array each subrange's count, lower bound and upper bound.
struct TypeEntry {
    tag: u64,
    size: Option<u64>,
    target: Option<u64>,
    subranges: Vec<(Option<u64>, Option<u64>, Option<u64>)>,
}

/// The size of the type at `offset`: its `DW_AT_byte_size`, looked
/// through typedefs and qualifiers, or for an array without one its
/// element's size times each subrange's count (its `DW_AT_count`, or its
/// upper bound less its lower bound, zero when absent, plus one). `None`
/// when the chain ends without either, or runs deeper than `depth`.
fn size_of(types: &BTreeMap<u64, TypeEntry>, offset: u64, depth: usize) -> Option<u64> {
    let depth = depth.checked_sub(1)?;
    let t = types.get(&offset)?;
    if let Some(size) = t.size {
        return Some(size);
    }
    if t.tag == TAG_ARRAY {
        if t.subranges.is_empty() {
            return None;
        }
        let mut size = size_of(types, t.target?, depth)?;
        for &(count, lower, upper) in &t.subranges {
            let n = match (count, upper) {
                (Some(n), _) => n,
                (None, Some(upper)) => upper.checked_sub(lower.unwrap_or(0))?.checked_add(1)?,
                (None, None) => return None,
            };
            size = size.checked_mul(n)?;
        }
        return Some(size);
    }
    if TYPE_ALIASES.contains(&t.tag) {
        return size_of(types, t.target?, depth);
    }
    None
}

/// Where an expression puts a variable: a lone `DW_OP_addr`, or another
/// expression the reader does not evaluate.
fn location_of(expr: &[u8]) -> Location {
    match expr.split_first() {
        Some((&OP_ADDR, a)) if a.len() == 8 => {
            let mut word = [0u8; 8];
            word.copy_from_slice(a);
            Location::Addr(u64::from_le_bytes(word))
        }
        _ => {
            let hex: Vec<String> = expr.iter().map(|b| format!("{b:02x}")).collect();
            Location::Other(format!("the expression {}", hex.join(" ")))
        }
    }
}

/// A variable or member entry as read, before a definition takes the
/// identity of the declaration it names.
struct Raw {
    tag: u64,
    name: Option<String>,
    linkage: Option<String>,
    location: Location,
    target: Option<u64>,
    /// The declaration its `DW_AT_specification` or `DW_AT_abstract_origin`
    /// names.
    refers: Option<u64>,
    declaration: bool,
    external: bool,
    /// The names of the namespaces and types it lies in.
    scope: Vec<String>,
    nested: bool,
}

/// Appends the statics among the entries of the unit that starts at
/// `start` in `.debug_info`.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over a unit's entries; each check sits beside the field it reads"
)]
fn entries<'a>(
    cur: &mut Cursor<'a>,
    start: usize,
    (table, from): (&Table, usize),
    strings: Option<&'a [u8]>,
    out: &mut Vec<Variable>,
) -> Result<(), String> {
    let mut scopes: Vec<Scope> = Vec::new();
    let mut rooted = false;
    let mut types: BTreeMap<u64, TypeEntry> = BTreeMap::new();
    let mut raws: BTreeMap<u64, Raw> = BTreeMap::new();
    while cur.at < cur.bytes.len() {
        let offset = u64::try_from(cur.at.saturating_sub(start))
            .map_err(|_| "NoDwarf: an offset overflows")?;
        let code = cur.uleb()?;
        if code == 0 {
            // The end of a sibling list, or padding after the root closes.
            if scopes.pop().is_none() && !rooted {
                return Err(format!(
                    "NoDwarf: the unit at {start:#x} begins with a null entry"
                ));
            }
            continue;
        }
        if scopes.is_empty() && rooted {
            return Err(format!(
                "NoDwarf: the unit at {start:#x} has an entry after its root closes"
            ));
        }
        let abbrev = declared(table, from, code).ok_or_else(|| {
            format!("NoDwarf: an entry uses abbreviation {code}, which its table does not declare")
        })?;
        let mut name = None;
        let mut linkage = None;
        let mut location = Location::Absent;
        let (mut size, mut target, mut refers) = (None, None, None);
        let (mut count, mut lower, mut upper) = (None, None, None);
        let (mut declaration, mut external) = (false, false);
        for &(attr, form) in &abbrev.attrs {
            let v = value(cur, form, strings)?;
            match (attr, v) {
                (AT_NAME, v) => name = Some(text(&v, "name")?),
                (AT_LINKAGE_NAME, v) => linkage = Some(text(&v, "linkage name")?),
                (AT_LOCATION, Value::Expr(e)) => location = location_of(e),
                (AT_LOCATION, _) => {
                    location = Location::Other(format!("an attribute of form {form:#x}"));
                }
                (AT_BYTE_SIZE, Value::Num(n)) => size = Some(n),
                (AT_TYPE, Value::Ref(r)) => target = Some(r),
                (AT_SPECIFICATION | AT_ABSTRACT_ORIGIN, Value::Ref(r)) => refers = Some(r),
                (AT_DECLARATION, _) => declaration = true,
                (AT_EXTERNAL, _) => external = true,
                (AT_COUNT, Value::Num(n)) => count = Some(n),
                (AT_LOWER_BOUND, Value::Num(n)) => lower = Some(n),
                (AT_UPPER_BOUND, Value::Num(n)) => upper = Some(n),
                _ => {}
            }
        }
        if scopes.is_empty() {
            rooted = true;
        }
        let at_top = scopes
            .first()
            .is_some_and(|s| matches!(s.kind, ScopeKind::Unit))
            && scopes
                .iter()
                .skip(1)
                .all(|s| matches!(s.kind, ScopeKind::Namespace(_)));
        match abbrev.tag {
            TAG_VARIABLE | TAG_MEMBER => {
                let scope = scopes
                    .iter()
                    .filter_map(|s| match &s.kind {
                        ScopeKind::Namespace(n) | ScopeKind::Type(n) => Some(n.clone()),
                        _ => None,
                    })
                    .collect();
                raws.insert(
                    offset,
                    Raw {
                        tag: abbrev.tag,
                        name: name.clone(),
                        linkage,
                        location,
                        target,
                        refers,
                        declaration,
                        external,
                        scope,
                        nested: !at_top,
                    },
                );
            }
            TAG_SUBRANGE => {
                if let Some(array) = scopes.last().and_then(|s| types.get_mut(&s.offset)) {
                    array.subranges.push((count, lower, upper));
                }
            }
            tag => {
                types.insert(
                    offset,
                    TypeEntry {
                        tag,
                        size,
                        target,
                        subranges: Vec::new(),
                    },
                );
            }
        }
        if abbrev.children {
            let kind = if scopes.is_empty() {
                ScopeKind::Unit
            } else if abbrev.tag == TAG_NAMESPACE {
                ScopeKind::Namespace(name.unwrap_or_default())
            } else if TYPE_SCOPES.contains(&abbrev.tag) {
                ScopeKind::Type(name.unwrap_or_default())
            } else {
                ScopeKind::Other
            };
            scopes.push(Scope { kind, offset });
        }
    }
    if !rooted {
        return Err(format!("NoDwarf: the unit at {start:#x} holds no entry"));
    }
    if !scopes.is_empty() {
        return Err(format!(
            "NoDwarf: the unit at {start:#x} ends with {} entries still open",
            scopes.len()
        ));
    }
    for (offset, raw) in &raws {
        if raw.tag != TAG_VARIABLE {
            continue;
        }
        if raw.declaration && raw.location != Location::Absent {
            return Err(format!(
                "NoDwarf: the variable at {:#x} is both a declaration and located",
                offset.saturating_add(start as u64)
            ));
        }
        // A definition that names no static itself takes the identity of
        // the declaration it completes.
        let (mut name, mut linkage, mut target) =
            (raw.name.clone(), raw.linkage.clone(), raw.target);
        let mut scope = raw.scope.clone();
        let mut external = raw.external;
        let mut next = raw.refers;
        // The declaration's scope is the static's, wherever the definition
        // lies: the first declaration that names it gives it.
        let mut scope_taken = false;
        for _ in 0..IDENTITY_DEPTH {
            let Some(d) = next.and_then(|r| raws.get(&r)) else {
                break;
            };
            if name.is_none() {
                name.clone_from(&d.name);
            }
            if !scope_taken && d.name.is_some() {
                scope.clone_from(&d.scope);
                scope_taken = true;
            }
            if linkage.is_none() {
                linkage.clone_from(&d.linkage);
            }
            target = target.or(d.target);
            external |= d.external;
            next = d.refers;
        }
        let stored = raw.location != Location::Absent;
        let named = name.is_some() || linkage.is_some();
        // A function's local: located on its stack or in its registers,
        // with no symbol of its own.
        if raw.nested
            && !matches!(raw.location, Location::Addr(_))
            && linkage.is_none()
            && !external
        {
            continue;
        }
        if !stored && (raw.nested || raw.refers.is_some() || !named) {
            continue;
        }
        if stored && !named {
            return Err(format!(
                "NoDwarf: the variable at {:#x} has a location but nothing names it",
                offset.saturating_add(start as u64)
            ));
        }
        scope.extend(name);
        out.push(Variable {
            path: scope.join("::"),
            linkage,
            location: raw.location.clone(),
            size: target.and_then(|t| size_of(&types, t, ALIAS_DEPTH)),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]
pub(crate) mod tests {
    use super::{
        AT_LINKAGE_NAME, AT_LOCATION, AT_NAME, FORM_ADDR, FORM_BLOCK1, FORM_DATA1, FORM_DATA2,
        FORM_DATA4, FORM_DATA8, FORM_EXPRLOC, FORM_FLAG_PRESENT, FORM_REF4, FORM_SDATA,
        FORM_SEC_OFFSET, FORM_STRING, FORM_STRP, FORM_UDATA, FORMS, OP_ADDR, Sections,
        TAG_NAMESPACE, TAG_VARIABLE, variables,
    };

    /// `DW_TAG_compile_unit`.
    const TAG_UNIT: u8 = 0x11;
    /// `DW_TAG_subprogram`.
    const TAG_SUBPROGRAM: u8 = 0x2e;
    /// `DW_TAG_base_type`, `DW_TAG_structure_type`, `DW_TAG_typedef` and
    /// `DW_TAG_const_type`.
    const TAG_BASE: u8 = 0x24;
    const TAG_STRUCT: u8 = 0x13;
    const TAG_TYPEDEF: u8 = 0x16;
    const TAG_CONST: u8 = 0x26;
    /// `DW_AT_type` and `DW_AT_byte_size`.
    const AT_TYPE: u8 = 0x49;
    const AT_BYTE_SIZE: u8 = 0x0b;
    /// Abbreviation codes, from the base of the unit's table.
    const UNIT: u8 = 0;
    const NAMESPACE: u8 = 1;
    const VARIABLE: u8 = 2;
    const VARIABLE_NO_LINKAGE: u8 = 3;
    const VARIABLE_NO_LOCATION: u8 = 4;
    const FUNCTION: u8 = 5;
    const LOCAL: u8 = 6;
    const BASE: u8 = 7;
    const UNSIZED: u8 = 8;
    const TYPEDEF: u8 = 9;
    const CONST: u8 = 10;
    const ARRAY: u8 = 11;
    const SUBRANGE_COUNT: u8 = 12;
    const SUBRANGE_BOUNDS: u8 = 13;
    const DECLARATION: u8 = 14;
    const DEFINITION_OF: u8 = 15;
    const INSTANCE_OF: u8 = 16;
    const TYPE_SCOPE: u8 = 17;
    const MEMBER: u8 = 18;
    const DECLARATION_UNLINKED: u8 = 19;
    const DEFINITION_NAMED: u8 = 20;
    const VARIABLE_INTERNAL: u8 = 21;
    const VARIABLE_DECLARED: u8 = 22;
    /// `DW_TAG_array_type`, `DW_TAG_subrange_type` and `DW_TAG_member`.
    const TAG_ARRAY: u8 = 0x01;
    const TAG_SUBRANGE: u8 = 0x21;
    const TAG_MEMBER: u8 = 0x0d;
    /// `DW_AT_specification`, `DW_AT_abstract_origin`, `DW_AT_declaration`,
    /// `DW_AT_external`, `DW_AT_count`, `DW_AT_lower_bound` and
    /// `DW_AT_upper_bound`.
    const AT_SPECIFICATION: u8 = 0x47;
    const AT_ABSTRACT_ORIGIN: u8 = 0x31;
    const AT_DECLARATION: u8 = 0x3c;
    const AT_EXTERNAL: u8 = 0x3f;
    const AT_COUNT: u8 = 0x37;
    const AT_LOWER: u8 = 0x22;
    const AT_UPPER: u8 = 0x2f;

    /// The shape of a static's type: its size alone, or an array of
    /// elements of that size with a count, or with bounds.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Shape {
        Plain,
        Count(u8),
        Bounds(u8, u8),
    }

    /// How a static's entries are split: one entry, or a declaration that
    /// names it and a definition elsewhere that locates it, pointing at the
    /// declaration by `DW_AT_specification` or `DW_AT_abstract_origin`, or
    /// one that repeats its name outside the declaration's namespaces, or a
    /// static member declared inside a type.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Split {
        Whole,
        Specification,
        Origin,
        NamedSpecification,
        Member,
    }

    /// Where a static's location says it is.
    #[derive(Clone, Debug)]
    pub(crate) enum Loc {
        /// A single `DW_OP_addr`.
        Addr(u64),
        /// Another expression.
        Expr(Vec<u8>),
        /// No `DW_AT_location`.
        Absent,
    }

    /// A static to describe.
    #[derive(Clone, Debug)]
    pub(crate) struct Static {
        /// Its namespaces, then its name.
        pub(crate) path: Vec<String>,
        pub(crate) linkage: Option<String>,
        pub(crate) loc: Loc,
        /// The byte size its type gives, through a `const` and a typedef;
        /// `None` for a type that declares no size.
        pub(crate) size: Option<u8>,
        /// The unit it is described in, 0 or 1.
        pub(crate) unit: usize,
        /// Described under a function rather than directly under its
        /// namespaces.
        pub(crate) nested: bool,
        pub(crate) shape: Shape,
        pub(crate) split: Split,
        /// Not marked `DW_AT_external`, and with none of the other
        /// attributes ahead of its location.
        pub(crate) internal: bool,
        /// Marked `DW_AT_declaration` although located.
        pub(crate) declared: bool,
    }

    impl Static {
        pub(crate) fn new(path: &str, linkage: Option<&str>, loc: Loc, size: Option<u8>) -> Self {
            Self {
                path: path.split("::").map(str::to_owned).collect(),
                linkage: linkage.map(str::to_owned),
                loc,
                size,
                unit: 0,
                nested: false,
                shape: Shape::Plain,
                split: Split::Whole,
                internal: false,
                declared: false,
            }
        }

        pub(crate) const fn internal(mut self) -> Self {
            self.internal = true;
            self
        }

        pub(crate) const fn declared(mut self) -> Self {
            self.declared = true;
            self
        }

        pub(crate) const fn shaped(mut self, shape: Shape) -> Self {
            self.shape = shape;
            self
        }

        pub(crate) const fn split(mut self, split: Split) -> Self {
            self.split = split;
            self
        }

        pub(crate) const fn in_unit(mut self, unit: usize) -> Self {
            self.unit = unit;
            self
        }

        pub(crate) const fn nested(mut self) -> Self {
            self.nested = true;
            self
        }
    }

    /// Every handled form but `DW_FORM_strp`, `DW_FORM_ref4` and
    /// `DW_FORM_exprloc` as one attribute each, ahead of a static's location
    /// and linkage name, so a wrong size for any of them moves both.
    const FILLER: [(u8, u64); 11] = [
        (0x3a, FORM_DATA1),
        (0x3b, FORM_DATA2),
        (0x39, FORM_DATA4),
        (0x1c, FORM_DATA8),
        (0x5a, FORM_STRING),
        (0x2a, FORM_BLOCK1),
        (0x0d, FORM_SDATA),
        (0x0f, FORM_UDATA),
        (0x11, FORM_ADDR),
        (0x10, FORM_SEC_OFFSET),
        (0x3f, FORM_FLAG_PRESENT),
    ];

    /// The values of [`FILLER`], in order, among them a two-byte block, a
    /// negative ten-byte `sdata` and a three-byte `udata`.
    fn filler() -> Vec<u8> {
        let mut b = vec![0x5a];
        b.extend(0x1234u16.to_le_bytes());
        b.extend(0xdead_beefu32.to_le_bytes());
        // A zero in the upper half: read short, the string after it ends early.
        b.extend(0x0011_2233_4455_6677u64.to_le_bytes());
        b.extend(b"doc\0");
        b.extend([2, 0xaa, 0xbb]);
        b.extend([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f]);
        b.extend([0xe5, 0x8e, 0x26]);
        b.extend(0x1_8000_1000u64.to_le_bytes());
        b.extend(0x40u32.to_le_bytes());
        b
    }

    /// One abbreviation table, its codes counted from `base`.
    pub(crate) fn abbrev_table(base: u8) -> Vec<u8> {
        let mut a = Vec::new();
        let mut decl = |code: u8, tag: u8, children: u8, attrs: &[(u8, u64)]| {
            a.extend_from_slice(&[base + code, tag, children]);
            for &(n, f) in attrs {
                a.extend_from_slice(&[n, f as u8]);
            }
            a.extend_from_slice(&[0, 0]);
        };
        let (name, link, loc) = (AT_NAME as u8, AT_LINKAGE_NAME as u8, AT_LOCATION as u8);
        decl(
            UNIT,
            TAG_UNIT,
            1,
            &[
                (name, FORM_STRP),
                (0x25, FORM_STRING),
                (0x13, FORM_DATA2),
                (0x10, FORM_SEC_OFFSET),
                (0x11, FORM_ADDR),
                (0x12, FORM_DATA4),
            ],
        );
        decl(NAMESPACE, TAG_NAMESPACE as u8, 1, &[(name, FORM_STRP)]);
        let mut variable = vec![(name, FORM_STRP), (AT_TYPE, FORM_REF4)];
        variable.extend(FILLER);
        variable.push((0x40, FORM_EXPRLOC));
        let mut full = variable.clone();
        full.extend([(loc, FORM_EXPRLOC), (link, FORM_STRP)]);
        decl(VARIABLE, TAG_VARIABLE as u8, 0, &full);
        let mut no_linkage = variable.clone();
        no_linkage.push((loc, FORM_EXPRLOC));
        decl(VARIABLE_NO_LINKAGE, TAG_VARIABLE as u8, 0, &no_linkage);
        let mut no_location = variable;
        no_location.push((link, FORM_STRP));
        decl(VARIABLE_NO_LOCATION, TAG_VARIABLE as u8, 0, &no_location);
        decl(FUNCTION, TAG_SUBPROGRAM, 1, &[(name, FORM_STRP)]);
        decl(
            LOCAL,
            TAG_VARIABLE as u8,
            0,
            &[(name, FORM_STRING), (loc, FORM_EXPRLOC)],
        );
        decl(
            BASE,
            TAG_BASE,
            0,
            &[
                (name, FORM_STRP),
                (AT_BYTE_SIZE, FORM_DATA1),
                (0x3e, FORM_DATA1),
            ],
        );
        decl(
            UNSIZED,
            TAG_STRUCT,
            0,
            &[(name, FORM_STRP), (0x3c, FORM_FLAG_PRESENT)],
        );
        decl(
            TYPEDEF,
            TAG_TYPEDEF,
            0,
            &[(name, FORM_STRP), (AT_TYPE, FORM_REF4)],
        );
        decl(CONST, TAG_CONST, 0, &[(AT_TYPE, FORM_REF4)]);
        decl(ARRAY, TAG_ARRAY, 1, &[(AT_TYPE, FORM_REF4)]);
        decl(SUBRANGE_COUNT, TAG_SUBRANGE, 0, &[(AT_COUNT, FORM_DATA1)]);
        decl(
            SUBRANGE_BOUNDS,
            TAG_SUBRANGE,
            0,
            &[(AT_LOWER, FORM_DATA1), (AT_UPPER, FORM_DATA1)],
        );
        let declared = [
            (name, FORM_STRP),
            (AT_TYPE, FORM_REF4),
            (link, FORM_STRP),
            (AT_EXTERNAL, FORM_FLAG_PRESENT),
            (AT_DECLARATION, FORM_FLAG_PRESENT),
        ];
        decl(DECLARATION, TAG_VARIABLE as u8, 0, &declared);
        decl(
            DEFINITION_OF,
            TAG_VARIABLE as u8,
            0,
            &[(AT_SPECIFICATION, FORM_REF4), (loc, FORM_EXPRLOC)],
        );
        decl(
            INSTANCE_OF,
            TAG_VARIABLE as u8,
            0,
            &[(AT_ABSTRACT_ORIGIN, FORM_REF4), (loc, FORM_EXPRLOC)],
        );
        decl(TYPE_SCOPE, TAG_STRUCT, 1, &[(name, FORM_STRP)]);
        decl(MEMBER, TAG_MEMBER, 0, &declared);
        decl(
            DECLARATION_UNLINKED,
            TAG_VARIABLE as u8,
            0,
            &[
                (name, FORM_STRP),
                (AT_TYPE, FORM_REF4),
                (AT_EXTERNAL, FORM_FLAG_PRESENT),
                (AT_DECLARATION, FORM_FLAG_PRESENT),
            ],
        );
        decl(
            DEFINITION_NAMED,
            TAG_VARIABLE as u8,
            0,
            &[
                (name, FORM_STRP),
                (AT_SPECIFICATION, FORM_REF4),
                (loc, FORM_EXPRLOC),
            ],
        );
        let internal = [
            (name, FORM_STRP),
            (AT_TYPE, FORM_REF4),
            (loc, FORM_EXPRLOC),
            (link, FORM_STRP),
        ];
        decl(VARIABLE_INTERNAL, TAG_VARIABLE as u8, 0, &internal);
        let mut declared_located = internal.to_vec();
        declared_located.push((AT_DECLARATION, FORM_FLAG_PRESENT));
        decl(VARIABLE_DECLARED, TAG_VARIABLE as u8, 0, &declared_located);
        a.push(0);
        a
    }

    /// The bytes of `.debug_info`, `.debug_abbrev` and `.debug_str` for
    /// two units holding `statics`, each under its namespaces with its type
    /// described before it. The second unit's abbreviation table lies at a
    /// non-zero offset and numbers its codes differently. The first unit
    /// also holds a function whose local shares a static's path but is no
    /// static.
    pub(crate) fn dwarf(statics: &[Static]) -> [Vec<u8>; 3] {
        let mut strs = vec![0u8];
        let mut intern = |s: &str| -> [u8; 4] {
            let at = strs.len() as u32;
            strs.extend_from_slice(s.as_bytes());
            strs.push(0);
            at.to_le_bytes()
        };
        let table0 = abbrev_table(1);
        let table1 = abbrev_table(41);
        let mut abbrev = table0.clone();
        abbrev.extend([0, 0, 0]);
        let table1_at = abbrev.len() as u32;
        abbrev.extend(table1);
        let mut info = Vec::new();
        for (unit, (base, table_at)) in [(1u8, 0u32), (41, table1_at)].into_iter().enumerate() {
            // Offsets in a unit count from its header, which is 11 bytes.
            let mut body: Vec<u8> = vec![base + UNIT];
            body.extend(intern(&format!("unit{unit}.rs")));
            body.extend(b"rustc\0");
            body.extend(0x1cu16.to_le_bytes());
            body.extend(0u32.to_le_bytes());
            body.extend(0x1_8000_1000u64.to_le_bytes());
            body.extend(0x100u32.to_le_bytes());
            for s in statics.iter().filter(|s| s.unit == unit) {
                let at = |body: &Vec<u8>| (11 + body.len()) as u32;
                let base_at = at(&body);
                if let Some(n) = s.size {
                    body.push(base + BASE);
                    body.extend(intern("u8x"));
                    body.extend([n, 7]);
                } else {
                    body.push(base + UNSIZED);
                    body.extend(intern("Opaque"));
                }
                let element_at = base_at;
                let base_at = match s.shape {
                    Shape::Plain => base_at,
                    Shape::Count(n) => {
                        let array_at = at(&body);
                        body.push(base + ARRAY);
                        body.extend(element_at.to_le_bytes());
                        body.extend([base + SUBRANGE_COUNT, n, 0]);
                        array_at
                    }
                    Shape::Bounds(lower, upper) => {
                        let array_at = at(&body);
                        body.push(base + ARRAY);
                        body.extend(element_at.to_le_bytes());
                        body.extend([base + SUBRANGE_BOUNDS, lower, upper, 0]);
                        array_at
                    }
                };
                let typedef_at = at(&body);
                body.push(base + TYPEDEF);
                body.extend(intern("Alias"));
                body.extend(base_at.to_le_bytes());
                let const_at = at(&body);
                body.push(base + CONST);
                body.extend(typedef_at.to_le_bytes());
                let (name, namespaces) = s.path.split_last().unwrap();
                for ns in namespaces {
                    body.push(base + NAMESPACE);
                    body.extend(intern(ns));
                }
                if s.nested {
                    body.push(base + FUNCTION);
                    body.extend(intern("f"));
                }
                if s.split != Split::Whole {
                    // The declaration here, the definition after the
                    // namespaces close.
                    if s.split == Split::Member {
                        body.push(base + TYPE_SCOPE);
                        body.extend(intern("Holder"));
                    }
                    let declared_at = at(&body);
                    body.push(
                        base + match (s.split, &s.linkage) {
                            (Split::Member, _) => MEMBER,
                            (_, None) => DECLARATION_UNLINKED,
                            _ => DECLARATION,
                        },
                    );
                    body.extend(intern(name));
                    body.extend(const_at.to_le_bytes());
                    if let Some(l) = &s.linkage {
                        body.extend(intern(l));
                    }
                    if s.split == Split::Member {
                        body.push(0);
                    }
                    if s.nested {
                        body.push(0);
                    }
                    body.extend(std::iter::repeat_n(0, namespaces.len()));
                    let expr = match &s.loc {
                        Loc::Addr(a) => {
                            let mut e = vec![OP_ADDR];
                            e.extend(a.to_le_bytes());
                            e
                        }
                        Loc::Expr(e) => e.clone(),
                        Loc::Absent => continue,
                    };
                    body.push(
                        base + match s.split {
                            Split::Origin => INSTANCE_OF,
                            Split::NamedSpecification => DEFINITION_NAMED,
                            _ => DEFINITION_OF,
                        },
                    );
                    if s.split == Split::NamedSpecification {
                        body.extend(intern(name));
                    }
                    body.extend(declared_at.to_le_bytes());
                    body.push(expr.len() as u8);
                    body.extend(expr);
                    continue;
                }
                if s.internal || s.declared {
                    // Name, type, location and linkage name, nothing else.
                    body.push(
                        base + if s.declared {
                            VARIABLE_DECLARED
                        } else {
                            VARIABLE_INTERNAL
                        },
                    );
                    body.extend(intern(name));
                    body.extend(const_at.to_le_bytes());
                    let expr = match &s.loc {
                        Loc::Addr(a) => {
                            let mut e = vec![OP_ADDR];
                            e.extend(a.to_le_bytes());
                            e
                        }
                        Loc::Expr(e) => e.clone(),
                        Loc::Absent => unreachable!("a located static"),
                    };
                    body.push(expr.len() as u8);
                    body.extend(expr);
                    body.extend(intern(s.linkage.as_deref().unwrap()));
                    if s.nested {
                        body.push(0);
                    }
                    body.extend(std::iter::repeat_n(0, namespaces.len()));
                    continue;
                }
                let code = match (&s.loc, &s.linkage) {
                    (Loc::Absent, _) => VARIABLE_NO_LOCATION,
                    (_, None) => VARIABLE_NO_LINKAGE,
                    _ => VARIABLE,
                };
                body.push(base + code);
                body.extend(intern(name));
                body.extend(const_at.to_le_bytes());
                body.extend(filler());
                body.extend([1, 0x9c]);
                match &s.loc {
                    Loc::Addr(a) => {
                        body.extend([9, OP_ADDR]);
                        body.extend(a.to_le_bytes());
                    }
                    Loc::Expr(e) => {
                        body.push(e.len() as u8);
                        body.extend(e);
                    }
                    Loc::Absent => {}
                }
                if let Some(l) = &s.linkage {
                    body.extend(intern(l));
                }
                if s.nested {
                    body.push(0);
                }
                body.extend(std::iter::repeat_n(0, namespaces.len()));
            }
            if unit == 0 {
                // A function whose local shares a static's path but is no
                // static: its location is `DW_OP_fbreg`.
                body.push(base + NAMESPACE);
                body.extend(intern("oxicrypt_module"));
                body.push(base + FUNCTION);
                body.extend(intern("f"));
                body.push(base + LOCAL);
                body.extend_from_slice(b"STATE\0");
                body.extend([2, 0x91, 0x10]);
                body.extend([0, 0]);
            }
            body.push(0);
            info.extend_from_slice(&((body.len() + 7) as u32).to_le_bytes());
            info.extend_from_slice(&4u16.to_le_bytes());
            info.extend_from_slice(&table_at.to_le_bytes());
            info.push(8);
            info.extend(body);
        }
        [info, abbrev, strs]
    }

    fn sections(d: &[Vec<u8>; 3]) -> Sections<'_> {
        Sections {
            info: &d[0],
            abbrev: &d[1],
            str: Some(&d[2]),
        }
    }

    /// Every handled form appears in each static's entry ahead of its
    /// location and linkage name, the second unit uses its own table at a
    /// non-zero offset, and each unit's end is where its length says.
    #[test]
    fn each_static_is_read_with_its_path_linkage_and_address() {
        let abbrev = abbrev_table(1);
        for form in FORMS {
            assert!(
                abbrev.windows(2).any(|w| w[1] == form as u8 && w[0] != 0),
                "the fixture uses form {form:#x}"
            );
        }
        let d = dwarf(&[
            Static::new(
                "oxicrypt_module::STATE",
                Some("_ZN15oxicrypt_module5STATE17h0123456789abcdefE"),
                Loc::Addr(0x1_8001_b000),
                Some(8),
            ),
            Static::new(
                "oxicrypt_integrity::inner::KAT",
                Some("_ZN18oxicrypt_integrity5inner3KAT"),
                Loc::Absent,
                Some(8),
            ),
            Static::new(
                "oxicrypt_integrity::LAST_STATUS",
                Some("_RNvCs1_18oxicrypt_integrity11LAST_STATUS"),
                Loc::Addr(0x1_8001_b010),
                Some(1),
            )
            .in_unit(1),
        ]);
        let v = variables(&sections(&d)).unwrap();
        assert_eq!(v.len(), 3, "{v:?}");
        assert_eq!(v[0].path, "oxicrypt_module::STATE");
        assert_eq!(
            v[0].linkage.as_deref(),
            Some("_ZN15oxicrypt_module5STATE17h0123456789abcdefE")
        );
        assert_eq!(v[0].addr(), Some(0x1_8001_b000));
        assert_eq!(v[0].size, Some(8), "through a const and a typedef");
        assert_eq!(v[1].path, "oxicrypt_integrity::inner::KAT");
        assert_eq!(v[1].location, super::Location::Absent);
        assert_eq!(v[2].path, "oxicrypt_integrity::LAST_STATUS");
        assert_eq!(v[2].addr(), Some(0x1_8001_b010));
        assert_eq!(v[2].size, Some(1));
    }

    #[test]
    fn a_form_the_reader_does_not_handle_is_refused() {
        let mut d = dwarf(&[]);
        // The unit's name attribute, given DW_FORM_strx1 (0x25).
        assert_eq!(
            &d[1][..5],
            &[1, TAG_UNIT, 1, AT_NAME as u8, FORM_STRP as u8]
        );
        d[1][4] = 0x25;
        let err = variables(&sections(&d)).unwrap_err();
        assert!(err.starts_with("DwarfForm"), "{err}");
    }

    #[test]
    fn a_unit_of_another_version_or_shape_is_refused() {
        let good = dwarf(&[]);
        assert!(variables(&sections(&good)).is_ok());
        for (at, byte) in [(4, 5u8), (10, 4), (3, 0xff)] {
            let mut d = good.clone();
            d[0][at] = byte;
            let err = variables(&sections(&d)).unwrap_err();
            assert!(err.starts_with("NoDwarf"), "{at}: {err}");
        }
        let empty = [Vec::new(), good[1].clone(), good[2].clone()];
        assert!(
            variables(&sections(&empty))
                .unwrap_err()
                .starts_with("NoDwarf")
        );
        let no_str = Sections {
            str: None,
            ..sections(&good)
        };
        assert!(variables(&no_str).unwrap_err().starts_with("NoDwarf"));
    }

    /// The offset in `.debug_info` where the first unit of `d` ends.
    fn first_unit(d: &[Vec<u8>; 3]) -> usize {
        u32::from_le_bytes(d[0][..4].try_into().unwrap()) as usize + 4
    }

    /// A unit holds one tree: an entry after its root closes, or a root
    /// left open at the unit's end, or a unit shorter than its header, is
    /// refused.
    #[test]
    fn a_unit_that_is_not_one_closed_tree_is_refused() {
        let good = dwarf(&[]);
        let end = first_unit(&good);
        assert_eq!(good[0][end - 1], 0, "the first unit's root closes last");

        // Another root after the first closes: a namespace with a static.
        let mut after = good.clone();
        let extra = [2u8, 0, 0, 0, 0, 0];
        after[0].splice(end..end, extra);
        let len = (end - 4 + extra.len()) as u32;
        after[0][..4].copy_from_slice(&len.to_le_bytes());
        let err = variables(&sections(&after)).unwrap_err();
        assert!(err.starts_with("NoDwarf") && err.contains("after"), "{err}");

        // The root's terminator dropped, the length shortened to match.
        let mut open = good.clone();
        open[0].remove(end - 1);
        let len = (end - 5) as u32;
        open[0][..4].copy_from_slice(&len.to_le_bytes());
        let err = variables(&sections(&open)).unwrap_err();
        assert!(err.starts_with("NoDwarf") && err.contains("open"), "{err}");

        // A unit length of 3, shorter than the seven bytes after it that a
        // version 4 header takes.
        let mut short = good.clone();
        short[0][..4].copy_from_slice(&3u32.to_le_bytes());
        let err = variables(&sections(&short)).unwrap_err();
        assert!(
            err.starts_with("NoDwarf") && err.contains("shorter than its header"),
            "{err}"
        );
    }

    /// Units that share one large table read it once: two thousand units
    /// over a table of three thousand abbreviations parse in well under the
    /// time one parse per unit takes.
    #[test]
    fn units_sharing_an_abbreviation_table_read_it_once() {
        let mut abbrev = Vec::new();
        // Code 1 is a root with no children; codes 2.. are padding the
        // table out, each a namespace with a name.
        abbrev.extend([1, TAG_UNIT, 0, AT_NAME as u8, FORM_STRING as u8, 0, 0]);
        for code in 2u16..3000 {
            let mut c = Vec::new();
            let mut v = code;
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    c.push(b);
                    break;
                }
                c.push(b | 0x80);
            }
            abbrev.extend(c);
            abbrev.extend([TAG_NAMESPACE as u8, 1, AT_NAME as u8, FORM_STRP as u8, 0, 0]);
        }
        abbrev.push(0);
        let mut info = Vec::new();
        for _ in 0..2000 {
            info.extend_from_slice(&10u32.to_le_bytes());
            info.extend_from_slice(&4u16.to_le_bytes());
            info.extend_from_slice(&0u32.to_le_bytes());
            info.push(8);
            info.extend([1, b'u', 0]);
        }
        let started = std::time::Instant::now();
        let v = variables(&Sections {
            info: &info,
            abbrev: &abbrev,
            str: None,
        })
        .unwrap();
        assert!(v.is_empty());
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(2),
            "two thousand units took {took:?}"
        );
    }

    /// Units that each name a different offset inside one long table read
    /// the table once: two hundred units spread over a table of twenty
    /// thousand abbreviations parse in well under the time a parse of the
    /// table's remainder per unit takes.
    #[test]
    fn units_at_distinct_offsets_in_one_table_read_it_once() {
        let uleb = |mut v: u64, out: &mut Vec<u8>| loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        };
        let mut abbrev = Vec::new();
        let mut starts = Vec::new();
        for code in 1u64..=20_000 {
            starts.push((abbrev.len() as u32, code));
            uleb(code, &mut abbrev);
            abbrev.extend([TAG_UNIT, 0, AT_NAME as u8, FORM_STRING as u8, 0, 0]);
        }
        abbrev.push(0);
        let mut info = Vec::new();
        for &(at, code) in starts.iter().step_by(50).take(200) {
            let mut root = Vec::new();
            uleb(code, &mut root);
            root.extend([b'u', 0]);
            info.extend_from_slice(&((7 + root.len()) as u32).to_le_bytes());
            info.extend_from_slice(&4u16.to_le_bytes());
            info.extend_from_slice(&at.to_le_bytes());
            info.push(8);
            info.extend(root);
        }
        let started = std::time::Instant::now();
        let v = variables(&Sections {
            info: &info,
            abbrev: &abbrev,
            str: None,
        })
        .unwrap();
        assert!(v.is_empty());
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(1),
            "two hundred units took {took:?}"
        );
        // A unit whose offset falls inside a declaration is refused.
        let mut inside = info.clone();
        inside[6..10].copy_from_slice(&(starts[1].0 + 1).to_le_bytes());
        let err = variables(&Sections {
            info: &inside,
            abbrev: &abbrev,
            str: None,
        })
        .unwrap_err();
        assert!(
            err.starts_with("NoDwarf") && err.contains("where no table or declaration does"),
            "{err}"
        );
        // A unit starting at a declaration uses a code declared before it.
        let mut earlier = info.clone();
        let mut root = Vec::new();
        uleb(starts[2].1, &mut root);
        root.extend([b'u', 0]);
        let mut unit = ((7 + root.len()) as u32).to_le_bytes().to_vec();
        unit.extend(4u16.to_le_bytes());
        unit.extend(starts[5].0.to_le_bytes());
        unit.push(8);
        unit.extend(root);
        earlier.extend(unit);
        let err = variables(&Sections {
            info: &earlier,
            abbrev: &abbrev,
            str: None,
        })
        .unwrap_err();
        assert!(
            err.starts_with("NoDwarf") && err.contains("does not declare"),
            "{err}"
        );
    }
}
