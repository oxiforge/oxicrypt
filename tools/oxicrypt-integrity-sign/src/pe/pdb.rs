//! The part of a program database (PDB) the module-statics check reads:
//! its identity and the data symbols it names.
//!
//! A PDB is a multi-stream file (MSF 7.00): a superblock, a directory of
//! streams, and each stream a list of fixed-size blocks. Stream 1 holds the
//! PDB's identity, the GUID and age the image's CodeView debug record
//! repeats; stream 3, the debug information stream, lists the modules, each
//! with a stream of symbol records, and names the stream of global symbol
//! records. The data symbols (`S_GDATA32`, `S_LDATA32`) and public symbols
//! (`S_PUB32`) in those streams give each static's section and offset.

use crate::image::{u16_at, u32_at};

/// The MSF 7.00 superblock magic.
const MSF_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0\0";
/// The stream holding the PDB's identity.
const PDB_STREAM: usize = 1;
/// The debug information stream.
const DBI_STREAM: usize = 3;
/// A stream the directory marks as absent.
const NIL_STREAM: u32 = u32::MAX;
/// The debug information stream's signature, `-1`.
const DBI_SIGNATURE: u32 = u32::MAX;
/// `DbiStreamVersion::V70`, the version MSVC and lld-link write.
const DBI_VERSION_V70: u32 = 19_990_903;
/// Size of the debug information stream's header.
const DBI_HEADER_SIZE: usize = 64;
/// Size of a module record's fixed part, before its two names.
const MODULE_INFO_SIZE: usize = 64;
/// The signature at the start of a module's symbol stream.
const CV_SIGNATURE_C13: u32 = 4;

/// `S_LDATA32`: a static with internal linkage.
pub(crate) const S_LDATA32: u16 = 0x110c;
/// `S_GDATA32`: a static with external linkage.
pub(crate) const S_GDATA32: u16 = 0x110d;
/// `S_PUB32`: a public symbol.
pub(crate) const S_PUB32: u16 = 0x110e;

/// A data or public symbol: where it lies, by section and offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Symbol {
    /// The image section, numbered from one.
    pub(crate) segment: u16,
    /// The offset in that section.
    pub(crate) offset: u32,
    /// The name, as the record spells it.
    pub(crate) name: String,
}

/// What the check reads from a PDB.
#[derive(Debug)]
pub(crate) struct Pdb {
    /// The PDB's GUID, as the image's CodeView record holds it.
    pub(crate) guid: [u8; 16],
    /// The PDB's age.
    pub(crate) age: u32,
    /// Every data and public symbol, from the global symbol records and
    /// every module's symbol stream.
    pub(crate) symbols: Vec<Symbol>,
}

/// The streams of an MSF file.
struct Msf<'a> {
    bytes: &'a [u8],
    block_size: usize,
    /// The blocks the superblock declares; the file holds every one, and
    /// no stream is larger than all of them.
    num_blocks: usize,
    /// Each stream's size and its blocks.
    streams: Vec<(usize, Vec<u32>)>,
}

impl<'a> Msf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.get(..MSF_MAGIC.len()) != Some(MSF_MAGIC.as_slice()) {
            return Err("not an MSF 7.00 program database".to_owned());
        }
        let field = |off: usize| -> Result<usize, String> {
            u32_at(bytes, off)
                .and_then(|v| usize::try_from(v).ok())
                .ok_or_else(|| "truncated PDB superblock".to_owned())
        };
        let block_size = field(32)?;
        if !matches!(block_size, 512 | 1024 | 2048 | 4096) {
            return Err(format!("PDB block size {block_size} is not one MSF uses"));
        }
        let num_blocks = field(40)?;
        let dir_bytes = field(44)?;
        let map_block = field(52)?;
        if num_blocks
            .checked_mul(block_size)
            .is_none_or(|extent| extent > bytes.len())
        {
            return Err(format!(
                "the PDB declares {num_blocks} blocks of {block_size} bytes, more than the file \
                 holds"
            ));
        }
        let mut msf = Self {
            bytes,
            block_size,
            num_blocks,
            streams: Vec::new(),
        };
        msf.check_size(dir_bytes)?;
        let dir_blocks = dir_bytes.div_ceil(block_size);
        let map = msf.block(map_block)?;
        let mut blocks = Vec::with_capacity(dir_blocks);
        for i in 0..dir_blocks {
            let at = i.checked_mul(4).ok_or("PDB directory overflows")?;
            blocks
                .push(u32_at(map, at).ok_or("the PDB directory's block map overflows its block")?);
        }
        let dir = msf.assemble(dir_bytes, &blocks)?;
        let count = u32_at(&dir, 0).ok_or("truncated PDB directory")?;
        let count = usize::try_from(count).map_err(|_| "PDB stream count overflows")?;
        let mut at = count
            .checked_mul(4)
            .and_then(|n| n.checked_add(4))
            .ok_or("PDB directory overflows")?;
        for i in 0..count {
            let size_at = i
                .checked_mul(4)
                .and_then(|n| n.checked_add(4))
                .ok_or("PDB directory overflows")?;
            let raw = u32_at(&dir, size_at).ok_or("truncated PDB directory")?;
            let size = if raw == NIL_STREAM {
                0
            } else {
                usize::try_from(raw).map_err(|_| "PDB stream size overflows")?
            };
            msf.check_size(size)?;
            let n = size.div_ceil(block_size);
            let mut list = Vec::with_capacity(n);
            for _ in 0..n {
                list.push(u32_at(&dir, at).ok_or("truncated PDB directory")?);
                at = at.checked_add(4).ok_or("PDB directory overflows")?;
            }
            msf.streams.push((size, list));
        }
        Ok(msf)
    }

    /// Refuses a stream larger than the blocks the superblock declares.
    fn check_size(&self, size: usize) -> Result<(), String> {
        if size > self.num_blocks.saturating_mul(self.block_size) {
            return Err(format!(
                "a PDB stream of {size} bytes is larger than the file's declared blocks"
            ));
        }
        Ok(())
    }

    fn block(&self, index: usize) -> Result<&'a [u8], String> {
        if index >= self.num_blocks {
            return Err(format!(
                "PDB block {index} lies past the {} blocks the superblock declares",
                self.num_blocks
            ));
        }
        let start = index
            .checked_mul(self.block_size)
            .ok_or("a PDB block index overflows")?;
        start
            .checked_add(self.block_size)
            .and_then(|end| self.bytes.get(start..end))
            .ok_or_else(|| format!("PDB block {index} lies past the end of the file"))
    }

    fn assemble(&self, size: usize, blocks: &[u32]) -> Result<Vec<u8>, String> {
        self.check_size(size)?;
        let mut out = Vec::new();
        out.try_reserve_exact(size.saturating_add(self.block_size))
            .map_err(|_| format!("cannot allocate a PDB stream of {size} bytes"))?;
        for &b in blocks {
            let index = usize::try_from(b).map_err(|_| "a PDB block index overflows")?;
            out.extend_from_slice(self.block(index)?);
        }
        out.truncate(size);
        if out.len() != size {
            return Err("a PDB stream is shorter than its declared size".to_owned());
        }
        Ok(out)
    }

    fn stream(&self, index: usize) -> Result<Vec<u8>, String> {
        let (size, blocks) = self
            .streams
            .get(index)
            .ok_or_else(|| format!("the PDB has no stream {index}"))?;
        self.assemble(*size, blocks)
    }
}

/// Appends the data and public symbols among the records in `records`.
fn symbols_in(records: &[u8], out: &mut Vec<Symbol>) -> Result<(), String> {
    let mut at = 0usize;
    while at < records.len() {
        let len = usize::from(u16_at(records, at).ok_or("truncated PDB symbol record")?);
        let body = at.checked_add(2).ok_or("PDB symbol record overflows")?;
        let end = body.checked_add(len).ok_or("PDB symbol record overflows")?;
        if len < 2 || end > records.len() {
            return Err("a PDB symbol record runs past its stream".to_owned());
        }
        let kind = u16_at(records, body).ok_or("truncated PDB symbol record")?;
        if matches!(kind, S_LDATA32 | S_GDATA32 | S_PUB32) {
            // DATASYM32: type index, offset, segment, name. PUBSYM32: flags,
            // offset, segment, name. The two share the layout after kind.
            let field = |d: usize| body.checked_add(d).ok_or("PDB symbol record overflows");
            let offset = u32_at(records, field(6)?).ok_or("truncated PDB data symbol")?;
            let segment = u16_at(records, field(10)?).ok_or("truncated PDB data symbol")?;
            let name_at = field(12)?;
            let raw = records
                .get(name_at..end)
                .ok_or("truncated PDB data symbol")?;
            let name_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            let name = String::from_utf8_lossy(raw.get(..name_len).unwrap_or(&[])).into_owned();
            out.push(Symbol {
                segment,
                offset,
                name,
            });
        }
        at = end;
    }
    Ok(())
}

/// Parses the identity and the data and public symbols of a PDB.
///
/// # Errors
///
/// A description when the file is not an MSF 7.00 PDB or a stream it reads
/// is malformed.
pub(crate) fn parse(bytes: &[u8]) -> Result<Pdb, String> {
    let msf = Msf::parse(bytes)?;
    let info = msf.stream(PDB_STREAM)?;
    let age = u32_at(&info, 8).ok_or("truncated PDB info stream")?;
    let mut guid = [0u8; 16];
    guid.copy_from_slice(info.get(12..28).ok_or("truncated PDB info stream")?);

    let dbi = msf.stream(DBI_STREAM)?;
    let header = |off: usize| -> Result<u32, String> {
        u32_at(&dbi, off).ok_or_else(|| "truncated PDB debug information header".to_owned())
    };
    // The debug information stream is the same build's: its own signature
    // and version, and the age the info stream gives.
    if header(0)? != DBI_SIGNATURE || header(4)? != DBI_VERSION_V70 {
        return Err("the PDB's debug information stream is not a version 7.0 stream".to_owned());
    }
    if header(8)? != age {
        return Err(format!(
            "the PDB's debug information age {} is not its info stream's age {age}",
            header(8)?
        ));
    }
    let symrec = u16_at(&dbi, 20).ok_or("truncated PDB debug information header")?;
    let modinfo_size =
        usize::try_from(header(24)?).map_err(|_| "PDB module information overflows")?;
    let mut symbols = Vec::new();
    if symrec != u16::MAX {
        symbols_in(&msf.stream(usize::from(symrec))?, &mut symbols)?;
    }
    let modinfo = DBI_HEADER_SIZE
        .checked_add(modinfo_size)
        .and_then(|end| dbi.get(DBI_HEADER_SIZE..end))
        .ok_or("the PDB module information runs past its stream")?;
    let mut at = 0usize;
    while at < modinfo.len() {
        let field = |d: usize| at.checked_add(d).ok_or("PDB module record overflows");
        let stream = u16_at(modinfo, field(34)?).ok_or("truncated PDB module record")?;
        let sym_bytes = u32_at(modinfo, field(36)?).ok_or("truncated PDB module record")?;
        // Two NUL-terminated names follow the fixed part; the record is
        // padded to four bytes.
        let mut end = field(MODULE_INFO_SIZE)?;
        for _ in 0..2 {
            let tail = modinfo.get(end..).ok_or("truncated PDB module record")?;
            let n = tail
                .iter()
                .position(|&b| b == 0)
                .ok_or("a PDB module name is not terminated")?;
            end = end
                .checked_add(n)
                .and_then(|e| e.checked_add(1))
                .ok_or("PDB module record overflows")?;
        }
        at = end
            .checked_next_multiple_of(4)
            .ok_or("PDB module record overflows")?;
        if stream == u16::MAX || sym_bytes == 0 {
            continue;
        }
        let data = msf.stream(usize::from(stream))?;
        let sym_bytes = usize::try_from(sym_bytes).map_err(|_| "PDB module symbols overflow")?;
        if u32_at(&data, 0) != Some(CV_SIGNATURE_C13) {
            return Err("a PDB module's symbols do not begin with the C13 signature".to_owned());
        }
        let records = data
            .get(4..sym_bytes)
            .ok_or("a PDB module's symbols run past its stream")?;
        symbols_in(records, &mut symbols)?;
    }
    Ok(Pdb { guid, age, symbols })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
pub(crate) mod tests {
    use super::{CV_SIGNATURE_C13, S_GDATA32, S_LDATA32, S_PUB32, parse};

    /// Block size of the PDBs these tests write: small, so streams span
    /// several blocks.
    const BLOCK: usize = 512;

    /// An MSF file holding `streams`, each stream's blocks placed in
    /// reverse so a reader that assumes contiguous blocks fails.
    pub(crate) fn msf(streams: &[Vec<u8>]) -> Vec<u8> {
        let mut blocks: Vec<Vec<u8>> = vec![vec![0u8; BLOCK]; 3];
        let mut lists = Vec::new();
        for s in streams {
            let mut list = Vec::new();
            let chunks: Vec<&[u8]> = s.chunks(BLOCK).collect();
            for c in chunks.iter().rev() {
                let mut b = c.to_vec();
                b.resize(BLOCK, 0);
                list.push(blocks.len() as u32);
                blocks.push(b);
            }
            list.reverse();
            lists.push(list);
        }
        let mut dir = Vec::new();
        dir.extend_from_slice(&(streams.len() as u32).to_le_bytes());
        for s in streams {
            dir.extend_from_slice(&(s.len() as u32).to_le_bytes());
        }
        for l in &lists {
            for b in l {
                dir.extend_from_slice(&b.to_le_bytes());
            }
        }
        let mut map = Vec::new();
        for c in dir.chunks(BLOCK) {
            let mut b = c.to_vec();
            b.resize(BLOCK, 0);
            map.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
            blocks.push(b);
        }
        map.resize(BLOCK, 0);
        blocks[2] = map;
        let mut out = vec![0u8; BLOCK];
        out[..32].copy_from_slice(super::MSF_MAGIC);
        out[32..36].copy_from_slice(&(BLOCK as u32).to_le_bytes());
        out[36..40].copy_from_slice(&1u32.to_le_bytes());
        out[40..44].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        out[44..48].copy_from_slice(&(dir.len() as u32).to_le_bytes());
        out[52..56].copy_from_slice(&2u32.to_le_bytes());
        blocks[0] = out;
        blocks.concat()
    }

    /// One symbol record of `kind` naming `name` at `segment:offset`.
    pub(crate) fn record(kind: u16, segment: u16, offset: u32, name: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&kind.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&segment.to_le_bytes());
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        while !(body.len() + 2).is_multiple_of(4) {
            body.push(0);
        }
        let mut out = (body.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// A PDB with identity `guid`/`age`, `globals` in the global symbol
    /// records and `module` in one module's symbol stream.
    pub(crate) fn pdb(guid: [u8; 16], age: u32, globals: &[u8], module: &[u8]) -> Vec<u8> {
        pdb_aged(guid, age, age, globals, module)
    }

    /// As [`pdb`], with the debug information stream carrying `dbi_age`.
    fn pdb_aged(guid: [u8; 16], age: u32, dbi_age: u32, globals: &[u8], module: &[u8]) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&20_000_404u32.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.extend_from_slice(&age.to_le_bytes());
        info.extend_from_slice(&guid);
        let mut modsyms = CV_SIGNATURE_C13.to_le_bytes().to_vec();
        modsyms.extend_from_slice(module);
        let mut modinfo = vec![0u8; super::MODULE_INFO_SIZE];
        modinfo[34..36].copy_from_slice(&5u16.to_le_bytes());
        modinfo[36..40].copy_from_slice(&(modsyms.len() as u32).to_le_bytes());
        modinfo.extend_from_slice(b"a.o\0a.o\0");
        while !modinfo.len().is_multiple_of(4) {
            modinfo.push(0);
        }
        // A second module with no symbols.
        let mut empty = vec![0u8; super::MODULE_INFO_SIZE];
        empty[34..36].copy_from_slice(&u16::MAX.to_le_bytes());
        empty.extend_from_slice(b"b\0b\0");
        modinfo.extend_from_slice(&empty);
        let mut dbi = vec![0u8; super::DBI_HEADER_SIZE];
        dbi[0..4].copy_from_slice(&(-1i32).to_le_bytes());
        dbi[4..8].copy_from_slice(&super::DBI_VERSION_V70.to_le_bytes());
        dbi[8..12].copy_from_slice(&dbi_age.to_le_bytes());
        dbi[20..22].copy_from_slice(&4u16.to_le_bytes());
        dbi[24..28].copy_from_slice(&(modinfo.len() as u32).to_le_bytes());
        dbi.extend_from_slice(&modinfo);
        msf(&[Vec::new(), info, Vec::new(), dbi, globals.to_vec(), modsyms])
    }

    #[test]
    fn identity_and_data_symbols_are_read_from_every_stream() {
        let guid = [7u8; 16];
        let mut globals = record(S_PUB32, 3, 0x10, "_ZN15oxicrypt_module5STATE17hE");
        globals.extend(record(0x1125, 0, 0, "a procedure reference"));
        globals.extend(record(
            S_GDATA32,
            3,
            0x20,
            "oxicrypt_integrity::LAST_STATUS",
        ));
        // A module stream long enough to span blocks.
        let mut module = Vec::new();
        for i in 0..60 {
            module.extend(record(S_LDATA32, 3, 0x100 + i, &format!("local{i:02}")));
        }
        let p = parse(&pdb(guid, 3, &globals, &module)).unwrap();
        assert_eq!((p.guid, p.age), (guid, 3));
        assert_eq!(p.symbols.len(), 62, "{:?}", p.symbols.first());
        assert_eq!(p.symbols[0].name, "_ZN15oxicrypt_module5STATE17hE");
        assert_eq!((p.symbols[1].segment, p.symbols[1].offset), (3, 0x20));
        assert_eq!(p.symbols[61].name, "local59");
        assert_eq!(p.symbols[61].offset, 0x100 + 59);
    }

    #[test]
    fn a_malformed_pdb_is_refused() {
        let good = pdb([1; 16], 1, &record(S_PUB32, 1, 0, "x"), &[]);
        assert!(parse(&good).is_ok());
        assert!(parse(b"not a pdb").is_err());
        // A record whose length runs past its stream.
        let mut long = record(S_PUB32, 1, 0, "x");
        long[0] = 0xf0;
        assert!(parse(&pdb([1; 16], 1, &long, &[])).is_err());
        // A file cut short of its streams' blocks.
        assert!(parse(&good[..good.len() - 512]).is_err());
    }

    /// The debug information stream must be the info stream's build: only
    /// its age differs here.
    #[test]
    fn a_debug_information_age_other_than_the_info_age_is_refused() {
        let globals = record(S_PUB32, 1, 0, "x");
        assert!(parse(&pdb_aged([1; 16], 2, 2, &globals, &[])).is_ok());
        let err = parse(&pdb_aged([1; 16], 2, 3, &globals, &[])).unwrap_err();
        assert!(err.contains("age"), "{err}");
    }

    /// The superblock's block count bounds every block and every stream: a
    /// directory naming one block many times for a stream far larger than
    /// the file is refused before anything is allocated for it, and a block
    /// past the count is refused.
    #[test]
    fn the_declared_block_count_bounds_every_block_and_stream() {
        let good = pdb([1; 16], 1, &record(S_PUB32, 1, 0, "x"), &[]);
        let num_blocks = u32::from_le_bytes(good[40..44].try_into().unwrap()) as usize;
        let map = u32::from_le_bytes(good[52..56].try_into().unwrap()) as usize;
        let dir_block =
            u32::from_le_bytes(good[map * BLOCK..map * BLOCK + 4].try_into().unwrap()) as usize;
        let dir = dir_block * BLOCK;
        // Stream 4 (the global records) declared 1 GiB, its blocks repeated.
        let mut huge = good.clone();
        huge[dir + 4 + 4 * 4..dir + 4 + 4 * 5].copy_from_slice(&(1u32 << 30).to_le_bytes());
        let err = parse(&huge).unwrap_err();
        assert!(
            err.contains("larger than the file's declared blocks"),
            "{err}"
        );
        // A count larger than the file.
        let mut count = good.clone();
        count[40..44].copy_from_slice(&((num_blocks + 1) as u32).to_le_bytes());
        assert!(
            parse(&count)
                .unwrap_err()
                .contains("more than the file holds")
        );
        // A count that leaves out the last block, which a stream uses.
        let mut short = good.clone();
        short[40..44].copy_from_slice(&((num_blocks - 1) as u32).to_le_bytes());
        assert!(parse(&short).is_err());
    }
}
