//! Choosing a byte to flip when testing tamper detection on an ELF image.
//!
//! The byte must be hashed, and nothing may parse or execute it before the
//! integrity test runs: a flipped instruction in start-up or self-test code,
//! or in a header the loader reads, crashes the process before the module
//! can refuse, which tells the test nothing. Alignment padding between two
//! sections satisfies all three: it is mapped and hashed, and referenced by
//! nothing. The chosen byte is the middle of the longest such gap inside the
//! signed extent, and there is no fallback to a byte that might run.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

/// `SHT_NOBITS`: a section with no file bytes.
const SHT_NOBITS: u32 = 8;

fn u16_at(d: &[u8], o: usize) -> usize {
    usize::from(u16::from_le_bytes(d[o..o + 2].try_into().unwrap()))
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
fn u64_at(d: &[u8], o: usize) -> usize {
    usize::try_from(u64::from_le_bytes(d[o..o + 8].try_into().unwrap())).unwrap()
}

/// The file offset of a padding byte between two sections, inside one of
/// `extent`'s `(file_off, len)` ranges. Panics if there is none.
pub(crate) fn padding_offset(image: &[u8], extent: &[(u32, u32)]) -> usize {
    assert_eq!(&image[..4], b"\x7fELF", "an ELF image is expected");
    // Everything the loader parses or something reads before the test.
    let mut busy: Vec<(usize, usize)> = vec![(0, 64)];
    let phoff = u64_at(image, 0x20);
    let (phentsize, phnum) = (u16_at(image, 0x36), u16_at(image, 0x38));
    busy.push((phoff, phoff + phentsize * phnum));
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        let kind = u32_at(image, p);
        // PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_TLS, PT_GNU_EH_FRAME.
        if matches!(kind, 2 | 3 | 4 | 7 | 0x6474_e550) {
            let off = u64_at(image, p + 8);
            busy.push((off, off + u64_at(image, p + 32)));
        }
    }
    let shoff = u64_at(image, 0x28);
    let (shentsize, shnum) = (u16_at(image, 0x3a), u16_at(image, 0x3c));
    for i in 0..shnum {
        let s = shoff + i * shentsize;
        if u32_at(image, s + 4) == SHT_NOBITS {
            continue;
        }
        let off = u64_at(image, s + 24);
        let size = u64_at(image, s + 32);
        if size > 0 {
            busy.push((off, off + size));
        }
    }
    busy.sort_unstable();

    // Gaps between busy regions, clipped to the extent; keep the longest.
    let mut best: Option<(usize, usize)> = None;
    for &(start, len) in extent {
        let (lo, hi) = (start as usize, start as usize + len as usize);
        let mut cursor = lo;
        for &(b0, b1) in &busy {
            if b1 <= cursor {
                continue;
            }
            if b0 >= hi {
                break;
            }
            if b0 > cursor && best.is_none_or(|(a, z)| b0 - cursor > z - a) {
                best = Some((cursor, b0));
            }
            cursor = cursor.max(b1);
        }
        if cursor < hi && best.is_none_or(|(a, z)| hi - cursor > z - a) {
            best = Some((cursor, hi));
        }
    }
    let (a, z) = best.expect("no padding between sections inside the signed extent");
    let off = a + (z - a) / 2;
    assert!(
        extent
            .iter()
            .any(|&(s, l)| off >= s as usize && off < (s + l) as usize),
        "premise failed: the chosen offset {off:#x} is not inside the signed extent"
    );
    assert!(
        !busy.iter().any(|&(b0, b1)| off >= b0 && off < b1),
        "premise failed: the chosen offset {off:#x} lies in a section or a parsed header"
    );
    off
}
