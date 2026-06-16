// Deterministic oracle-dataset generator for maxwell §5 (ISC-81 L2 verdict layer).
// IID  : SplitMix64 stream, low byte -> 8-bit uniform, no serial dependence -> passes §5.
// nonIID: serially-correlated random walk mod 256 -> strong order dependence -> fails §5.
// Fixed seeds => reproducible. 100_000 samples each (stable verdict, tractable 10k-perm run).
use std::io::Write;
fn sm64(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}
fn main() {
    let n = 100_000usize;
    // IID
    let mut s = 0x0DDC0FFEEBADF00Du64;
    let mut iid = Vec::with_capacity(n);
    for _ in 0..n { iid.push((sm64(&mut s) & 0xFF) as u8); }
    std::fs::File::create("/tmp/oracle_iid.bin").unwrap().write_all(&iid).unwrap();
    // non-IID random walk
    let mut s2 = 0xCAFEBABE12345678u64;
    let mut x: i32 = 128;
    let mut nw = Vec::with_capacity(n);
    for _ in 0..n {
        let step = ((sm64(&mut s2) & 0x3) as i32) - 1; // -1,0,1,2 -> drift
        x = (x + step).rem_euclid(256);
        nw.push(x as u8);
    }
    std::fs::File::create("/tmp/oracle_noniid.bin").unwrap().write_all(&nw).unwrap();
    eprintln!("wrote {} samples each", n);
}
