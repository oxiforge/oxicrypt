#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::format_collect,
    clippy::needless_range_loop,
    clippy::manual_string_new,
    clippy::uninlined_format_args,
    clippy::many_single_char_names,
    clippy::ignore_without_reason,
    clippy::similar_names
)]
//! One-shot helper that generates `RSA-sigGen-FIPS186-5/kat-slice.json`
//! from an existing RSA key (borrowed from the sigPrim slice) by signing
//! messages with both PKCS#1v1.5 and PSS, then writing the combined
//! request+response JSON. Run with:
//!
//!   cargo test -p acvp-harness --test gen_rsa_siggen_slice -- --ignored --nocapture
//!
//! The resulting file lands in the vendor tree ready for MANIFEST.toml.

use std::io::Write;

// --- hex helpers (minimal, test-only) ---

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

// --- key material (from sigPrim tgId=4, tcId=11) ---

const N_HEX: &str = "DAF664E04A3C85EAA67F3399FC97DE34C1F99F76AA2BE18F27FDB168C542BE883AFCD787CD902D2BF94FBB180529EF39731489F5CBDA3E25A2E1A5AE26016C42AC76AFE0904C7B86B890313CDD93129C55111719B467DDF672AD845DF86B707D386C318718BE5A346F153C79C7361BDA7759F2E99C3454DF3A9E2D7AC47B32089437B85690193BFB51CC919E796313700477491A8074F06DC8DA02437611B8DB868ACBC35C46CC7B325BC3697B3456D6C50D5FF6D4077EAC3B06C44386BACB88891BEB040CF40BBA0D501D52F305AD3D6276376AA87CFF9E5EC5EC93ED2D3A3BAF6AF3B262AAA2C14E9A2C9A3162CD0BCD9A1903DC0DE038336800513D8F53D5";
const E_HEX: &str = "010001";
const D_HEX: &str = "0D9B3F1482F874D7EA85C006A3202AD23B759017B72667EB55F0595C69D9A66E5FC00382B05EF3B7A653F28BE1124487DCE35B59575416058FB416F015F383AF36F95F1F84C803EB10C0011747AB927DFD7944E6B783B6D2D038811FB7C6B1644EA3C6861F1F010AFE16233E6C072C3EECA8BDC40F8D5EF2CA39371948696167F297C5BA344881CF6C79C432513AFE8A176FBD699ECCD9399DB35589E75D5567D41209DD384E4B7B270706CCF8D4C21525F20309BE86AF85D18B7F6EE893DA8BDECF2911CA35BACF7415595C0569EAC95C7B0268563C948C5326A0ACFD3B1EBAFDA2FB6BBE137760C978208F2B54F39803FB4C7A07A2294F62F85A50034CA261";
const P_HEX: &str = "FB49B1B44CDB33B0D62D435D8FD8B49FDF76FC58FFEEAF69BAE0062CB3647750B00E435B3BEDB06F44B2F5BBFE6EB1A261BD626DD048D33EA4ECA2FC4A7763CCE841CC417A165C41E3CCA0D22C53565CDD51A416305F927C4FBD71972F943CE485220E55CA8EF305D393CD62C423FC1584D191875CE8EEF69797D06E1C2FD5B1";
const Q_HEX: &str = "DF1185A52F5D74F32ED3781D0E0AFF6AA853E1EED7B6CFEE878D58B2F9AA38C359DFA30311329EED0019053F20928B882DEF076363745D831496D8CE4A740D331298B099922C5AB0B645623439E485605CA32707DD4B5C0A79352F6BE25532634E3E24A5F3E72B54F6E5AEBF7ED6B94401BB247DD75B72363EA381BD80509565";
const DP_HEX: &str = "2305BC5CB2B1825CCD1CF5DC9E65C796D8A04EBF60BC357A78EF2C2D22BB87DD990C03DB3D58FD5424B1048AB5055C80933ABFF32A2A5C36C8E9AA359B73545784AF56F6713B98941E59B0B85A312B423A1E5CCE32E3BF18D04C48FE974503CF9DB68764F19C46C6B31C506DC9847267D56117F553BFAB3E7716539865194DA1";
const DQ_HEX: &str = "CE2DE4E8645A2E81A3B3645EFE9EDDAC18BFC7A1BA92C7A842743C1AD93723D63458C7D44AEE0E052344FD1B7720DC8557678ADDAB8C5FEE8B764E1886AAB3949448BB5A86C8265F156A16360D98924B19F4D75BA688441F8E1EC1A12706F656E17800E9BF01D98463DCB1E35FFA5A2D68A830377C79929C5ED3445502A7F91D";
const QINV_HEX: &str = "5A6BA60B2DFBF986D6A30599A0C97E8250CDB6E445D83CD32E57BED179F3591FD7F1E69A2A0B3C13A7A100E62FBD82C437F15ABCAD89DFDFD612950181AC5207AFB4C4C70229522D805574B554DDB33E2F64754CBD1E801022F91E2F0532D1798EF4C65FFBBA86D92DD265D30FF26F693CBBED04A9A02288F437686DECCD10E4";

// A few short messages (hex) for signing.
const MESSAGES: [&str; 5] = [
    "ABCDEF0123456789",
    "00112233445566778899AABBCCDDEEFF",
    "DEADBEEF",
    "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
    "FF",
];

const SALT_HEX: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

#[test]
#[ignore]
fn generate_rsa_siggen_slice() {
    let n = hex_decode(N_HEX);
    let d = hex_decode(D_HEX);
    let e_bytes = hex_decode(E_HEX);
    let p = hex_decode(P_HEX);
    let q = hex_decode(Q_HEX);
    let dp = hex_decode(DP_HEX);
    let dq = hex_decode(DQ_HEX);
    let qinv = hex_decode(QINV_HEX);
    let salt = hex_decode(SALT_HEX);

    // --- build arrays ---
    let n_arr: [u8; 256] = n.as_slice().try_into().unwrap();
    let d_arr: [u8; 256] = d.as_slice().try_into().unwrap();
    let p_arr: [u8; 128] = p.as_slice().try_into().unwrap();
    let q_arr: [u8; 128] = q.as_slice().try_into().unwrap();
    let dp_arr: [u8; 128] = dp.as_slice().try_into().unwrap();
    let dq_arr: [u8; 128] = dq.as_slice().try_into().unwrap();
    let qinv_arr: [u8; 128] = qinv.as_slice().try_into().unwrap();
    let salt_arr: [u8; 32] = salt.as_slice().try_into().unwrap();

    let mut e_val: u64 = 0;
    for &b in &e_bytes {
        e_val = (e_val << 8) | u64::from(b);
    }

    // --- Generate PKCS#1v1.5 tests (non-CRT, group tgId=1) ---
    let mut pkcs_tests = Vec::new();
    for (i, msg_hex) in MESSAGES.iter().enumerate() {
        let msg = hex_decode(msg_hex);
        let sig = fips_rsa::rsa_pkcs1_v15_sign_2048_sha256_internal(
            &n_arr, &d_arr, &msg,
        )
        .expect("PKCS#1v1.5 sign failed");
        // Verify
        assert!(
            fips_rsa::rsa_pkcs1_v15_verify_2048_sha256_internal(&n_arr, e_val, &msg, &sig),
            "PKCS#1v1.5 verify failed for test {i}"
        );
        pkcs_tests.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "signature": "{}"}}"#,
            i + 1,
            msg_hex,
            hex_upper(&sig),
        ));
    }

    // --- Generate PSS tests (CRT, group tgId=2) ---
    let mut pss_tests = Vec::new();
    for (i, msg_hex) in MESSAGES.iter().enumerate() {
        let msg = hex_decode(msg_hex);
        let sig = fips_rsa::rsa_pss_sign_2048_sha256_crt_internal(
            &n_arr, e_val, &p_arr, &q_arr, &dp_arr, &dq_arr, &qinv_arr,
            &msg, &salt_arr,
        )
        .expect("PSS CRT sign failed");
        // Verify
        assert!(
            fips_rsa::rsa_pss_verify_2048_sha256_internal(&n_arr, e_val, &msg, &sig),
            "PSS verify failed for test {i}"
        );
        let tc_id = MESSAGES.len() + i + 1;
        pss_tests.push(format!(
            r#"        {{"tcId": {}, "message": "{}", "salt": "{}", "signature": "{}"}}"#,
            tc_id,
            msg_hex,
            SALT_HEX,
            hex_upper(&sig),
        ));
    }

    let json = format!(
        r#"{{
  "vsId": 0,
  "algorithm": "RSA",
  "mode": "sigGen",
  "revision": "FIPS186-5",
  "isSample": true,
  "testGroups": [
    {{
      "tgId": 1,
      "testType": "GDT",
      "sigType": "pkcs1v1.5",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "n": "{N_HEX}",
      "e": "{E_HEX}",
      "d": "{D_HEX}",
      "tests": [
{}
      ]
    }},
    {{
      "tgId": 2,
      "testType": "GDT",
      "sigType": "pss",
      "modulo": 2048,
      "hashAlg": "SHA2-256",
      "saltLen": 32,
      "n": "{N_HEX}",
      "e": "{E_HEX}",
      "p": "{P_HEX}",
      "q": "{Q_HEX}",
      "dmp1": "{DP_HEX}",
      "dmq1": "{DQ_HEX}",
      "iqmp": "{QINV_HEX}",
      "tests": [
{}
      ]
    }}
  ]
}}"#,
        pkcs_tests.join(",\n"),
        pss_tests.join(",\n"),
    );

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("vendor/nist/acvp-server/gen-val/json-files/RSA-sigGen-FIPS186-5");
    std::fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("kat-slice.json");
    let mut f = std::fs::File::create(&out_path).unwrap();
    f.write_all(json.as_bytes()).unwrap();
    println!("Wrote {}", out_path.display());
}
