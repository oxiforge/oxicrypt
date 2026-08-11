# Algorithm testing evidence

<!-- Generated from acvp-demo-evidence.json by scripts/gen-acvp-evidence-md.py.
     Do not edit by hand; CI regenerates this file and fails if it differs. -->

Every algorithm oxicrypt has submitted to NIST for grading, and the verdict NIST returned.

This is the submission record, not an inventory of the codebase: an algorithm implemented here
but never submitted does not appear. **XMSS is the notable absence** — it is implemented, but
NIST's demonstration server does not advertise it, so it cannot be submitted for grading at all.

> **Not a certificate.** These gradings come from NIST's ACVP *demonstration* server. It runs
> the same protocol and the same test-vector generators as the certification path, but issues no
> certificate. **oxicrypt holds no CAVP or FIPS 140-3 certificate** and has not been submitted to
> a testing laboratory.

| | |
|---|--:|
| Algorithm families | **20** |
| ACVP services graded | **78** |
| Vector sets graded | **154** — 141 passed, 13 failed |
| NIST test sessions | 151 |
| Period | 2026-04-27 to 2026-08-09 |

## What was graded

One row per ACVP service — the (algorithm, mode, revision) tuple NIST registers and grades.

**AES** — 7 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `ACVP-AES-CBC` | — | 1.0 | 1 | — |
| `ACVP-AES-CCM` | — | 1.0 | 1 | — |
| `ACVP-AES-CTR` | — | 1.0 | 1 | — |
| `ACVP-AES-ECB` | — | 1.0 | 1 | — |
| `ACVP-AES-GCM` | — | 1.0 | 1 | — |
| `ACVP-AES-KW` | — | 1.0 | 1 | — |
| `ACVP-AES-KWP` | — | 1.0 | 1 | — |

**CMAC** — 1 service

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `CMAC-AES` | — | 1.0 | 1 | — |

**DRBG** — 3 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `ctrDRBG` | — | 1.0 | 1 | — |
| `hashDRBG` | — | 1.0 | 1 | 360 |
| `hmacDRBG` | — | 1.0 | 1 | 360 |

**ECDSA** — 4 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `ECDSA` | keyGen | FIPS186-5 | 1 | — |
| `ECDSA` | keyVer | FIPS186-5 | 2 | — |
| `ECDSA` | sigGen | FIPS186-5 | 1 | — |
| `ECDSA` | sigVer | FIPS186-5 | 1 | — |

**EdDSA** — 4 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `EDDSA` | keyGen | 1.0 | 1 | — |
| `EDDSA` | keyVer | 1.0 | 1 | — |
| `EDDSA` | sigGen | 1.0 | 1 | — |
| `EDDSA` | sigVer | 1.0 | 1 | — |

**HMAC** — 11 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `HMAC-SHA-1` | — | 1.0 | 1 | — |
| `HMAC-SHA2-224` | — | 1.0 | 1 | — |
| `HMAC-SHA2-256` | — | 1.0 | 1 | — |
| `HMAC-SHA2-384` | — | 1.0 | 1 | — |
| `HMAC-SHA2-512` | — | 1.0 | 1 | — |
| `HMAC-SHA2-512/224` | — | 1.0 | 1 | — |
| `HMAC-SHA2-512/256` | — | 1.0 | 1 | — |
| `HMAC-SHA3-224` | — | 1.0 | 1 | — |
| `HMAC-SHA3-256` | — | 1.0 | 1 | — |
| `HMAC-SHA3-384` | — | 1.0 | 1 | — |
| `HMAC-SHA3-512` | — | 1.0 | 1 | — |

**KAS** — 2 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `KAS-ECC-SSC` | — | Sp800-56Ar3 | 1 | — |
| `KAS-FFC-SSC` | — | Sp800-56Ar3 | 2 | 25 |

**KBKDF** — 1 service

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `KDF` | — | 1.0 | 3 | 1300 |

**KDA-HKDF** — 1 service

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `KDA` | HKDF | Sp800-56Cr2 | 1 | — |

**KTS-IFC (OAEP)** — 1 service

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `KTS-IFC` | — | Sp800-56Br2 | 1 | 30 |

**LMS** — 5 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `LMS` | keyGen | 1.0 | 3 | 432 |
| `LMS` | sigGen | 1.0 | 4 | 800 |
| `LMS` | sigGen | SP800-208 | 6 | 1184 |
| `LMS` | sigVer | 1.0 | 5 | 848 |
| `LMS` | sigVer | SP800-208 | 1 | 320 |

**ML-DSA** — 3 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `ML-DSA` | keyGen | FIPS204 | 3 | 100 |
| `ML-DSA` | sigGen | FIPS204 | 3 | 94 |
| `ML-DSA` | sigVer | FIPS204 | 3 | 60 |

**ML-KEM** — 2 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `ML-KEM` | encapDecap | FIPS203 | 2 | 105 |
| `ML-KEM` | keyGen | FIPS203 | 1 | 75 |

**PBKDF** — 1 service

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `PBKDF` | — | 1.0 | 1 | — |

**RSA** — 5 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `RSA` | decryptionPrimitive | Sp800-56Br2 | 1 | 30 |
| `RSA` | keyGen | FIPS186-5 | 1 | 75 |
| `RSA` | sigGen | FIPS186-5 | 1 | 62 |
| `RSA` | sigVer | FIPS186-5 | 1 | 108 |
| `RSA` | signaturePrimitive | 2.0 | 1 | 30 |

**SHA-1 / SHA-2** — 7 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `SHA-1` | — | 1.0 | 1 | — |
| `SHA2-224` | — | 1.0 | 1 | — |
| `SHA2-256` | — | 1.0 | 1 | — |
| `SHA2-384` | — | 1.0 | 1 | — |
| `SHA2-512` | — | 1.0 | 1 | — |
| `SHA2-512/224` | — | 1.0 | 1 | — |
| `SHA2-512/256` | — | 1.0 | 1 | — |

**SHA-3** — 4 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `SHA3-224` | — | 2.0 | 1 | — |
| `SHA3-256` | — | 2.0 | 1 | — |
| `SHA3-384` | — | 2.0 | 1 | — |
| `SHA3-512` | — | 2.0 | 1 | — |

**SLH-DSA** — 3 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `SLH-DSA` | keyGen | FIPS205 | 13 | 120 |
| `SLH-DSA` | sigGen | FIPS205 | 13 | 84 |
| `SLH-DSA` | sigVer | FIPS205 | 13 | 168 |

**SP 800-185 (XOF)** — 10 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `KMAC-128` | — | 1.0 | 2 | — |
| `KMAC-256` | — | 1.0 | 2 | — |
| `ParallelHash-128` | — | 1.0 | 1 | 402 |
| `ParallelHash-256` | — | 1.0 | 1 | 402 |
| `SHAKE-128` | — | FIPS202 | 1 | — |
| `SHAKE-256` | — | FIPS202 | 1 | — |
| `TupleHash-128` | — | 1.0 | 1 | 402 |
| `TupleHash-256` | — | 1.0 | 1 | 402 |
| `cSHAKE-128` | — | 1.0 | 1 | 201 |
| `cSHAKE-256` | — | 1.0 | 1 | 201 |

**TLS KDFs** — 3 services

| Algorithm | Mode | Revision | Vector sets | Cases |
|---|---|---|--:|--:|
| `TLS-v1.2` | KDF | RFC7627 | 1 | — |
| `TLS-v1.3` | KDF | RFC8446 | 1 | — |
| `kdf-components` | tls | 1.0 | 1 | — |

<details>
<summary>Full session record — all 154 graded vector sets, with the NIST identifiers</summary>

| Graded | Session | Vector set | Algorithm | Mode | Revision | Verdict | Cases |
|---|--:|--:|---|---|---|---|--:|
| 2026-04-27 | 724101 | 3821745 | `ACVP-AES-CBC` | — | 1.0 | passed | — |
| 2026-04-27 | 724112 | 3821756 | `CMAC-AES` | — | 1.0 | passed | — |
| 2026-04-27 | 724122 | 3821766 | `ACVP-AES-GCM` | — | 1.0 | passed | — |
| 2026-04-27 | 724132 | 3821780 | `HMAC-SHA2-512` | — | 1.0 | passed | — |
| 2026-04-27 | 724146 | 3821794 | `HMAC-SHA-1` | — | 1.0 | passed | — |
| 2026-04-27 | 724216 | 3822111 | `TLS-v1.3` | KDF | RFC8446 | passed | — |
| 2026-04-28 | 724470 | 3823590 | `SHA3-384` | — | 2.0 | passed | — |
| 2026-04-28 | 724475 | 3823595 | `HMAC-SHA2-384` | — | 1.0 | passed | — |
| 2026-04-28 | 724479 | 3823599 | `ACVP-AES-ECB` | — | 1.0 | passed | — |
| 2026-04-28 | 724499 | 3823724 | `SHA3-224` | — | 2.0 | passed | — |
| 2026-04-28 | 724515 | 3823821 | `SHA3-512` | — | 2.0 | passed | — |
| 2026-04-28 | 724516 | 3823822 | `SHA3-256` | — | 2.0 | passed | — |
| 2026-04-28 | 724517 | 3823823 | `HMAC-SHA2-256` | — | 1.0 | passed | — |
| 2026-04-28 | 724524 | 3823830 | `kdf-components` | tls | 1.0 | passed | — |
| 2026-04-28 | 724526 | 3823832 | `TLS-v1.2` | KDF | RFC7627 | passed | — |
| 2026-05-01 | 725698 | 3828196 | `ACVP-AES-CTR` | — | 1.0 | passed | — |
| 2026-05-01 | 725701 | 3828199 | `ACVP-AES-KW` | — | 1.0 | **failed** | — |
| 2026-05-01 | 725713 | 3828211 | `ACVP-AES-KW` | — | 1.0 | passed | — |
| 2026-05-01 | 725714 | 3828212 | `ACVP-AES-KWP` | — | 1.0 | passed | — |
| 2026-05-01 | 725739 | 3828239 | `ACVP-AES-CCM` | — | 1.0 | passed | — |
| 2026-05-01 | 725749 | 3828249 | `KMAC-128` | — | 1.0 | **failed** | — |
| 2026-05-01 | 725751 | 3828251 | `KMAC-256` | — | 1.0 | **failed** | — |
| 2026-05-01 | 725755 | 3828270 | `KMAC-128` | — | 1.0 | passed | — |
| 2026-05-01 | 725758 | 3828327 | `KMAC-256` | — | 1.0 | passed | — |
| 2026-05-01 | 725768 | 3828486 | `SHAKE-128` | — | FIPS202 | passed | — |
| 2026-05-01 | 725772 | 3828638 | `SHAKE-256` | — | FIPS202 | passed | — |
| 2026-05-01 | 725776 | 3828791 | `ECDSA` | keyVer | FIPS186-5 | passed | — |
| 2026-05-01 | 725791 | 3829144 | `ECDSA` | keyVer | FIPS186-5 | passed | — |
| 2026-05-01 | 725809 | 3829447 | `ECDSA` | sigVer | FIPS186-5 | passed | — |
| 2026-05-03 | 726883 | 3838951 | `HMAC-SHA2-224` | — | 1.0 | passed | — |
| 2026-05-03 | 726884 | 3838952 | `HMAC-SHA2-512/224` | — | 1.0 | passed | — |
| 2026-05-03 | 726885 | 3838953 | `HMAC-SHA2-512/256` | — | 1.0 | passed | — |
| 2026-05-03 | 726886 | 3838954 | `HMAC-SHA3-224` | — | 1.0 | passed | — |
| 2026-05-03 | 726887 | 3838955 | `HMAC-SHA3-256` | — | 1.0 | passed | — |
| 2026-05-03 | 726888 | 3838956 | `HMAC-SHA3-384` | — | 1.0 | passed | — |
| 2026-05-03 | 726889 | 3838957 | `HMAC-SHA3-512` | — | 1.0 | passed | — |
| 2026-05-03 | 726890 | 3838958 | `SHA2-256` | — | 1.0 | passed | — |
| 2026-05-03 | 726891 | 3838959 | `SHA2-224` | — | 1.0 | passed | — |
| 2026-05-03 | 726892 | 3838960 | `SHA2-384` | — | 1.0 | passed | — |
| 2026-05-03 | 726893 | 3838961 | `SHA2-512` | — | 1.0 | passed | — |
| 2026-05-03 | 726894 | 3838962 | `SHA2-512/224` | — | 1.0 | passed | — |
| 2026-05-03 | 726895 | 3838963 | `SHA2-512/256` | — | 1.0 | passed | — |
| 2026-05-03 | 726896 | 3838964 | `SHA-1` | — | 1.0 | passed | — |
| 2026-05-03 | 726897 | 3838965 | `ctrDRBG` | — | 1.0 | passed | — |
| 2026-05-03 | 726898 | 3838966 | `KDA` | HKDF | Sp800-56Cr2 | passed | — |
| 2026-05-03 | 726902 | 3838975 | `ECDSA` | sigGen | FIPS186-5 | passed | — |
| 2026-05-03 | 726908 | 3838991 | `ECDSA` | keyGen | FIPS186-5 | passed | — |
| 2026-05-03 | 726913 | 3839005 | `KMAC-128` | — | 1.0 | passed | — |
| 2026-05-03 | 726919 | 3839012 | `KMAC-256` | — | 1.0 | passed | — |
| 2026-05-03 | 726921 | 3839014 | `KAS-ECC-SSC` | — | Sp800-56Ar3 | passed | — |
| 2026-05-03 | 726925 | 3839020 | `PBKDF` | — | 1.0 | passed | — |
| 2026-05-03 | 726927 | 3839022 | `EDDSA` | keyGen | 1.0 | passed | — |
| 2026-05-04 | 727018 | 3839617 | `KDF` | — | 1.0 | **failed** | — |
| 2026-05-04 | 727083 | 3840237 | `KDF` | — | 1.0 | passed | — |
| 2026-05-04 | 727087 | 3840242 | `KDF` | — | 1.0 | **failed** | — |
| 2026-05-04 | 727099 | 3840453 | `KDF` | — | 1.0 | passed | — |
| 2026-05-05 | 727271 | 3841780 | `EDDSA` | sigVer | 1.0 | passed | — |
| 2026-05-05 | 727272 | 3841781 | `EDDSA` | keyVer | 1.0 | passed | — |
| 2026-05-05 | 727294 | 3841995 | `EDDSA` | sigGen | 1.0 | passed | — |
| 2026-05-06 | 727385 | 3842699 | `KAS-FFC-SSC` | — | Sp800-56Ar3 | passed | — |
| 2026-05-07 | 727778 | 3844675 | `ML-KEM` | encapDecap | FIPS203 | **failed** | — |
| 2026-05-07 | 727796 | 3844699 | `ML-KEM` | encapDecap | FIPS203 | passed | — |
| 2026-05-07 | 727797 | 3844700 | `SLH-DSA` | keyGen | FIPS205 | passed | — |
| 2026-05-07 | 727798 | 3844703 | `SLH-DSA` | sigGen | FIPS205 | passed | — |
| 2026-05-07 | 727803 | 3844732 | `SLH-DSA` | sigVer | FIPS205 | passed | — |
| 2026-05-07 | 727840 | 3844884 | `ML-DSA` | keyGen | FIPS204 | passed | — |
| 2026-05-07 | 727841 | 3844885 | `ML-DSA` | sigGen | FIPS204 | passed | — |
| 2026-05-07 | 727843 | 3844889 | `ML-DSA` | sigVer | FIPS204 | passed | — |
| 2026-05-07 | 727856 | 3844902 | `LMS` | keyGen | 1.0 | **failed** | — |
| 2026-05-07 | 727859 | 3844907 | `LMS` | keyGen | 1.0 | passed | — |
| 2026-05-07 | 727860 | 3844908 | `LMS` | sigGen | 1.0 | passed | — |
| 2026-05-07 | 727861 | 3844909 | `LMS` | sigVer | 1.0 | passed | — |
| 2026-05-11 | 728969 | 3851852 | `cSHAKE-128` | — | 1.0 | **failed** | — |
| 2026-05-11 | 728996 | 3852190 | `cSHAKE-128` | — | 1.0 | passed | 201 |
| 2026-05-11 | 728998 | 3852193 | `cSHAKE-256` | — | 1.0 | passed | 201 |
| 2026-05-11 | 729018 | 3852233 | `TupleHash-128` | — | 1.0 | **failed** | 402 |
| 2026-05-11 | 729022 | 3852241 | `TupleHash-128` | — | 1.0 | **failed** | 402 |
| 2026-05-11 | 729028 | 3852252 | `TupleHash-128` | — | 1.0 | passed | 402 |
| 2026-05-11 | 729030 | 3852254 | `TupleHash-256` | — | 1.0 | passed | 402 |
| 2026-05-11 | 729038 | 3852381 | `ParallelHash-128` | — | 1.0 | passed | 402 |
| 2026-05-11 | 729040 | 3852385 | `ParallelHash-256` | — | 1.0 | passed | 402 |
| 2026-05-13 | 729653 | 3855619 | `KDF` | — | 1.0 | passed | 1300 |
| 2026-05-13 | 729659 | 3855727 | `KAS-FFC-SSC` | — | Sp800-56Ar3 | passed | 25 |
| 2026-05-13 | 729663 | 3855731 | `RSA` | sigVer | FIPS186-5 | passed | 108 |
| 2026-05-13 | 729667 | 3855837 | `RSA` | keyGen | FIPS186-5 | passed | 75 |
| 2026-05-13 | 729669 | 3855839 | `RSA` | sigGen | FIPS186-5 | passed | 62 |
| 2026-05-13 | 729670 | 3855840 | `RSA` | signaturePrimitive | 2.0 | passed | 30 |
| 2026-05-13 | 729677 | 3855957 | `RSA` | decryptionPrimitive | Sp800-56Br2 | passed | 30 |
| 2026-05-13 | 729740 | 3856597 | `hashDRBG` | — | 1.0 | passed | 360 |
| 2026-05-13 | 729742 | 3856599 | `hmacDRBG` | — | 1.0 | passed | 360 |
| 2026-05-14 | 729996 | 3857283 | `KTS-IFC` | — | Sp800-56Br2 | passed | 30 |
| 2026-05-14 | 730219 | 3858709 | `ML-KEM` | keyGen | FIPS203 | passed | 75 |
| 2026-05-14 | 730219 | 3858710 | `ML-KEM` | encapDecap | FIPS203 | passed | 105 |
| 2026-05-15 | 730469 | 3859349 | `ML-DSA` | keyGen | FIPS204 | passed | 25 |
| 2026-05-15 | 730469 | 3859350 | `ML-DSA` | sigGen | FIPS204 | **failed** | 22 |
| 2026-05-15 | 730469 | 3859351 | `ML-DSA` | sigVer | FIPS204 | passed | 15 |
| 2026-05-15 | 730519 | 3859456 | `ML-DSA` | sigGen | FIPS204 | passed | 22 |
| 2026-05-15 | 730583 | 3859878 | `ML-DSA` | keyGen | FIPS204 | passed | 75 |
| 2026-05-15 | 730598 | 3859996 | `ML-DSA` | sigGen | FIPS204 | passed | 72 |
| 2026-05-15 | 730599 | 3859997 | `ML-DSA` | sigVer | FIPS204 | passed | 45 |
| 2026-05-15 | 730746 | 3860771 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-15 | 730749 | 3860775 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-15 | 730750 | 3860776 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730835 | 3861253 | `SLH-DSA` | keyGen | FIPS205 | **failed** | 10 |
| 2026-05-16 | 730837 | 3861255 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730838 | 3861256 | `SLH-DSA` | sigGen | FIPS205 | **failed** | 7 |
| 2026-05-16 | 730839 | 3861257 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730840 | 3861258 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730841 | 3861259 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730842 | 3861260 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730843 | 3861261 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730844 | 3861262 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730845 | 3861263 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730846 | 3861264 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730849 | 3861285 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730853 | 3861291 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730858 | 3861318 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730861 | 3861326 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730868 | 3861345 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730875 | 3861364 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730881 | 3861385 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730886 | 3861396 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730889 | 3861405 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730890 | 3861406 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730891 | 3861407 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730894 | 3861410 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730897 | 3861419 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730903 | 3861426 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730907 | 3861435 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730908 | 3861436 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730911 | 3861439 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730916 | 3861452 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730919 | 3861455 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730922 | 3861466 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730923 | 3861467 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-16 | 730926 | 3861471 | `SLH-DSA` | keyGen | FIPS205 | passed | 10 |
| 2026-05-16 | 730931 | 3861487 | `SLH-DSA` | sigGen | FIPS205 | passed | 7 |
| 2026-05-16 | 730934 | 3861500 | `SLH-DSA` | sigVer | FIPS205 | passed | 14 |
| 2026-05-17 | 731047 | 3861959 | `LMS` | sigVer | 1.0 | passed | 320 |
| 2026-06-10 | 741293 | 3901787 | `LMS` | sigVer | 1.0 | passed | 192 |
| 2026-06-10 | 741298 | 3901792 | `LMS` | keyGen | 1.0 | passed | 192 |
| 2026-06-10 | 741327 | 3901821 | `LMS` | sigGen | 1.0 | passed | 480 |
| 2026-06-13 | 743683 | 3912624 | `LMS` | sigVer | 1.0 | passed | 16 |
| 2026-07-20 | 753430 | 3966778 | `LMS` | sigGen | 1.0 | passed | 40 |
| 2026-07-24 | 754542 | 3976184 | `LMS` | keyGen | 1.0 | passed | 240 |
| 2026-07-24 | 754715 | 3976999 | `LMS` | sigVer | 1.0 | passed | 320 |
| 2026-07-25 | 754795 | 3977576 | `LMS` | sigGen | 1.0 | passed | 280 |
| 2026-07-25 | 754895 | 3977898 | `LMS` | sigVer | SP800-208 | passed | 320 |
| 2026-07-25 | 754896 | 3977899 | `LMS` | sigGen | SP800-208 | passed | 32 |
| 2026-07-28 | 755665 | 3981311 | `LMS` | sigGen | SP800-208 | passed | 832 |
| 2026-08-05 | 758163 | 3993919 | `LMS` | sigGen | SP800-208 | passed | 160 |
| 2026-08-06 | 758378 | 3995036 | `LMS` | sigGen | SP800-208 | passed | 80 |
| 2026-08-08 | 758706 | 3997505 | `LMS` | sigGen | SP800-208 | passed | 40 |
| 2026-08-09 | 758856 | 3998015 | `LMS` | sigGen | SP800-208 | passed | 40 |

</details>

## Notes

**Why some case counts are blank.** The test harness did not retain the full verdict body
in its earliest sessions, so those gradings kept the verdict but not the per-case detail.
**Every grading up to and including 2026-05-07 lacks a count** (72 of 73 blanks). Retention began with the next
session and has held since.

There is **1 exception after that date** (1 failed), listed in the table
above rather than smoothed over: vector set 3851852 on 2026-05-11.

**Failures are listed.** A failed vector set means that submission did not pass; where the
implementation was then corrected, a later passing row for the same service records it.

**Case counts are partial.** A count appears only where the full verdict body was retained — 81 of 154 sets, and 16 of 59 algorithms. It is
left blank rather than estimated elsewhere, so the project's overall test-case total cannot be
rebuilt from this page and is not claimed here.

**Checking these rows.** ACVP sessions expire thirty days after creation and are scoped to the
account that created them, so a third party cannot re-run them. The identifiers support a
specific question to NIST or to a testing laboratory about a named session, and hold this record
against any future certification submission.

**Source.** Generated from [`acvp-demo-evidence.json`](acvp-demo-evidence.json), the machine-
readable form of the same record. Raw session transcripts are not published: each embeds an
account access token carrying personal data in cleartext.

