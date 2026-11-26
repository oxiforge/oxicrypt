// Hashes, signs and establishes a shared secret through the oxicrypt C
// library, checking each result against the line examples/README.md expects.
//
//   node example.js <bundle-dir> <out-dir>
//   node example.js <bundle-dir> decaps <dk-file> <ct-file>
'use strict';

const { timingSafeEqual } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const koffi = require('koffi');

const MESSAGE = Buffer.from('The quick brown fox jumps over the lazy dog', 'ascii');
const SIG_FLIP_BYTE = 0;
const CT_FLIP_BYTE = 0;
const PERSONALIZATION = Buffer.from('oxicrypt example', 'ascii');
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

const PK_LEN = 2592, SK_LEN = 4896, SIG_LEN = 4627;
const EK_LEN = 1568, DK_LEN = 3168, CT_LEN = 1568, SS_LEN = 32;

const names = { linux: 'liboxicrypt_ffi.so.4', darwin: 'liboxicrypt_ffi.4.dylib', win32: 'oxicrypt_ffi.dll' };

const args = process.argv.slice(2);
const decapsMode = args.length === 4 && args[1] === 'decaps';
if (!decapsMode && args.length !== 2) {
    console.error('usage: node example.js <bundle-dir> <out-dir>\n       node example.js <bundle-dir> decaps <dk-file> <ct-file>');
    process.exit(2);
}

const lib = koffi.load(path.join(args[0], names[process.platform]));
koffi.opaque('OxiDrbg');
const oxi = {
    init: lib.func('int oxi_init(int profile)'),
    integrityStatus: lib.func('int oxi_integrity_status(void)'),
    integrityKeyFingerprint: lib.func('int oxi_integrity_key_fingerprint(uint8_t *out, uintptr_t out_len)'),
    sha256: lib.func('int oxi_sha256(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out)'),
    hmacDrbgSha256NewRbg: lib.func('int oxi_hmac_drbg_sha256_new_rbg(_Out_ OxiDrbg **out)'),
    drbgInstantiate: lib.func('int oxi_drbg_instantiate(OxiDrbg *h, const uint8_t *perso, uintptr_t perso_len)'),
    drbgFree: lib.func('void oxi_drbg_free(OxiDrbg *h)'),
    mlDsa87KeygenRbg: lib.func('int oxi_ml_dsa_87_keygen_rbg(OxiDrbg *rbg, uint8_t *pk_out, uint8_t *sk_out, uint8_t *seed_out)'),
    mlDsa87Sign: lib.func('int oxi_ml_dsa_87_sign(const uint8_t *sk_ptr, const uint8_t *msg_ptr, uintptr_t msg_len, const uint8_t *ctx_ptr, uintptr_t ctx_len, uint8_t *sig_out)'),
    mlDsa87Verify: lib.func('int oxi_ml_dsa_87_verify(const uint8_t *pk_ptr, const uint8_t *msg_ptr, uintptr_t msg_len, const uint8_t *ctx_ptr, uintptr_t ctx_len, const uint8_t *sig_ptr)'),
    mlKem1024KeygenRbg: lib.func('int oxi_ml_kem_1024_keygen_rbg(OxiDrbg *rbg, uint8_t *ek_out, uint8_t *dk_out, uint8_t *seed_out)'),
    mlKem1024EncapsulateRbg: lib.func('int oxi_ml_kem_1024_encapsulate_rbg(const uint8_t *ek_ptr, OxiDrbg *rbg, uint8_t *ss_out, uint8_t *ct_out)'),
    mlKem1024Decapsulate: lib.func('int oxi_ml_kem_1024_decapsulate(const uint8_t *dk_ptr, const uint8_t *ct_ptr, uint8_t *ss_out)'),
};

let rbg = null;
const sk = Buffer.alloc(SK_LEN), dk = Buffer.alloc(DK_LEN);
const ss = Buffer.alloc(SS_LEN), ss2 = Buffer.alloc(SS_LEN);

// Frees the DRBG handle, which wipes its state, and wipes every secret. The
// hex string printed for the shared secret is a JavaScript string, which
// cannot be wiped.
function release() {
    oxi.drbgFree(rbg);
    rbg = null;
    for (const secret of [sk, dk, ss, ss2]) secret.fill(0);
}

// Thrown to end the program with status 1. Unwinding to the end of the
// script, rather than calling process.exit, lets Node finish writing the
// lines already printed, which it may still hold for a pipe.
class Failure extends Error {}

function fail() {
    throw new Failure();
}

// Prints a line to stdout and fails when it cannot. console.log reports a
// failed write only as an event, after which the program would still exit
// 0 having lost a line.
function say(line) {
    try {
        fs.writeSync(1, `${line}\n`);
    } catch (e) {
        console.error(`stdout: ${e.message}`);
        fail();
    }
}

// Prints `got` when it equals `want`; otherwise prints both and fails.
function expect(want, got) {
    if (want !== got) {
        console.error(`expected: ${want}\n     got: ${got}`);
        fail();
    }
    say(got);
}

function expectOk(what, rc) {
    expect(`${what} ok`, rc === 0 ? `${what} ok` : `${what} returned ${rc}`);
}

// Fails naming the call when it returned other than Ok.
function check(call, rc) {
    if (rc !== 0) {
        console.error(`${call} returned ${rc}`);
        fail();
    }
}

// Writes the file, readable and writable by its owner only when `ownerOnly`
// is set, as the decapsulation key is. An existing file keeps its mode
// through truncation, so the mode is set again. On Windows the file takes
// the access control list of its directory.
function write(dir, name, data, ownerOnly = false) {
    let fd;
    try {
        fd = fs.openSync(path.join(dir, name), 'w', ownerOnly ? 0o600 : 0o644);
        if (ownerOnly && process.platform !== 'win32') fs.fchmodSync(fd, 0o600);
        fs.writeSync(fd, data);
    } catch (e) {
        console.error(e.message);
        fail();
    } finally {
        if (fd !== undefined) fs.closeSync(fd);
    }
}

// Fills `into` from the file, which must hold exactly into.length bytes; it
// reads no more than one byte past that.
function read(file, into) {
    let fd, n, extra;
    try {
        fd = fs.openSync(file, 'r');
        n = fs.readSync(fd, into, 0, into.length, 0);
        extra = fs.readSync(fd, Buffer.alloc(1), 0, 1, into.length);
    } catch (e) {
        console.error(e.message);
        fail();
    } finally {
        if (fd !== undefined) fs.closeSync(fd);
    }
    if (n !== into.length || extra !== 0) {
        console.error(`${file}: expected ${into.length} bytes`);
        fail();
    }
}

// Starts the module and reads its integrity result. Prints the fingerprint
// of the key the library trusts to stderr, and fails unless the module is
// operational with its integrity test passed (status 1), leading with the
// condition that failed.
function start() {
    const rc = oxi.init(0);
    const status = oxi.integrityStatus();
    const fp = Buffer.alloc(32);
    const fpRc = oxi.integrityKeyFingerprint(fp, fp.length);
    const fpLine = `verify key sha256:${fp.toString('hex')}`;
    if (rc === 0 && status === 1 && fpRc === 0) {
        console.error(fpLine);
        return;
    }
    if (rc !== 0) {
        console.error(`oxi_init returned ${rc}: the module refused to start`);
    } else if (status !== 1) {
        console.error(`oxi_init returned 0 but the integrity test reported status ${status}, not 1 (passed)`);
    } else {
        console.error(`oxi_integrity_key_fingerprint returned ${fpRc} after the integrity test passed`);
        fail();
    }
    console.error(`integrity status ${status}`);
    console.error(fpRc === 0 ? fpLine : `oxi_integrity_key_fingerprint returned ${fpRc}`);
    fail();
}

function decaps(dkFile, ctFile) {
    start();
    const ct = Buffer.alloc(CT_LEN);
    read(dkFile, dk);
    read(ctFile, ct);
    check('oxi_ml_kem_1024_decapsulate', oxi.mlKem1024Decapsulate(dk, ct, ss));
    say(`ml-kem-1024 ss ${ss.toString('hex')}`);
}

// Decapsulates `ct` into ss2 and describes the result against ss.
function decapsLine(what, ct) {
    const rc = oxi.mlKem1024Decapsulate(dk, ct, ss2);
    if (rc !== 0) return `${what} returned ${rc}`;
    return `${what} ${timingSafeEqual(ss, ss2) ? 'match' : 'differs'}`;
}

function run(out) {
    start();

    const abc = Buffer.from('abc', 'ascii');
    const digest = Buffer.alloc(32);
    check('oxi_sha256', oxi.sha256(abc, abc.length, digest));
    expect(`sha256 abc ${SHA256_ABC}`, `sha256 abc ${digest.toString('hex')}`);

    const handle = [null];
    check('oxi_hmac_drbg_sha256_new_rbg', oxi.hmacDrbgSha256NewRbg(handle));
    rbg = handle[0];
    check('oxi_drbg_instantiate', oxi.drbgInstantiate(rbg, PERSONALIZATION, PERSONALIZATION.length));
    say('drbg instantiated');

    const pk = Buffer.alloc(PK_LEN), sig = Buffer.alloc(SIG_LEN);
    expectOk('ml-dsa-87 keygen', oxi.mlDsa87KeygenRbg(rbg, pk, sk, null));
    check('oxi_ml_dsa_87_sign', oxi.mlDsa87Sign(sk, MESSAGE, MESSAGE.length, null, 0, sig));
    write(out, 'pk.bin', pk);
    write(out, 'message.txt', MESSAGE);
    write(out, 'sig.bin', sig);
    expectOk('ml-dsa-87 verify', oxi.mlDsa87Verify(pk, MESSAGE, MESSAGE.length, null, 0, sig));
    const tamperedSig = Buffer.from(sig);
    tamperedSig[SIG_FLIP_BYTE] ^= 0x01;
    const rc = oxi.mlDsa87Verify(pk, MESSAGE, MESSAGE.length, null, 0, tamperedSig);
    expect('ml-dsa-87 verify-tampered rejected 22',
        rc === 0 ? 'ml-dsa-87 verify-tampered accepted' : `ml-dsa-87 verify-tampered rejected ${rc}`);

    const ek = Buffer.alloc(EK_LEN), ct = Buffer.alloc(CT_LEN);
    expectOk('ml-kem-1024 keygen', oxi.mlKem1024KeygenRbg(rbg, ek, dk, null));
    check('oxi_ml_kem_1024_encapsulate_rbg', oxi.mlKem1024EncapsulateRbg(ek, rbg, ss, ct));
    write(out, 'ek.bin', ek);
    write(out, 'dk.bin', dk, true);
    write(out, 'ct.bin', ct);
    expect('ml-kem-1024 decaps match', decapsLine('ml-kem-1024 decaps', ct));
    const tamperedCt = Buffer.from(ct);
    tamperedCt[CT_FLIP_BYTE] ^= 0x01;
    expect('ml-kem-1024 decaps-tampered differs', decapsLine('ml-kem-1024 decaps-tampered', tamperedCt));

    say(`ml-kem-1024 ss ${ss.toString('hex')}`);
}

try {
    if (decapsMode) {
        decaps(args[2], args[3]);
    } else {
        run(args[1]);
    }
} catch (e) {
    if (!(e instanceof Failure)) throw e;
    process.exitCode = 1;
} finally {
    release();
}
