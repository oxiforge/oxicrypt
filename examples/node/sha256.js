// Prints the SHA-256 digest of "abc", computed by the oxicrypt C library
// loaded from the bundle directory given as the first argument.
'use strict';

const path = require('node:path');
const koffi = require('koffi');

const names = { linux: 'liboxicrypt_ffi.so.2', darwin: 'liboxicrypt_ffi.2.dylib', win32: 'oxicrypt_ffi.dll' };

if (process.argv.length !== 3) {
    console.error('usage: node sha256.js <bundle-dir>');
    process.exit(2);
}
const lib = koffi.load(path.join(process.argv[2], names[process.platform]));
const oxiInit = lib.func('int oxi_init(int profile)');
const oxiSha256 = lib.func('int oxi_sha256(const uint8_t *data_ptr, uintptr_t data_len, uint8_t *out)');

const rc = oxiInit(0);
if (rc !== 0) {
    console.error(`oxi_init returned ${rc}: the module refused to start`);
    process.exit(1);
}
const data = Buffer.from('abc');
const out = Buffer.alloc(32);
const hashRc = oxiSha256(data, data.length, out);
if (hashRc !== 0) {
    console.error(`oxi_sha256 returned ${hashRc}`);
    process.exit(1);
}
console.log(out.toString('hex'));
