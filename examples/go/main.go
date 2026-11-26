// Command example hashes, signs and establishes a shared secret through the
// oxicrypt C library, checking each result against the line
// examples/README.md expects.
//
//	example <bundle-dir> <out-dir>
//	example <bundle-dir> decaps <dk-file> <ct-file>
//
// cgo links the library when the program is built, so <bundle-dir> is not
// read; it is taken so that every example has the same arguments.
package main

/*
#include "oxicrypt.h"
*/
import "C"

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"
)

const (
	MESSAGE         = "The quick brown fox jumps over the lazy dog"
	SIG_FLIP_BYTE   = 0
	CT_FLIP_BYTE    = 0
	PERSONALIZATION = "oxicrypt example"
	SHA256_ABC      = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

const (
	pkLen  = 2592
	skLen  = 4896
	sigLen = 4627
	ekLen  = 1568
	dkLen  = 3168
	ctLen  = 1568
	ssLen  = 32
)

var (
	rbg *C.OxiDrbg
	sk  = make([]byte, skLen)
	dk  = make([]byte, dkLen)
	ss  = make([]byte, ssLen)
	ss2 = make([]byte, ssLen)
)

func ptr(b []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&b[0])) }

// release frees the DRBG handle, which wipes its state, and wipes every
// secret. The hex string printed for the shared secret is a Go string, which
// cannot be wiped.
func release() {
	C.oxi_drbg_free(rbg)
	rbg = nil
	for _, s := range [][]byte{sk, dk, ss, ss2} {
		clear(s)
	}
}

func fail() {
	release()
	os.Exit(1)
}

// say prints line to stdout and exits 1 when it cannot, so that a program
// that lost a line never exits 0.
func say(line string) {
	if _, err := fmt.Println(line); err != nil {
		fmt.Fprintln(os.Stderr, "stdout:", err)
		fail()
	}
}

// expect prints got when it equals want; otherwise it prints both and exits 1.
func expect(want, got string) {
	if want != got {
		fmt.Fprintf(os.Stderr, "expected: %s\n     got: %s\n", want, got)
		fail()
	}
	say(got)
}

func expectOK(what string, rc C.int) {
	got := what + " ok"
	if rc != C.OXI_RESULT_OK {
		got = fmt.Sprintf("%s returned %d", what, int(rc))
	}
	expect(what+" ok", got)
}

// check exits 1 naming the call when it returned other than Ok.
func check(call string, rc C.int) {
	if rc != C.OXI_RESULT_OK {
		fmt.Fprintf(os.Stderr, "%s returned %d\n", call, int(rc))
		fail()
	}
}

// write writes the file, readable and writable by its owner only when
// ownerOnly is set, as the decapsulation key is. An existing file keeps its
// mode through truncation, so the mode is set again. On Windows the file
// takes the access control list of its directory.
func write(dir, name string, data []byte, ownerOnly bool) {
	mode := os.FileMode(0o644)
	if ownerOnly {
		mode = 0o600
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err == nil {
		if ownerOnly {
			err = f.Chmod(mode)
		}
		if _, werr := f.Write(data); err == nil {
			err = werr
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fail()
	}
}

// read fills into from the file, which must hold exactly len(into) bytes;
// it reads no more than one byte past that.
func read(path string, into []byte) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fail()
	}
	defer f.Close()
	_, err = io.ReadFull(f, into)
	extra, _ := f.Read(make([]byte, 1))
	if err != nil || extra != 0 {
		fmt.Fprintf(os.Stderr, "%s: expected %d bytes\n", path, len(into))
		fail()
	}
}

// start starts the module and reads its integrity result. It prints the
// fingerprint of the key the library trusts to stderr, and exits 1 unless
// the module is operational with its integrity test passed (status 1),
// leading with the condition that failed.
func start() {
	rc := C.oxi_init(0)
	status := C.oxi_integrity_status()
	fp := make([]byte, 32)
	fpRC := C.oxi_integrity_key_fingerprint(ptr(fp), C.uintptr_t(len(fp)))
	if rc == C.OXI_RESULT_OK && status == 1 && fpRC == C.OXI_RESULT_OK {
		fmt.Fprintf(os.Stderr, "verify key sha256:%x\n", fp)
		return
	}
	switch {
	case rc != C.OXI_RESULT_OK:
		fmt.Fprintf(os.Stderr, "oxi_init returned %d: the module refused to start\n", int(rc))
	case status != 1:
		fmt.Fprintf(os.Stderr, "oxi_init returned 0 but the integrity test reported status %d, not 1 (passed)\n", int(status))
	default:
		fmt.Fprintf(os.Stderr, "oxi_integrity_key_fingerprint returned %d after the integrity test passed\n", int(fpRC))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "integrity status %d\n", int(status))
	if fpRC == C.OXI_RESULT_OK {
		fmt.Fprintf(os.Stderr, "verify key sha256:%x\n", fp)
	} else {
		fmt.Fprintf(os.Stderr, "oxi_integrity_key_fingerprint returned %d\n", int(fpRC))
	}
	os.Exit(1)
}

func decaps(dkPath, ctPath string) {
	start()
	ct := make([]byte, ctLen)
	read(dkPath, dk)
	read(ctPath, ct)
	check("oxi_ml_kem_1024_decapsulate", C.oxi_ml_kem_1024_decapsulate(ptr(dk), ptr(ct), ptr(ss)))
	say(fmt.Sprintf("ml-kem-1024 ss %x", ss))
}

func run(out string) {
	start()

	abc := []byte("abc")
	digest := make([]byte, 32)
	check("oxi_sha256", C.oxi_sha256(ptr(abc), C.uintptr_t(len(abc)), ptr(digest)))
	expect("sha256 abc "+SHA256_ABC, fmt.Sprintf("sha256 abc %x", digest))

	check("oxi_hmac_drbg_sha256_new_rbg", C.oxi_hmac_drbg_sha256_new_rbg(&rbg))
	perso := []byte(PERSONALIZATION)
	check("oxi_drbg_instantiate", C.oxi_drbg_instantiate(rbg, ptr(perso), C.uintptr_t(len(perso))))
	say("drbg instantiated")

	message := []byte(MESSAGE)
	msgLen := C.uintptr_t(len(message))
	pk, sig := make([]byte, pkLen), make([]byte, sigLen)
	expectOK("ml-dsa-87 keygen", C.oxi_ml_dsa_87_keygen_rbg(rbg, ptr(pk), ptr(sk), nil))
	check("oxi_ml_dsa_87_sign", C.oxi_ml_dsa_87_sign(ptr(sk), ptr(message), msgLen, nil, 0, ptr(sig)))
	write(out, "pk.bin", pk, false)
	write(out, "message.txt", message, false)
	write(out, "sig.bin", sig, false)
	expectOK("ml-dsa-87 verify", C.oxi_ml_dsa_87_verify(ptr(pk), ptr(message), msgLen, nil, 0, ptr(sig)))
	tamperedSig := bytes.Clone(sig)
	tamperedSig[SIG_FLIP_BYTE] ^= 0x01
	rc := C.oxi_ml_dsa_87_verify(ptr(pk), ptr(message), msgLen, nil, 0, ptr(tamperedSig))
	got := "ml-dsa-87 verify-tampered accepted"
	if rc != C.OXI_RESULT_OK {
		got = fmt.Sprintf("ml-dsa-87 verify-tampered rejected %d", int(rc))
	}
	expect("ml-dsa-87 verify-tampered rejected 22", got)

	ek, ct := make([]byte, ekLen), make([]byte, ctLen)
	expectOK("ml-kem-1024 keygen", C.oxi_ml_kem_1024_keygen_rbg(rbg, ptr(ek), ptr(dk), nil))
	check("oxi_ml_kem_1024_encapsulate_rbg", C.oxi_ml_kem_1024_encapsulate_rbg(ptr(ek), rbg, ptr(ss), ptr(ct)))
	write(out, "ek.bin", ek, false)
	write(out, "dk.bin", dk, true)
	write(out, "ct.bin", ct, false)
	expect("ml-kem-1024 decaps match", decapsLine("ml-kem-1024 decaps", ct))
	tamperedCT := bytes.Clone(ct)
	tamperedCT[CT_FLIP_BYTE] ^= 0x01
	expect("ml-kem-1024 decaps-tampered differs", decapsLine("ml-kem-1024 decaps-tampered", tamperedCT))

	say(fmt.Sprintf("ml-kem-1024 ss %x", ss))
}

// decapsLine decapsulates ct into ss2 and describes the result against ss.
func decapsLine(what string, ct []byte) string {
	rc := C.oxi_ml_kem_1024_decapsulate(ptr(dk), ptr(ct), ptr(ss2))
	switch {
	case rc != C.OXI_RESULT_OK:
		return fmt.Sprintf("%s returned %d", what, int(rc))
	case subtle.ConstantTimeCompare(ss, ss2) == 1:
		return what + " match"
	default:
		return what + " differs"
	}
}

func main() {
	args := os.Args[1:]
	switch {
	case len(args) == 4 && args[1] == "decaps":
		decaps(args[2], args[3])
	case len(args) == 2:
		run(args[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: example <bundle-dir> <out-dir>\n       example <bundle-dir> decaps <dk-file> <ct-file>")
		os.Exit(2)
	}
	release()
}
