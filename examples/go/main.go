// Command sha256 prints the SHA-256 digest of "abc", computed by the oxicrypt
// C library through cgo.
package main

/*
#include "oxicrypt.h"
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

func main() {
	if rc := C.oxi_init(0); rc != C.OXI_RESULT_OK {
		fmt.Fprintf(os.Stderr, "oxi_init returned %d: the module refused to start\n", int(rc))
		os.Exit(1)
	}
	data := []byte("abc")
	var out [32]byte
	rc := C.oxi_sha256((*C.uint8_t)(unsafe.Pointer(&data[0])), C.uintptr_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	if rc != C.OXI_RESULT_OK {
		fmt.Fprintf(os.Stderr, "oxi_sha256 returned %d\n", int(rc))
		os.Exit(1)
	}
	fmt.Printf("%x\n", out)
}
