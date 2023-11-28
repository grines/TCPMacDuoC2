//go:build darwin && cgo
// +build darwin,cgo

package syscall

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework Foundation
#import <Foundation/Foundation.h>
#import <Security/Security.h>
*/
import "C"
import (
	"bytes"
	"fmt"
	"unsafe"
)

func SecKeychainFindGenericPassword(service string) (string, error) {
	sbuf := make([]C.char, len(service))
	for i := 0; i < len(service); i++ {
		sbuf[i] = C.char(service[i])
	}

	olen := new(C.UInt32)
	obuf := new(unsafe.Pointer)
	status := C.SecKeychainFindGenericPassword(
		0,                   // keychainOrArray (NULL means search default keychain search list)
		C.UInt32(len(sbuf)), // serviceNameLength
		&sbuf[0],            // serviceName
		0,                   // accountNameLength
		nil,                 // accountName
		olen,                // passwordLength
		obuf,                // passwordData
		nil,                 // itemRef
	)
	if status != 0 {
		cfString := C.SecCopyErrorMessageString(status, nil)
		defer C.CFRelease(C.CFTypeRef(cfString))
		// Figuring out exactly how much memory we need is a pain, so
		// just allocate a bunch more memory than any error message
		// we've ever seen.
		errBuf := make([]C.char, 4096)
		ok := C.CFStringGetCString(cfString, &errBuf[0], C.CFIndex(len(errBuf)), C.kCFStringEncodingUTF8)
		if ok != 1 {
			return "", fmt.Errorf("unknown error retrieving error string from keychain lookup")
		}
		var buf bytes.Buffer
		for _, ch := range errBuf {
			if ch == 0 {
				break
			}
			buf.WriteByte(byte(ch))
		}
		return "", fmt.Errorf("while getting keychain entry %q: %s Your keychain may be in a bad state. Reach out to #it for help.", service, buf.String())
	}
	defer C.SecKeychainItemFreeContent(nil, *obuf)

	return C.GoStringN((*C.char)(*obuf), C.int(*olen)), nil
}
