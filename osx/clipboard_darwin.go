//go:build darwin
// +build darwin

package osx

/*
#cgo CFLAGS: -g -Wall -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework OSAKit -framework Foundation -framework AppleScriptObjC
#include "clipboard_darwin.h"
*/
import "C"

func runCommandClipboard() string {
	res := C.GoString(C.clipboard())
	return res
}
