//go:build darwin
// +build darwin

package osx

/*
#cgo CFLAGS: -g -Wall -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework OSAKit -framework Foundation -framework AppleScriptObjC
#include "osascript_darwin.h"
*/
import "C"

func runCommand(arg string) string {
	file := C.CString(arg)
	res := C.GoString(C.osascript(file))
	return res
}

func runCommandFromUrl(arg string) string {
	url := C.CString(arg)
	res := C.GoString(C.osascript_url(url))
	return res
}
