package osx

import "fmt"

// ScreenShot - interface for holding screenshot data
type ScreenShot interface {
	Monitor() int
	Data() []byte
}

func Screencapture() []ScreenShot {
	result, err := getscreenshot()
	if err != nil {
		fmt.Println(err)
	}

	return result
}
