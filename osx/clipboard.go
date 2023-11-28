package osx

func Clipboard() string {
	result := runCommandClipboard()
	return result
}
