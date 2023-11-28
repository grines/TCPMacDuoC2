package osx

import "fmt"

func Run(jxa string) string {
	result := runCommand(jxa)
	return result
}

func Run_url(url string) string {
	fmt.Println("try")
	result := runCommandFromUrl(url)
	return result
}
