package syscall

import (
	"fmt"
	"os"
)

func Rm(filename string) error {
	err := os.Remove(filename)
	if err != nil {
		fmt.Println("Error removing file", err)
		return err
	}
	return nil
}
