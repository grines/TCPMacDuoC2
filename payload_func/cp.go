package syscall

import (
	"fmt"
	"io"
	"os"
)

func Cp(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		fmt.Println("Error opening source file", err)
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		fmt.Println("Error creating destination file", err)
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		fmt.Println("Error copying file", err)
		return err
	}
	return nil
}
