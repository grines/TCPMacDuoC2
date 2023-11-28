package syscall

import (
	"fmt"
	"os"
)

func Mv(src, dst string) error {
	err := os.Rename(src, dst)
	if err != nil {
		fmt.Println("Error moving file", err)
		return err
	}
	return nil
}
