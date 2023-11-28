package syscall

import (
	"fmt"
	"os"
)

func Mkdir(directory string) error {
	err := os.Mkdir(directory, 0755)
	if err != nil {
		fmt.Println("Error creating directory", err)
		return err
	}
	return nil
}
