package syscall

import (
	"fmt"
	"os"
)

func Touch(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file", err)
		return err
	}
	defer file.Close()
	return nil
}
