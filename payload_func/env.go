package syscall

import (
	"os"
	"strings"
)

func Env() string {
	return strings.Join(os.Environ(), "\n")
}
