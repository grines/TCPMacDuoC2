package syscall

import "os/user"

func Whoami() (*user.User, error) {
	return user.Current()
}
