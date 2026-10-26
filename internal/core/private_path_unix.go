//go:build !windows

package core

import "os"

// RestrictPrivatePath removes access for other local accounts.
func RestrictPrivatePath(path string, directory bool) error {
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
