//go:build !windows

package core

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockSensorRegistry(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
