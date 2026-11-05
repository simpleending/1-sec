//go:build !windows

package core

import (
	"os"
	"path/filepath"
)

func syncAuditDirectory(dir string) error {
	for _, path := range []string{dir, filepath.Dir(dir)} {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		err = f.Sync()
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
