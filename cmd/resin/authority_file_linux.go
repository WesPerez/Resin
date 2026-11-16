//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
)

// Deployments additionally provide an exclusively owned generation/mount.
// This protects against accidental aliasing, shared writable directories and
// hardlinked source files; it is not isolation from host root or the same UID.
func verifyPrivateAuthorityPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("authority path ownership or mode refused")
	}
	if info.IsDir() {
		return nil
	}
	if !info.Mode().IsRegular() || st.Nlink != 1 {
		return errors.New("authority requires independent regular files")
	}
	return nil
}
