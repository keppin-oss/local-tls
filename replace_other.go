//go:build !windows

package localtls

import "os"

// replaceFile renames oldpath over newpath. On non-Windows platforms this is
// only used by offline tests of the platform-independent persistence logic.
func replaceFile(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
