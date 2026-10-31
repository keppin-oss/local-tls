//go:build windows

package localtls

import (
	"golang.org/x/sys/windows"
)

// replaceFile renames oldpath over newpath with a single MoveFileExW call using
// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH.
//
// MOVEFILE_COPY_ALLOWED is deliberately not set: both paths are in the same
// directory, so the move is a rename and never falls back to copy-and-delete,
// and newpath is never deleted before the replacement. WRITE_THROUGH asks the
// system not to return until the move is flushed; it is a best-effort
// durability measure, not a power-loss guarantee. There is no retry loop: a
// failure (for example a sharing violation while a reader holds newpath open
// without FILE_SHARE_DELETE) is returned to the caller.
func replaceFile(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
