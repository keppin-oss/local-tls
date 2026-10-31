package localtls

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// tempPrefix is the reserved prefix of the temporary files atomicWrite creates
// inside the TLS state directory. Only files with this exact prefix are ever
// treated as Local-TLS temporaries by removeOrphanTemps.
const tempPrefix = ".localtls-tmp-"

// tempFile is the subset of *os.File used by atomicWrite. It exists so tests
// can inject write, sync and close failures.
type tempFile interface {
	Name() string
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// fileSystem is the internal file-operation seam used by the persistence and
// renewal paths. Production code uses osFS; tests replace individual
// operations to inject faults, including failures reported after the
// operation took effect.
type fileSystem struct {
	readFile   func(path string) ([]byte, error)
	stat       func(path string) (fs.FileInfo, error)
	createTemp func(dir, pattern string) (tempFile, error)
	// replace atomically renames oldpath over newpath within one directory.
	// It never copies and never deletes newpath first.
	replace func(oldpath, newpath string) error
	remove  func(path string) error
	readDir func(dir string) ([]fs.DirEntry, error)
}

var osFS = fileSystem{
	readFile:   os.ReadFile,
	stat:       os.Stat,
	createTemp: func(dir, pattern string) (tempFile, error) { return os.CreateTemp(dir, pattern) },
	replace:    replaceFile,
	remove:     os.Remove,
	readDir:    os.ReadDir,
}

// statExists reports whether path exists. Only a not-exist result is
// reported as (false, nil); any other stat failure (for example access
// denied) is returned as an error so that it is never mistaken for absence.
func (fsys fileSystem) statExists(path string) (bool, error) {
	_, err := fsys.stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %s: %w", path, err)
}

// atomicWrite writes data to path through a temporary file in the same
// directory: write (a short write is an error), flush (Sync), close, then a
// same-directory replace.
//
// Every step's error is checked and reported. A failure before the replace
// leaves path unchanged. An error reported by the replace itself may have
// occurred after the rename took effect, so path then holds either its
// previous or the new bytes, each complete; the caller must reconcile. The
// guarantee targeted is process-crash safety: path never holds a partial
// write. Persistence across sudden power loss is best effort only (see the
// README durability section); a successful return, or a later re-read, is not
// proof of physical durability.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	return osFS.atomicWrite(path, data, perm)
}

func (fsys fileSystem) atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := fsys.createTemp(dir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		fsys.remove(tmpName)
	}
	n, err := tmp.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		fsys.remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		fsys.remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := fsys.replace(tmpName, path); err != nil {
		fsys.remove(tmpName)
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}

// removeOrphanTemps removes regular files carrying the reserved tempPrefix in
// dir. They can only be left behind by an interrupted atomicWrite. It must run
// only inside the single-writer window (never concurrently with a write), and
// it never touches any other file.
func (fsys fileSystem) removeOrphanTemps(dir string) error {
	entries, err := fsys.readDir(dir)
	if err != nil {
		return fmt.Errorf("list TLS state directory: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		if err := fsys.remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove orphan temp %s: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}
