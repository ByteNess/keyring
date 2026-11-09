//go:build linux && !keyring_nooo7

package keyring

import (
	"os"

	"golang.org/x/sys/unix"
)

// oo7FileLock is an advisory, exclusive flock on a file. It serialises
// writers of a keyring across processes; the kernel releases it if the
// process dies. The lock file is never deleted, not even with an emptied
// keyring: a waiter already blocked on the old inode would otherwise be
// granted a lock a newcomer cannot see, and the two could write at once.
type oo7FileLock struct {
	file *os.File
}

func oo7LockFile(path string) (*oo7FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &oo7FileLock{file: f}, nil
}

func (l *oo7FileLock) Unlock() error {
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	if cerr := l.file.Close(); err == nil {
		err = cerr
	}
	return err
}
