//go:build !windows

package main

import "syscall"

// diskUsage returns total and available bytes of the filesystem holding path.
func diskUsage(path string) (total, free uint64, err error) {
	var s syscall.Statfs_t
	if err = syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	return s.Blocks * uint64(s.Bsize), s.Bavail * uint64(s.Bsize), nil
}
