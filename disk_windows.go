//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// diskUsage (Windows, for local development only — production runs in a Linux container).
func diskUsage(path string) (total, free uint64, err error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var avail, tot, totFree uint64
	r, _, e := syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW").Call(
		uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&tot)), uintptr(unsafe.Pointer(&totFree)))
	if r == 0 {
		return 0, 0, e
	}
	return tot, avail, nil
}
