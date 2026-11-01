//go:build windows

package core

import (
	"os"
	"syscall"
)

// appendAccess is the only access the recorder asks for when it writes the
// log: append and synchronize. os.OpenFile with O_APPEND would also request
// FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA and READ_CONTROL, which the
// append-only log folder ACL deliberately does not grant.
const appendAccess = syscall.FILE_APPEND_DATA | syscall.SYNCHRONIZE

func openAppend(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(p, appendAccess, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
