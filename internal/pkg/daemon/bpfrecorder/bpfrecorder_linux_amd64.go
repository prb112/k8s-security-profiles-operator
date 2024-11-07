//go:build amd64 && linux
// +build amd64,linux

package bpfrecorder

import "syscall"

// UnameMachineToString converts uname.Machine to a string for amd64.
func UnameMachineToString(uname syscall.Utsname) string {
	return toStringInt8(uname.Machine)
}

// UnameReleaseToString converts uname.Release to a string for amd64.
func UnameReleaseToString(uname syscall.Utsname) string {
	return toStringInt8(uname.Release)
}

// Helper function to convert [65]int8 to string.
func toStringInt8(array [65]int8) string {
	var buf [65]byte
	for i, b := range array {
		buf[i] = byte(b)
	}
	return toStringByte(buf[:])
}
