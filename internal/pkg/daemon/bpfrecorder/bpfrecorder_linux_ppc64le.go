//go:build ppc64le && linux
// +build ppc64le,linux

package bpfrecorder

import "syscall"

// UnameMachineToString converts uname.Machine to a string for ppc64le.
func UnameMachineToString(uname syscall.Utsname) string {
	return toStringUint8(uname.Machine)
}

// UnameReleaseToString converts uname.Release to a string for ppc64le.
func UnameReleaseToString(uname syscall.Utsname) string {
	return toStringUint8(uname.Release)
}

// Helper function to convert [65]uint8 to string.
func toStringUint8(u [65]uint8) string {
	n := 0
	for i, v := range u {
		if v == 0 { // Stop at null terminator
			n = i
			break
		}
	}
	return string(u[:n])
}