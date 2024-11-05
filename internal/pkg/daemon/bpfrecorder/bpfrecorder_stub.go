//go:build !ppc64le && !s390x && !amd64 && !arm64
// +build !ppc64le,!s390x,!amd64,!arm64

package daemon

import "syscall"

// UnameMachineToString provides a stub implementation for unsupported architectures.
func UnameMachineToString(uname syscall.Utsname) string {
	return ""
}
// UnameReleaseToString provides a stub implementation for unsupported architectures.
func UnameReleaseToString(uname syscall.Utsname) string {
	return ""
}