/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"time"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 5 * time.Minute

	wait = 10 * time.Second

	errGetProfile          = "cannot get profile"
	errSeccompProfileNil   = "seccomp profile cannot be nil"
	errSavingProfile       = "cannot save profile"
	errCreatingOperatorDir = "cannot create operator directory"
	errForbiddenSyscall    = "syscall not allowed"
	errForbiddenProfile    = "seccomp profile not allowed"
	errForbiddenAction     = "seccomp action not allowed"

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	reasonSeccompNotSupported   string = "SeccompNotSupportedOnNode"
	reasonInvalidSeccompProfile string = "InvalidSeccompProfile"
	reasonCannotPullProfile     string = "CannotPullSeccompProfile"
	reasonCannotSaveProfile     string = "CannotSaveSeccompProfile"
	reasonCannotRemoveProfile   string = "CannotRemoveSeccompProfile"
	reasonCannotUpdateProfile   string = "CannotUpdateSeccompProfile"
	reasonCannotUpdateStatus    string = "CannotUpdateNodeStatus"
	reasonProfileNotAllowed     string = "ProfileNotAllowed"
	reasonSavedProfile          string = "SavedSeccompProfile"

	defaultCacheTimeout time.Duration = 24 * time.Hour
	maxCacheItems       uint64        = 1000
)

func main() {
	log.SetFlags(log.Lmicroseconds)
	content := []byte("Here is a string....")
	fileName := "/var/lib/kubelet/seccomp/operator/demo/out.json"
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		fmt.Println("%s: %w", errCreatingOperatorDir, err)
	}

	existingContent, err := os.ReadFile(fileName)
	if err == nil && bytes.Equal(existingContent, content) {
		log.Fatalln("Not Equals", err)
	}

	if err := os.WriteFile(fileName, content, filePermissionMode); err != nil {
		fmt.Println("%s %s", errSavingProfile, err)
	}
}
