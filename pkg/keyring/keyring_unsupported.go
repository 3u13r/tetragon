// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !linux

package keyring

func verifySignatures(_ int32, _ []byte, _ []string) error {
	return ErrUnsupportedPlatform
}
