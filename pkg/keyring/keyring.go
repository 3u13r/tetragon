// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package keyring

import "errors"

var (
	// ErrUnsupportedPlatform indicates that Linux keyctl is not available.
	ErrUnsupportedPlatform = errors.New("linux keyring verification is only supported on linux")

	// ErrSignatureNotVerified indicates that none of the provided signatures could be verified.
	ErrSignatureNotVerified = errors.New("no valid signatures found in keyring")
)

// VerifySignatures checks whether any of the provided signatures can be verified for data by any key
// linked into the provided Linux keyring. It returns nil if a valid signature was found, or an error
// otherwise (ErrSignatureNotVerified if none of the signatures could be verified).
func VerifySignatures(keyringID int32, data []byte, signatures []string) error {
	return verifySignatures(keyringID, data, signatures)
}
