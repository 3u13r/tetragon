// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package keyring

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	ErrInvalidInput = errors.New("data and signature must be non-empty")
)

// keyctlPkeyParams mirrors Linux struct keyctl_pkey_params.
type keyctlPkeyParams struct {
	KeyID  int32
	InLen  uint32
	In2Len uint32
	Spare  [7]uint32
}

// verifySignatures returns nil if any of the signatures can be verified against data by a key
// in the keyring identified by keyringID. If none of the signatures verify, it returns an error
// wrapping ErrSignatureNotVerified.
// The signatures are expected to be hex-encoded ASN.1 ECDSA signatures.
func verifySignatures(keyringID int32, data []byte, signatures []string) error {
	// Parse signatures into []byte, decoding the expected hex encoding.
	parsedSignatures := make([][]byte, len(signatures))
	for i, sig := range signatures {
		decoded, err := hex.DecodeString(sig)
		if err != nil {
			return fmt.Errorf("decode signature %d %x: %w", i, sig, err)
		}
		parsedSignatures[i] = decoded
	}

	var errs error
	for _, signature := range parsedSignatures {
		err := verifySignature(keyringID, data, signature)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrSignatureNotVerified) {
			return err
		}
		errs = errors.Join(errs, err)
	}
	return errors.Join(ErrSignatureNotVerified, errs)
}

// verifySignature returns nil if signature can be verified against data by any asymmetric key
// in the keyring. If no key verifies it, it returns an error wrapping ErrSignatureNotVerified.
func verifySignature(keyringID int32, data []byte, signature []byte) error {
	if len(data) == 0 || len(signature) == 0 {
		return ErrInvalidInput
	}

	keyIDs, err := readKeyringSerials(keyringID)
	if err != nil {
		return err
	}

	var errs error
	for _, keyID := range keyIDs {
		keyDescribed, err := keyDescribe(keyID)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("describe key %d: %w", keyID, err))
			continue
		}
		if !isAsymmetricKey(keyDescribed) {
			continue
		}

		if verifyErr := verifyWithKey(keyID, data, signature); verifyErr != nil {
			errs = errors.Join(errs, verifyErr)
			continue
		}
		return nil
	}

	return errors.Join(ErrSignatureNotVerified, errs)
}

// similar to
// https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git/tree/keyutils.c?id=c076dff259e99d84d3822b4d2ad7f3f66532f411#n435
func readKeyringSerials(keyringID int32) ([]int32, error) {
	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(keyringID), nil, 0)
	if err != nil {
		return nil, fmt.Errorf("read keyring %d size: %w", keyringID, err)
	}
	if sz == 0 {
		return nil, nil
	}

	buf := make([]byte, sz)
	readN, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(keyringID), buf, 0)
	if err != nil {
		return nil, fmt.Errorf("read keyring %d payload: %w", keyringID, err)
	}

	return parseKeySerials(buf[:readN])
}

func parseKeySerials(buf []byte) ([]int32, error) {
	if len(buf)%4 != 0 {
		return nil, fmt.Errorf("invalid keyring payload length %d", len(buf))
	}

	count := len(buf) / 4
	ids := make([]int32, 0, count)
	for i := range count {
		off := i * 4
		ids = append(ids, int32(binary.NativeEndian.Uint32(buf[off:off+4])))
	}
	return ids, nil
}

// verifyWithKey returns nil if signature can be verified against data by keyID using any of the
// supported algorithm infos. If none succeed, it returns an error wrapping ErrSignatureNotVerified.
func verifyWithKey(keyID int32, data, signature []byte) error {
	infos := []string{
		"enc=x962 hash=sha256", // ECDSA
	}
	var errs error

	for _, info := range infos {
		if err := verifyWithKeyInfo(keyID, data, signature, info); err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		return nil
	}

	return errors.Join(ErrSignatureNotVerified, errs)
}

// verifyWithKeyInfo returns nil if the keyctl KEYCTL_PKEY_VERIFY operation succeeds for keyID
// using the given algorithm info string, meaning signature was verified against data.
func verifyWithKeyInfo(keyID int32, data, signature []byte, info string) error {
	infoPtr, err := unix.BytePtrFromString(info)
	if err != nil {
		return fmt.Errorf("build keyctl verify info: %w", err)
	}

	params := keyctlPkeyParams{
		KeyID:  keyID,
		InLen:  uint32(len(data)),
		In2Len: uint32(len(signature)),
	}

	dataPtr := unsafe.Pointer(&data[0])
	sigPtr := unsafe.Pointer(&signature[0])

	_, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		uintptr(unix.KEYCTL_PKEY_VERIFY),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(infoPtr)),
		uintptr(dataPtr),
		uintptr(sigPtr),
		0,
	)
	// KEYCTL_PKEY_VERIFY returns 0 on success.
	if errno != 0 {
		return errno
	}
	return nil
}

// keyDescribe returns the kernel "describe" string for a key/keyring ID.
// Example output looks like:
//
//	"keyring;_ses: 123456789 0 perm 3f030000"
//	"asymmetric;my-key: 123456789 0 perm 3f010000"
func keyDescribe(id int32) (string, error) {
	// First call with nil buffer to get required size.
	n, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		uintptr(unix.KEYCTL_DESCRIBE),
		uintptr(id),
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return "", errno
	}

	buf := make([]byte, int(n))
	n2, _, errno := unix.Syscall6(
		unix.SYS_KEYCTL,
		uintptr(unix.KEYCTL_DESCRIBE),
		uintptr(id),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		0,
	)
	if errno != 0 {
		return "", errno
	}

	// Kernel returns a NUL-terminated string; trim trailing NULs/newlines.
	return string(buf[:n2]), nil
}

func isAsymmetricKey(desc string) bool {
	s := strings.Split(desc, ";")
	return len(s) > 0 && s[0] == "asymmetric"
}
