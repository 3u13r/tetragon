// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux && !amd64 && !arm64

package celbpf

import cgChecker "github.com/google/cel-go/checker"

type rawRegisterInfo struct {
	offset uint16
	size   uint8
}

func rawRegister(string) (rawRegisterInfo, bool) {
	return rawRegisterInfo{}, false
}

func checkerAddRawRegisters(*cgChecker.Env) {}
